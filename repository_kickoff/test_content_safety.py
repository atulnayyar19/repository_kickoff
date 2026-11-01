from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from repository_kickoff.content_safety import scan_tree


class ContentSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "repository"
        self.root.mkdir()

    def write(self, name: str, text: str | bytes):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode("utf-8") if isinstance(text, str) else text)
        return path

    def assertWithheld(self, report, *values):
        serialized = json.dumps(report)
        for value in values:
            self.assertNotIn(value, serialized)
        self.assertNotIn(str(self.root), serialized)
        for finding in report["findings"]:
            self.assertEqual(set(finding) - {"line"}, {"category", "severity", "disposition", "relative_path", "detector", "fingerprint"})
            self.assertRegex(finding["fingerprint"], r"^[0-9a-f]{64}$")
            self.assertFalse(Path(finding["relative_path"]).is_absolute())

    def test_normal_config_source_and_synthetic_placeholders_are_clean(self):
        self.write("pyproject.toml", '[project]\nname = "sample"\nversion = "1.2.3"\n')
        self.write("src/config.py", "password = os.getenv('PASSWORD')\ntoken = response.token\napi_key = settings['api_key']\n")
        self.write("examples/config.json", '{"email": "user@example.com", "phone": "555-0199", "full_name": "Example User", "api_key": "YOUR_API_KEY_HERE", "passport": "SYNTHETIC-ID-ABCDEF012345"}')
        self.write("LICENSE", "MIT License\n")
        report = scan_tree(self.root)
        self.assertEqual(report["status"], "clean")
        self.assertEqual(report["counts"]["files_scanned"], 4)

    def test_text_pii_and_fixture_names_are_remediable_without_disclosure(self):
        values = ["sensitive.person@private-company.org", "+1 212-876-9876", "321-45-6789", "A98765432", "Morgan Sensitive"]
        self.write("tests/fixtures/person.txt", f'email: {values[0]}\nphone: {values[1]}\nssn: {values[2]}\npassport: {values[3]}\nfull_name = "{values[4]}"\n')
        report = scan_tree(self.root)
        self.assertEqual(report["status"], "remediation_required")
        self.assertTrue({"email", "phone", "structured_id", "fixture_name"} <= {item["detector"] for item in report["findings"]})
        self.assertTrue(all(item["disposition"] == "remediate" for item in report["findings"]))
        self.assertWithheld(report, *values)

    def test_real_secrets_keys_and_environment_files_block(self):
        values = ["live-secret-6f2d9e8c", "ghp_" + "Q" * 36, "superSecureP455word", "-----BEGIN RSA PRIVATE KEY-----", "privateAccessSecret589abcd"]
        self.write("settings.py", f'API_KEY = "{values[0]}"\n# {values[1]}\nAWS_SECRET_ACCESS_KEY = "{values[4]}"\n')
        self.write(".env.production", f"PASSWORD={values[2]}\n")
        self.write("key.txt", values[3] + "\nprivate-material\n-----END RSA PRIVATE KEY-----")
        report = scan_tree(self.root)
        self.assertEqual(report["status"], "rejected")
        self.assertTrue({"environment_file", "private_key", "secret_assignment", "known_token"} <= {item["detector"] for item in report["findings"]})
        self.assertWithheld(report, *values, "private-material")

    def test_common_password_placeholder_can_be_replaced(self):
        self.write("fixture.py", 'password = "changeme"\n')
        report = scan_tree(self.root)
        self.assertEqual(report["status"], "remediation_required")
        self.assertEqual(report["findings"][0]["detector"], "placeholder_secret")
        self.assertWithheld(report, "changeme")

    def test_github_id_token_permission_is_not_a_secret(self):
        self.write(".github/workflows/release.yml", "permissions:\n  id-token: write\n  contents: read\n")
        report = scan_tree(self.root)
        self.assertEqual(report["status"], "clean")

    def test_documentation_placeholders_and_short_test_credentials_are_bounded(self):
        values = ["secret", "pass"]
        self.write("docs/configuration.md", f"export TOOL_REPOSITORY_PASSWORD={values[0]}\n")
        self.write("docs/repositories.md", "export TOOL_REPOSITORY_PASSWORD=<password>\n")
        self.write("tests/test_config.py", f'config = {{"password": "{values[1]}"}}\n')
        report = scan_tree(self.root)
        self.assertEqual(report["status"], "remediation_required")
        self.assertEqual(report["counts"]["findings"], 2)
        self.assertTrue(all(item["detector"] == "placeholder_secret" for item in report["findings"]))
        self.assertWithheld(report)

    def test_long_or_high_confidence_credentials_still_block_in_examples(self):
        values = ["highEntropyCredentialValue123456789", "ghp_" + "R" * 36]
        self.write("tests/fixtures/config.py", f'password = "{values[0]}"\n# {values[1]}\n')
        report = scan_tree(self.root)
        self.assertEqual(report["status"], "rejected")
        self.assertTrue({"secret_assignment", "known_token"} <= {item["detector"] for item in report["findings"]})
        self.assertWithheld(report, *values)

    def test_author_contacts_and_attribution_lists_are_remediable(self):
        values = ["maintainer@private-company.org", "author@private-company.org"]
        self.write("pyproject.toml", f'authors = [{{name = "Maintainer", email = "{values[0]}"}}]\n')
        report = scan_tree(self.root)
        self.assertEqual(report["status"], "remediation_required")
        self.assertEqual(report["findings"][0]["disposition"], "remediate")
        self.root.joinpath("pyproject.toml").unlink()
        self.write("AUTHORS", f"Project Author <{values[1]}>\n")
        report = scan_tree(self.root)
        self.assertEqual(report["status"], "remediation_required")
        self.assertEqual(report["findings"][0]["disposition"], "remediate")
        self.assertEqual(report["findings"][0]["detector"], "attribution_name")
        self.assertWithheld(report, *values)

    def test_international_phone_numbers_are_screened(self):
        values = ["+91 98765 43210", "+442079460987"]
        self.write("contact.txt", "\n".join(values))
        report = scan_tree(self.root)
        self.assertEqual(report["status"], "remediation_required")
        self.assertEqual([item["detector"] for item in report["findings"]], ["phone", "phone"])
        self.assertWithheld(report, *values)

    def test_exports_opaque_and_unknown_encodings_require_review(self):
        self.write("export.csv", "email\nsensitive.person@private-company.org\n")
        self.write("screenshots/screen.png", b"\x89PNG\r\n\0sensitive pixels")
        self.write("cache.bin", b"\0secret bytes")
        self.write("legacy.txt", b"private name \xff\xfe")
        self.write("utf16.txt", "sensitive text".encode("utf-16"))
        report = scan_tree(self.root)
        self.assertEqual(report["status"], "manual_review_required")
        self.assertTrue({"structured_export", "opaque_file", "binary_or_encoding", "unknown_encoding"} <= {item["detector"] for item in report["findings"]})
        self.assertWithheld(report, "sensitive.person@private-company.org", "sensitive pixels", "secret bytes")

    def test_plain_svg_is_scanned_as_text_but_embedded_raster_requires_review(self):
        self.write("diagram.svg", '<svg xmlns="http://www.w3.org/2000/svg"><text>safe diagram</text></svg>')
        report = scan_tree(self.root)
        self.assertEqual(report["status"], "clean")
        self.root.joinpath("diagram.svg").unlink()
        self.write(
            "embedded.svg",
            '<svg xmlns="http://www.w3.org/2000/svg"><image href="data:image/png;base64,AAAA"/></svg>',
        )
        report = scan_tree(self.root)
        self.assertEqual(report["status"], "manual_review_required")
        self.assertEqual(report["findings"][0]["detector"], "embedded_raster_image")

    def test_proprietary_indicators_and_legal_attribution_need_review(self):
        self.write("README.md", "Proprietary and confidential. Internal use only.\n")
        self.write("LICENSE", "Copyright person@private-company.org\n")
        report = scan_tree(self.root)
        self.assertEqual(report["status"], "manual_review_required")
        self.assertEqual(
            {item["detector"]: item["disposition"] for item in report["findings"]},
            {"ownership_indicator": "manual_review", "email": "remediate"},
        )
        self.assertWithheld(report, "person@private-company.org")

    def test_standard_rights_reservation_is_not_a_proprietary_signal(self):
        self.write("module.py", "# Copyright 2026 Example Project. All rights reserved.\n")
        report = scan_tree(self.root)
        self.assertEqual(report["status"], "remediation_required")
        self.assertEqual(report["findings"][0]["detector"], "attribution_name")

    def test_sensitive_filename_values_are_not_disclosed(self):
        name = "person@private-company.org"
        self.write(name + ".txt", "plain text")
        report = scan_tree(self.root)
        self.assertEqual(report["status"], "manual_review_required")
        self.assertWithheld(report, name)

    def test_large_files_and_unreadable_files_fail_closed(self):
        self.write("big.txt", "x" * 100)
        with patch("repository_kickoff.content_safety.MAX_TEXT_BYTES", 10):
            report = scan_tree(self.root)
        self.assertEqual(report["status"], "manual_review_required")
        self.assertEqual(report["findings"][0]["detector"], "file_size_limit")
        with patch("repository_kickoff.content_safety.os.open", side_effect=PermissionError("do not leak private detail")):
            report = scan_tree(self.root)
        self.assertEqual(report["findings"][0]["detector"], "unreadable_file")
        self.assertWithheld(report, "do not leak private detail")

    def test_file_count_limit_and_missing_root_fail_closed(self):
        self.write("a.txt", "safe")
        self.write("b.txt", "safe")
        with patch("repository_kickoff.content_safety.MAX_FILES", 1):
            report = scan_tree(self.root)
        self.assertEqual(report["status"], "manual_review_required")
        self.assertEqual(scan_tree(self.root / "missing")["status"], "rejected")

    def test_symlink_is_never_followed(self):
        outside = Path(self.temporary.name) / "outside"
        outside.mkdir()
        (outside / "secret.txt").write_text('password="outside-secret-123"', encoding="utf-8")
        try:
            os.symlink(outside, self.root / "linked", target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("Host does not permit creation of symlinks")
        report = scan_tree(self.root)
        self.assertEqual(report["status"], "rejected")
        self.assertEqual(report["counts"]["files_scanned"], 0)
        self.assertEqual(report["findings"][0]["detector"], "symlink_or_junction")
        self.assertWithheld(report, "outside-secret-123")

    def test_windows_reparse_attribute_is_rejected_without_opening(self):
        self.write("safe.txt", "safe")
        metadata = self.root.lstat()
        reparse = SimpleNamespace(st_mode=metadata.st_mode, st_file_attributes=1024)
        with patch.object(Path, "lstat", return_value=reparse), patch("repository_kickoff.content_safety.os.open") as opener:
            report = scan_tree(self.root)
        self.assertEqual(report["status"], "rejected")
        opener.assert_not_called()

    def test_child_link_metadata_is_rejected_without_opening(self):
        candidate = self.write("linked.txt", "outside-sensitive-content")
        original_lstat = Path.lstat

        def lstat(path, *args, **kwargs):
            if path == candidate:
                return SimpleNamespace(st_mode=stat.S_IFLNK, st_file_attributes=0)
            return original_lstat(path, *args, **kwargs)

        with patch.object(Path, "lstat", lstat), patch("repository_kickoff.content_safety.os.open") as opener:
            report = scan_tree(self.root)
        self.assertEqual(report["status"], "rejected")
        self.assertEqual(report["findings"][0]["detector"], "symlink_or_junction")
        opener.assert_not_called()
        self.assertWithheld(report, "outside-sensitive-content")


if __name__ == "__main__":
    unittest.main()
