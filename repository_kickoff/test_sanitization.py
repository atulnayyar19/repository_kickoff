from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from repository_kickoff.sanitization import prepare_repository


COMMIT = "a" * 40
ORIGINAL_ARCHIVE = "b" * 64


def report(status: str, findings: list[dict] | None = None) -> dict:
    findings = findings or []
    by_category: dict[str, int] = {}
    by_disposition: dict[str, int] = {}
    for finding in findings:
        by_category[finding["category"]] = by_category.get(finding["category"], 0) + 1
        by_disposition[finding["disposition"]] = by_disposition.get(finding["disposition"], 0) + 1
    return {
        "status": status,
        "counts": {
            "files_seen": 1,
            "files_scanned": 1,
            "findings": len(findings),
            "by_category": by_category,
            "by_disposition": by_disposition,
        },
        "findings": findings,
    }


def finding(category: str, detector: str, *, disposition: str = "remediate", line: int = 1) -> dict:
    return {
        "category": category,
        "severity": "medium",
        "disposition": disposition,
        "relative_path": "fixtures.py",
        "line": line,
        "detector": detector,
        "fingerprint": hashlib.sha256(f"{category}|{detector}|{line}".encode()).hexdigest()[:16],
    }


class SanitizationTests(unittest.TestCase):
    def test_remediation_changes_only_copy_and_packages_safe_content(self) -> None:
        raw_values = [
            "sk-sample-1234567890", "alice@private.company", "+1 (212) 867-5309",
            "123-45-6789", "Alice Example",
        ]
        text = (
            'api_key = "sk-sample-1234567890"\n'
            'email = "alice@private.company"\n'
            'phone = "+1 (212) 867-5309"\n'
            'ssn = "123-45-6789"\n'
            'name = "Alice Example"\n'
        )
        initial_findings = [
            finding("placeholder_secret", "placeholder_secret", line=1),
            finding("text_pii", "email", line=2),
            finding("text_pii", "phone", line=3),
            finding("text_pii", "structured_id", line=4),
            finding("fixture_name", "fixture_name", line=5),
        ]
        for item, raw in zip(initial_findings, raw_values):
            item["raw_match"] = raw  # An unsafe scanner extension must be stripped at the boundary.

        def scanner(root: Path) -> dict:
            scanned = (root / "fixtures.py").read_text(encoding="utf-8")
            return report("remediation_required", initial_findings) if raw_values[0] in scanned else report("clean")

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "source"
            source.mkdir()
            (source / "fixtures.py").write_text(text, encoding="utf-8")
            before = (source / "fixtures.py").read_bytes()
            result = prepare_repository(
                source, base / "output", upstream_commit_sha=COMMIT,
                original_archive_sha256=ORIGINAL_ARCHIVE, scanner=scanner,
            )
            self.assertEqual(result["status"], "sanitized_clean", result)
            self.assertEqual((source / "fixtures.py").read_bytes(), before)
            prepared_path = Path(result["prepared_root"]) / "fixtures.py"
            prepared = prepared_path.read_text(encoding="utf-8")
            self.assertIn("YOUR_API_KEY_HERE", prepared)
            self.assertIn("user@example.com", prepared)
            self.assertIn("555-0199", prepared)
            self.assertIn("SYNTHETIC-ID-", prepared)
            self.assertIn("Example User", prepared)
            for value in raw_values:
                self.assertNotIn(value, prepared)
            with zipfile.ZipFile(result["archive_path"]) as archive:
                archived = archive.read("fixtures.py")
            self.assertEqual(archived, prepared_path.read_bytes())

            serialized = json.dumps(result, sort_keys=True)
            manifest = Path(result["manifest_path"]).read_text(encoding="utf-8")
            for value in raw_values:
                self.assertNotIn(value, serialized)
                self.assertNotIn(value, manifest)
                self.assertNotIn(value, Path(result["report_path"]).read_text(encoding="utf-8"))

            identity = result["identity"]
            self.assertEqual(identity["upstream_commit_sha"], COMMIT)
            self.assertEqual(identity["original_archive_sha256"], ORIGINAL_ARCHIVE)
            self.assertEqual(identity["workspace_state"], "sanitized_derivative")
            self.assertEqual(identity["safety_status"], "sanitized_clean")
            self.assertEqual(
                identity["prepared_archive_sha256"],
                hashlib.sha256(Path(result["archive_path"]).read_bytes()).hexdigest(),
            )
            self.assertEqual(
                identity["sanitization_manifest_sha256"],
                hashlib.sha256(Path(result["manifest_path"]).read_bytes()).hexdigest(),
            )

    def test_clean_tree_has_clean_upstream_identity_and_reproducible_archive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "source"
            source.mkdir()
            (base / "one").mkdir()
            (source / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
            one = prepare_repository(
                source, base / "one", upstream_commit_sha=COMMIT,
                original_archive_sha256=ORIGINAL_ARCHIVE, scanner=lambda _: report("clean"),
            )
            two = prepare_repository(
                source, base / "two", upstream_commit_sha=COMMIT,
                original_archive_sha256=ORIGINAL_ARCHIVE, scanner=lambda _: report("clean"),
            )
            self.assertEqual(one["status"], "clean")
            self.assertEqual(one["identity"]["workspace_state"], "clean_upstream")
            self.assertEqual(one["identity"]["prepared_archive_sha256"], two["identity"]["prepared_archive_sha256"])
            manifest = json.loads(Path(one["manifest_path"]).read_text(encoding="utf-8"))
            self.assertEqual(manifest["status"], "clean")

    def test_hard_block_fails_closed_without_archive(self) -> None:
        private_key = "-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----\n"
        hard_block = finding("key_material", "private_key", disposition="reject")
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "source"
            source.mkdir()
            (source / "fixtures.py").write_text(private_key, encoding="utf-8")
            result = prepare_repository(
                source, base / "output", upstream_commit_sha=COMMIT,
                original_archive_sha256=ORIGINAL_ARCHIVE,
                scanner=lambda _: report("rejected", [hard_block]),
            )
            self.assertEqual(result["status"], "rejected")
            self.assertIsNone(result["archive_path"])
            self.assertIsNone(result["prepared_root"])
            self.assertIsNone(result["identity"]["prepared_archive_sha256"])
            self.assertEqual(result["identity"]["safety_status"], "rejected")
            self.assertNotIn(private_key, json.dumps(result))
            self.assertNotIn(private_key, Path(result["manifest_path"]).read_text(encoding="utf-8"))

    def test_root_level_blocker_is_preserved_without_becoming_a_file_target(self) -> None:
        root_block = finding("uninspectable", "file_count_limit", disposition="manual_review")
        root_block.pop("line")
        root_block["relative_path"] = "."
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "source"
            source.mkdir()
            (source / "safe.py").write_text("VALUE = 1\n", encoding="utf-8")
            result = prepare_repository(
                source, base / "output", upstream_commit_sha=COMMIT,
                original_archive_sha256=ORIGINAL_ARCHIVE,
                scanner=lambda _: report("manual_review_required", [root_block]),
            )
            self.assertEqual(result["status"], "manual_review_required")
            self.assertEqual(result["source_report"]["findings"][0]["relative_path"], ".")
            self.assertIsNone(result["archive_path"])

    def test_unrecognized_or_unmatched_remediation_requires_manual_review(self) -> None:
        cases = [
            finding("binary", "binary_file"),
            finding("text_pii", "email"),
        ]
        contents = [b"\x00\x01", b"no address here\n"]
        for index, (unsafe_finding, content) in enumerate(zip(cases, contents)):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                source = base / "source"
                source.mkdir()
                (source / "fixtures.py").write_bytes(content)
                result = prepare_repository(
                    source, base / "output", upstream_commit_sha=COMMIT,
                    original_archive_sha256=ORIGINAL_ARCHIVE,
                    scanner=lambda _, item=unsafe_finding: report("remediation_required", [item]),
                )
                self.assertEqual(result["status"], "manual_review_required")
                self.assertIsNone(result["archive_path"])

    def test_nonclean_rescan_discards_prepared_copy(self) -> None:
        raw = 'email = "person@company.com"\n'
        calls = 0

        def scanner(_: Path) -> dict:
            nonlocal calls
            calls += 1
            if calls == 1:
                return report("remediation_required", [finding("text_pii", "email")])
            return report("manual_review_required", [
                finding("proprietary", "ownership", disposition="manual_review")
            ])

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "source"
            source.mkdir()
            (source / "fixtures.py").write_text(raw, encoding="utf-8")
            result = prepare_repository(
                source, base / "output", upstream_commit_sha=COMMIT,
                original_archive_sha256=ORIGINAL_ARCHIVE, scanner=scanner,
            )
            self.assertEqual(result["status"], "manual_review_required")
            self.assertIsNone(result["prepared_root"])
            self.assertIsNone(result["archive_path"])
            self.assertEqual((source / "fixtures.py").read_text(encoding="utf-8"), raw)

    def test_real_scanner_contract_remediates_then_rescans_clean(self) -> None:
        fixture = (
            'email: sensitive.person@private-company.org\n'
            'phone: +1 212-876-9876\n'
            'ssn: 321-45-6789\n'
            'passport: A98765432\n'
            'full_name = "Morgan Sensitive"\n'
            'password = "changeme"\n'
        )
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "source"
            path = source / "tests" / "fixtures" / "person.txt"
            path.parent.mkdir(parents=True)
            path.write_text(fixture, encoding="utf-8")
            json_fixture = source / "examples" / "person.json"
            json_fixture.parent.mkdir(parents=True)
            json_fixture.write_text(
                '{"email":"another.person@private-company.org","backup_email":"backup@private-company.org",'
                '"phone":"+44 20 7946 0958",'
                '"passport":"B12345678","full_name":"Taylor Sensitive","api_key":"changeme"}\n',
                encoding="utf-8",
            )
            result = prepare_repository(
                source, base / "output", upstream_commit_sha=COMMIT,
                original_archive_sha256=ORIGINAL_ARCHIVE,
            )
            self.assertEqual(result["status"], "sanitized_clean", result)
            self.assertEqual(result["final_report"]["status"], "clean")
            prepared = (Path(result["prepared_root"]) / "tests" / "fixtures" / "person.txt").read_text(
                encoding="utf-8"
            )
            self.assertNotIn("Morgan Sensitive", prepared)
            self.assertNotIn("changeme", prepared)
            self.assertIn("Example User", prepared)
            self.assertIn("YOUR_API_KEY_HERE", prepared)
            prepared_json = (Path(result["prepared_root"]) / "examples" / "person.json").read_text(
                encoding="utf-8"
            )
            self.assertNotIn("private-company.org", prepared_json)
            self.assertNotIn("Taylor Sensitive", prepared_json)
            self.assertIn("user@example.com", prepared_json)
            self.assertIn("YOUR_API_KEY_HERE", prepared_json)

    def test_prefixed_documentation_and_test_passwords_are_sanitized(self) -> None:
        values = ["secret", "pass"]
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "source"
            docs = source / "docs" / "configuration.md"
            tests = source / "tests" / "test_config.py"
            docs.parent.mkdir(parents=True)
            tests.parent.mkdir(parents=True)
            docs.write_text(f"export TOOL_HTTP_BASIC_REPOSITORY_PASSWORD={values[0]}\n", encoding="utf-8")
            tests.write_text(f'config = {{"password": "{values[1]}"}}\n', encoding="utf-8")
            result = prepare_repository(
                source, base / "output", upstream_commit_sha=COMMIT,
                original_archive_sha256=ORIGINAL_ARCHIVE,
            )
            self.assertEqual(result["status"], "sanitized_clean", result)
            prepared_root = Path(result["prepared_root"])
            for relative, raw in (("docs/configuration.md", values[0]), ("tests/test_config.py", values[1])):
                prepared = (prepared_root / relative).read_text(encoding="utf-8")
                self.assertNotIn(f"={raw}", prepared)
                self.assertNotIn(f'"{raw}"', prepared)
                self.assertIn("YOUR_API_KEY_HERE", prepared)

    def test_attribution_names_and_contacts_are_sanitized_in_the_derivative(self) -> None:
        values = ["Private Person", "private.person@private-company.org"]
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / "source"
            source.mkdir()
            (source / "AUTHORS").write_text(f"{values[0]} <{values[1]}>\n", encoding="utf-8")
            result = prepare_repository(
                source, base / "output", upstream_commit_sha=COMMIT,
                original_archive_sha256=ORIGINAL_ARCHIVE,
            )
            self.assertEqual(result["status"], "sanitized_clean", result)
            prepared = (Path(result["prepared_root"]) / "AUTHORS").read_text(encoding="utf-8")
            self.assertEqual(prepared, "Example Contributor\n")
            for value in values:
                self.assertNotIn(value, prepared)


if __name__ == "__main__":
    unittest.main()
