from __future__ import annotations

import hashlib
import io
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from repository_kickoff.archive_preparation import (
    ArchivePreparationError,
    download_github_archive,
    safely_extract_archive,
)


class _Response(io.BytesIO):
    def __init__(self, value: bytes, content_length: int | None = None) -> None:
        super().__init__(value)
        self.headers = {} if content_length is None else {"Content-Length": str(content_length)}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def _zip_bytes(files: dict[str, bytes], *, symlink: str | None = None) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, value in files.items():
            archive.writestr(name, value)
        if symlink:
            info = zipfile.ZipInfo(symlink)
            info.external_attr = (0o120777 << 16)
            archive.writestr(info, "target")
    return stream.getvalue()


class ArchivePreparationTests(unittest.TestCase):
    def test_download_measures_streamed_bytes_and_hash(self) -> None:
        payload = b"a" * 25
        with tempfile.TemporaryDirectory() as directory, patch(
            "repository_kickoff.archive_preparation.urlopen", return_value=_Response(payload)
        ):
            destination = Path(directory) / "source.zip"
            result = download_github_archive("owner/repo", "a" * 40, destination, max_bytes=26)
            self.assertEqual(destination.read_bytes(), payload)
        self.assertEqual(result["archive_size_bytes"], 25)
        self.assertEqual(result["original_archive_sha256"], hashlib.sha256(payload).hexdigest())

    def test_download_limit_is_strict_and_removes_partial_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch(
            "repository_kickoff.archive_preparation.urlopen", return_value=_Response(b"a" * 25)
        ):
            destination = Path(directory) / "source.zip"
            with self.assertRaisesRegex(ArchivePreparationError, "smaller than"):
                download_github_archive("owner/repo", "a" * 40, destination, max_bytes=25)
            self.assertFalse(destination.exists())
            self.assertFalse(destination.with_suffix(".zip.part").exists())

    def test_advertised_size_at_limit_is_rejected_before_write(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch(
            "repository_kickoff.archive_preparation.urlopen", return_value=_Response(b"", content_length=25)
        ):
            with self.assertRaisesRegex(ArchivePreparationError, "advertised"):
                download_github_archive("owner/repo", "a" * 40, Path(directory) / "source.zip", max_bytes=25)

    def test_safe_extract_returns_single_repository_root(self) -> None:
        payload = _zip_bytes({"repo-sha/README.md": b"ok", "repo-sha/src/app.py": b"print('ok')"})
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "source.zip"
            archive.write_bytes(payload)
            root, review = safely_extract_archive(archive, Path(directory) / "extracted")
            self.assertEqual(root.name, "repo-sha")
            self.assertEqual((root / "README.md").read_text(), "ok")
            self.assertEqual(review["file_count"], 2)

    def test_extract_rejects_traversal_and_symlinks(self) -> None:
        cases = (
            (_zip_bytes({"../escape.txt": b"bad"}), "unsafe relative path"),
            (_zip_bytes({"repo/ok.txt": b"ok"}, symlink="repo/link"), "link or special file"),
            (_zip_bytes({"repo/CON.txt": b"bad"}), "platform-unsafe path"),
            (_zip_bytes({"repo/file.txt:stream": b"bad"}), "platform-unsafe path"),
        )
        for payload, message in cases:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as directory:
                archive = Path(directory) / "source.zip"
                archive.write_bytes(payload)
                with self.assertRaisesRegex(ArchivePreparationError, message):
                    safely_extract_archive(archive, Path(directory) / "extracted")


if __name__ == "__main__":
    unittest.main()
