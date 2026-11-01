"""Bounded, non-executing download and extraction of GitHub source archives."""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


MAX_ARCHIVE_BYTES = 50 * 1024 * 1024
MAX_EXTRACTED_BYTES = 500 * 1024 * 1024
MAX_ARCHIVE_FILES = 50_000
MAX_COMPRESSION_RATIO = 200
DOWNLOAD_CHUNK_BYTES = 1024 * 1024
WINDOWS_RESERVED_NAMES = {
    "con", "prn", "aux", "nul", *(f"com{number}" for number in range(1, 10)),
    *(f"lpt{number}" for number in range(1, 10)),
}


class ArchivePreparationError(RuntimeError):
    """The source archive could not be downloaded or safely inspected."""


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(DOWNLOAD_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _content_length(response: BinaryIO) -> int | None:
    raw = response.headers.get("Content-Length")
    if not raw:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def download_github_archive(
    full_name: str,
    commit_sha: str,
    destination: Path,
    *,
    max_bytes: int = MAX_ARCHIVE_BYTES,
) -> dict[str, Any]:
    """Stream a commit archive to disk and enforce the limit on actual bytes."""
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    url = f"https://codeload.github.com/{full_name}/zip/{commit_sha}"
    request = Request(url, headers={"User-Agent": "taiga-repository-kickoff/2"})
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".part")
    digest = hashlib.sha256()
    downloaded = 0
    try:
        with urlopen(request, timeout=60) as response:
            advertised = _content_length(response)
            if advertised is not None and advertised >= max_bytes:
                raise ArchivePreparationError(
                    f"Source archive must be smaller than {max_bytes:,} bytes; "
                    f"server advertised {advertised:,} bytes."
                )
            with temporary.open("wb") as output:
                while True:
                    chunk = response.read(DOWNLOAD_CHUNK_BYTES)
                    if not chunk:
                        break
                    downloaded += len(chunk)
                    if downloaded >= max_bytes:
                        raise ArchivePreparationError(
                            f"Source archive must be smaller than {max_bytes:,} bytes; "
                            "the streamed download reached the limit."
                        )
                    digest.update(chunk)
                    output.write(chunk)
        temporary.replace(destination)
    except ArchivePreparationError:
        temporary.unlink(missing_ok=True)
        raise
    except HTTPError as exc:
        temporary.unlink(missing_ok=True)
        raise ArchivePreparationError(f"GitHub archive download failed with HTTP {exc.code}.") from exc
    except (URLError, TimeoutError, OSError) as exc:
        temporary.unlink(missing_ok=True)
        raise ArchivePreparationError(f"GitHub archive download failed: {exc}") from exc
    return {
        "source_url": url,
        "archive_size_bytes": downloaded,
        "original_archive_sha256": digest.hexdigest(),
        "size_limit_bytes_exclusive": max_bytes,
        "size_status": "verified_from_streamed_bytes",
    }


def _safe_member_path(name: str) -> PurePosixPath:
    normalized = name.replace("\\", "/")
    if "\0" in normalized:
        raise ArchivePreparationError("Archive contains a path with a NUL byte.")
    path = PurePosixPath(normalized)
    if not normalized or normalized.startswith("/") or path.is_absolute():
        raise ArchivePreparationError(f"Archive contains an unsafe absolute path: {name!r}")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ArchivePreparationError(f"Archive contains an unsafe relative path: {name!r}")
    for part in path.parts:
        stem = part.split(".", 1)[0].casefold()
        if ":" in part or part.endswith((" ", ".")) or stem in WINDOWS_RESERVED_NAMES:
            raise ArchivePreparationError(f"Archive contains a platform-unsafe path: {name!r}")
    return path


def safely_extract_archive(
    archive_path: Path,
    destination: Path,
    *,
    max_files: int = MAX_ARCHIVE_FILES,
    max_extracted_bytes: int = MAX_EXTRACTED_BYTES,
    max_compression_ratio: int = MAX_COMPRESSION_RATIO,
) -> tuple[Path, dict[str, Any]]:
    """Extract a ZIP after rejecting traversal, links, collisions, and bombs."""
    destination.mkdir(parents=True, exist_ok=False)
    try:
        archive = zipfile.ZipFile(archive_path)
    except (OSError, zipfile.BadZipFile) as exc:
        raise ArchivePreparationError("Downloaded source archive is not a valid ZIP file.") from exc

    with archive:
        members = archive.infolist()
        files = [member for member in members if not member.is_dir()]
        if len(files) > max_files:
            raise ArchivePreparationError(
                f"Archive contains {len(files):,} files, above the safety limit of {max_files:,}."
            )
        total_uncompressed = sum(member.file_size for member in files)
        if total_uncompressed > max_extracted_bytes:
            raise ArchivePreparationError(
                f"Archive expands to {total_uncompressed:,} bytes, above the safety limit."
            )
        total_compressed = sum(max(member.compress_size, 1) for member in files)
        if files and total_uncompressed / total_compressed > max_compression_ratio:
            raise ArchivePreparationError("Archive compression ratio exceeds the safety limit.")

        seen: set[str] = set()
        safe_members: list[tuple[zipfile.ZipInfo, PurePosixPath]] = []
        for member in members:
            relative = _safe_member_path(member.filename.rstrip("/"))
            collision_key = relative.as_posix().casefold()
            if collision_key in seen:
                raise ArchivePreparationError(f"Archive contains a duplicate or case-colliding path: {member.filename!r}")
            seen.add(collision_key)
            mode = (member.external_attr >> 16) & 0xFFFF
            kind = stat.S_IFMT(mode)
            if kind not in {0, stat.S_IFREG, stat.S_IFDIR}:
                raise ArchivePreparationError(f"Archive contains a link or special file: {member.filename!r}")
            safe_members.append((member, relative))

        try:
            for member, relative in safe_members:
                target = destination.joinpath(*relative.parts)
                if member.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member, "r") as source, target.open("wb") as output:
                    shutil.copyfileobj(source, output, length=DOWNLOAD_CHUNK_BYTES)
        except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
            raise ArchivePreparationError("Source archive failed safe extraction.") from exc

    top_levels = {relative.parts[0] for _, relative in safe_members}
    root = destination / next(iter(top_levels)) if len(top_levels) == 1 else destination
    if not root.is_dir():
        root = destination
    review = {
        "archive_sha256": _hash_file(archive_path),
        "archive_size_bytes": archive_path.stat().st_size,
        "file_count": len(files),
        "extracted_size_bytes": total_uncompressed,
        "compression_ratio": round(total_uncompressed / total_compressed, 2) if files else 0.0,
        "safety_checks": {
            "path_traversal": "passed",
            "links_and_special_files": "passed",
            "duplicate_paths": "passed",
            "file_count": "passed",
            "expanded_size": "passed",
            "compression_ratio": "passed",
        },
    }
    return root, review
