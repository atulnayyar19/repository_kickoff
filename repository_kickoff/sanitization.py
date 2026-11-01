"""Fail-closed preparation of a repository archive after content scanning.

The extracted source tree is read-only input.  Any remediation is applied to a
copy, which is scanned again before an upload archive can be created.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import stat
import zipfile
from collections import defaultdict
from collections.abc import Callable, Mapping
from pathlib import Path, PurePosixPath
from typing import Any


ScanTree = Callable[[Path], Mapping[str, Any]]

_ALLOWED_REMEDIATIONS = {
    ("text_pii", "email"),
    ("text_pii", "phone"),
    ("text_pii", "structured_id"),
    ("text_pii", "personal_name"),
    ("text_pii", "attribution_name"),
    ("fixture_name", "fixture_name"),
    ("placeholder_secret", "placeholder_secret"),
}
_EMAIL = re.compile(r"(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![\w.-])", re.IGNORECASE)
_PHONE = re.compile(r"(?<!\w)(?:\+?\d[\d ()-]{5,}\d)(?!\w)")
_UUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE)
_DASHED_ID = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
_FIELD_VALUE = re.compile(
    r"(?P<prefix>\b(?:account_?id|customer_?id|employee_?id|tax_?id|national_?id|user_?id|id|ssn|"
    r"social[_ -]?security(?:[_ -]?number)?|passport(?:[_ -]?(?:number|no))?|date[_ -]?of[_ -]?birth|"
    r"dob|credit[_ -]?card(?:[_ -]?number)?|card[_ -]?number|iban)\b[\"']?\s*(?:=|:|,)\s*[\"']?)"
    r"(?P<value>[A-Za-z0-9][A-Za-z0-9 /_.:-]{2,40}?)(?P<suffix>[\"']?)(?=\s*(?:[,;#}\]]|$))",
    re.IGNORECASE,
)
_NAME_FIELD = re.compile(
    r"(?P<prefix>\b(?:display[_ -]?name|full[_ -]?name|first[_ -]?name|last[_ -]?name|person[_ -]?name|"
    r"customer[_ -]?name|patient[_ -]?name|name)\b[\"']?\s*(?:=|:)\s*[\"'])"
    r"(?P<value>[^\"'\r\n]+)(?P<suffix>[\"'])",
    re.IGNORECASE,
)
_ATTRIBUTION_FIELD = re.compile(
    r'''(?ix)\b(?:author|maintainer|copyright(?:[_ -]?holder)?|owner)["']?\s*[:=]\s*(?:\[?\{?\s*)?["'](?P<value>[A-Z][A-Z .'’&()-]{1,100})["']'''
)
_COPYRIGHT_NAME = re.compile(
    r'''(?ix)\bcopyright(?:\s*\(c\))?(?:\s+\d{4}(?:\s*[-–]\s*\d{4})?)?\s+(?P<value>[A-Z][A-Z0-9 .'’&(),_-]{1,100}?)(?=\s*<|\s*$)'''
)
_SECRET_FIELD = re.compile(
    r"(?P<prefix>(?<![\w])(?:[a-z0-9]+[_-])*(?:api[_-]?key|access[_-]?token|auth[_-]?token|"
    r"refresh[_-]?token|client[_-]?secret|secret[_-]?access[_-]?key|secret[_-]?key|private[_-]?key|"
    r"password|passwd|pwd|token|secret)[\"']?\s*(?:=|:)\s*[\"']?)"
    r"(?P<value>[^\s\"',;#}]+)(?P<suffix>[\"']?)",
    re.IGNORECASE,
)


class PreparationError(ValueError):
    """The preparation request itself is invalid or unsafe."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _safe_relative_path(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PreparationError("Scanner finding has no relative_path.")
    normalized = value.replace("\\", "/")
    # The scanner uses "." for root-level blockers such as an unsafe root or
    # file-count limit. It is reportable, but never a valid remediation target.
    if normalized == ".":
        return normalized
    path = PurePosixPath(normalized)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise PreparationError("Scanner finding has an unsafe relative_path.")
    return path.as_posix()


def _normalize_report(report: Mapping[str, Any]) -> dict[str, Any]:
    """Allowlist scanner output so reports cannot accidentally retain raw matches."""
    if not isinstance(report, Mapping):
        raise PreparationError("Scanner returned a non-object report.")
    status = report.get("status")
    if status not in {"clean", "remediation_required", "manual_review_required", "rejected"}:
        raise PreparationError(f"Scanner returned an unsupported status: {status!r}.")
    normalized_findings: list[dict[str, Any]] = []
    raw_findings = report.get("findings", [])
    if not isinstance(raw_findings, list):
        raise PreparationError("Scanner report findings must be a list.")
    for raw in raw_findings:
        if not isinstance(raw, Mapping):
            raise PreparationError("Scanner report contains a non-object finding.")
        finding: dict[str, Any] = {
            "category": str(raw.get("category", "")),
            "severity": str(raw.get("severity", "")),
            "disposition": str(raw.get("disposition", "")),
            "relative_path": _safe_relative_path(raw.get("relative_path")),
            "detector": str(raw.get("detector", "")),
            "fingerprint": str(raw.get("fingerprint", "")),
        }
        for field in ("category", "detector"):
            if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", finding[field]):
                raise PreparationError(f"Scanner finding has an invalid {field}.")
        if finding["severity"] not in {"medium", "high", "critical"}:
            raise PreparationError("Scanner finding has an invalid severity.")
        if finding["disposition"] not in {"remediate", "manual_review", "reject"}:
            raise PreparationError("Scanner finding has an invalid disposition.")
        if not re.fullmatch(r"[0-9a-fA-F]{12,64}", finding["fingerprint"]):
            raise PreparationError("Scanner finding fingerprint must be a hexadecimal digest.")
        line = raw.get("line")
        if line is not None:
            if type(line) is not int or line < 1:
                raise PreparationError("Scanner finding line must be a positive integer.")
            finding["line"] = line
        normalized_findings.append(finding)
    normalized_findings.sort(
        key=lambda item: (
            item["relative_path"], item.get("line", 0), item["category"], item["detector"], item["fingerprint"]
        )
    )
    raw_counts = report.get("counts", {})
    counts = raw_counts if isinstance(raw_counts, Mapping) else {}

    def integer(name: str, default: int = 0) -> int:
        value = counts.get(name, default)
        return value if type(value) is int and value >= 0 else default

    by_category: dict[str, int] = defaultdict(int)
    by_disposition: dict[str, int] = defaultdict(int)
    for finding in normalized_findings:
        by_category[finding["category"]] += 1
        by_disposition[finding["disposition"]] += 1

    return {
        "status": status,
        "counts": {
            "files_seen": integer("files_seen"),
            "files_scanned": integer("files_scanned"),
            "findings": len(normalized_findings),
            "by_category": dict(sorted(by_category.items())),
            "by_disposition": dict(sorted(by_disposition.items())),
        },
        "findings": normalized_findings,
    }


def _synthetic_id(finding: Mapping[str, Any]) -> str:
    stable_input = "|".join(
        str(finding.get(key, "")) for key in ("fingerprint", "relative_path", "line", "detector")
    )
    suffix = hashlib.sha256(stable_input.encode("utf-8")).hexdigest()[:12].upper()
    return f"SYNTHETIC-ID-{suffix}"


def _scanner_fingerprint(value: str) -> str:
    return hashlib.sha256(
        b"repository-content-safety-v1\0" + value.encode("utf-8", errors="surrogatepass")
    ).hexdigest()


def _replace_one(
    line: str,
    candidates: list[tuple[int, int, str]],
    finding: Mapping[str, Any],
    replacement: str,
) -> tuple[str, int]:
    candidates = [candidate for candidate in candidates if candidate[2] != replacement]
    if not candidates:
        return line, 0
    expected = str(finding["fingerprint"]).casefold()
    selected = next(
        (candidate for candidate in candidates if _scanner_fingerprint(candidate[2]) == expected),
        candidates[0],
    )
    start, end, _ = selected
    return line[:start] + replacement + line[end:], 1


def _matches(pattern: re.Pattern[str], line: str, group: str | int = 0) -> list[tuple[int, int, str]]:
    return [(match.start(group), match.end(group), match.group(group)) for match in pattern.finditer(line)]


def _substitute_line(line: str, finding: Mapping[str, Any]) -> tuple[str, str, int]:
    category = str(finding["category"])
    detector = str(finding["detector"])
    if (category, detector) not in _ALLOWED_REMEDIATIONS:
        return line, "", 0
    if detector == "email":
        replacement = "user@example.com"
        updated, count = _replace_one(line, _matches(_EMAIL, line), finding, replacement)
    elif detector == "phone":
        replacement = "555-0199"
        updated, count = _replace_one(line, _matches(_PHONE, line), finding, replacement)
    elif detector == "structured_id":
        replacement = _synthetic_id(finding)
        candidates = _matches(_FIELD_VALUE, line, "value")
        candidates.extend(_matches(_DASHED_ID, line))
        candidates.extend(_matches(_UUID, line))
        candidates = [candidate for candidate in candidates if not candidate[2].upper().startswith("SYNTHETIC-ID-")]
        updated, count = _replace_one(line, candidates, finding, replacement)
    elif detector in {"fixture_name", "personal_name"}:
        replacement = "Example User"
        updated, count = _replace_one(line, _matches(_NAME_FIELD, line, "value"), finding, replacement)
    elif detector == "attribution_name":
        replacement = "Example Contributor"
        candidates = _matches(_ATTRIBUTION_FIELD, line, "value")
        candidates.extend(_matches(_COPYRIGHT_NAME, line, "value"))
        stripped = line.strip()
        if stripped:
            start = len(line) - len(line.lstrip())
            candidates.append((start, start + len(stripped), stripped))
        updated, count = _replace_one(line, candidates, finding, replacement)
    else:
        replacement = "YOUR_API_KEY_HERE"
        updated, count = _replace_one(line, _matches(_SECRET_FIELD, line, "value"), finding, replacement)
    return updated, replacement, count


def _remediate_copy(root: Path, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    seen: set[tuple[str, int, str, str]] = set()
    for finding in findings:
        if finding["disposition"] != "remediate" or (
            finding["category"], finding["detector"]
        ) not in _ALLOWED_REMEDIATIONS or "line" not in finding:
            raise PreparationError("A scanner finding is not eligible for deterministic remediation.")
        key = (
            finding["relative_path"], int(finding["line"]), finding["detector"], finding["fingerprint"]
        )
        if key in seen:
            continue
        seen.add(key)
        grouped[finding["relative_path"]].append(finding)

    changes: list[dict[str, Any]] = []
    for relative_path in sorted(grouped):
        path = root.joinpath(*PurePosixPath(relative_path).parts)
        if not path.is_file() or path.is_symlink():
            raise PreparationError(f"Remediation target is not a regular file: {relative_path}")
        raw = path.read_bytes()
        had_bom = raw.startswith(b"\xef\xbb\xbf")
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise PreparationError(f"Remediation target is not UTF-8 text: {relative_path}") from exc
        lines = text.splitlines(keepends=True)
        for finding in sorted(grouped[relative_path], key=lambda item: int(item["line"])):
            line_index = int(finding["line"]) - 1
            if line_index >= len(lines):
                raise PreparationError(f"Scanner line is outside file: {relative_path}")
            updated, placeholder, count = _substitute_line(lines[line_index], finding)
            if count < 1:
                raise PreparationError(
                    f"Reported finding could not be safely remediated: {relative_path}:{line_index + 1}"
                )
            lines[line_index] = updated
            changes.append({
                "relative_path": relative_path,
                "category": finding["category"],
                "detector": finding["detector"],
                "fingerprint": finding["fingerprint"],
                "line": line_index + 1,
                "replacement_count": count,
                "placeholder": placeholder,
            })
        encoded = "".join(lines).encode("utf-8")
        path.write_bytes((b"\xef\xbb\xbf" if had_bom else b"") + encoded)
    return changes


def _write_reproducible_zip(root: Path, archive_path: Path) -> None:
    entries = sorted(root.rglob("*"), key=lambda path: path.relative_to(root).as_posix())
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in entries:
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                raise PreparationError(f"Refusing to archive a symbolic link: {relative}")
            if path.is_dir():
                info = zipfile.ZipInfo(relative + "/", date_time=(1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = (stat.S_IFDIR | 0o755) << 16
                archive.writestr(info, b"")
                continue
            info = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            executable = bool(path.stat().st_mode & 0o111)
            info.external_attr = (stat.S_IFREG | (0o755 if executable else 0o644)) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)


def _blocked_status(report: Mapping[str, Any]) -> str:
    if report["status"] == "rejected" or any(
        finding["disposition"] == "reject" for finding in report["findings"]
    ):
        return "rejected"
    return "manual_review_required"


def prepare_repository(
    source_root: Path,
    output_directory: Path,
    *,
    upstream_commit_sha: str,
    original_archive_sha256: str,
    scanner: ScanTree | None = None,
) -> dict[str, Any]:
    """Scan, safely remediate when possible, re-scan, and package a repository.

    A successful return has status ``clean`` or ``sanitized_clean``.  Rejected
    and manual-review results intentionally contain no prepared archive.
    """
    source_root = Path(source_root).resolve()
    output_directory = Path(output_directory).resolve()
    if not source_root.is_dir():
        raise PreparationError("source_root must be an existing directory.")
    try:
        output_directory.relative_to(source_root)
    except ValueError:
        pass
    else:
        raise PreparationError("output_directory must not be inside source_root.")
    if not isinstance(upstream_commit_sha, str) or not re.fullmatch(r"[0-9a-fA-F]{40}", upstream_commit_sha):
        raise PreparationError("upstream_commit_sha must be a 40-character hexadecimal SHA.")
    if not isinstance(original_archive_sha256, str) or not re.fullmatch(
        r"[0-9a-fA-F]{64}", original_archive_sha256
    ):
        raise PreparationError("original_archive_sha256 must be a 64-character hexadecimal digest.")
    owned_paths = (
        output_directory / "prepared_repository",
        output_directory / "content_safety_report.json",
        output_directory / "sanitization_manifest.json",
        output_directory / "upload_ready_repository.zip",
    )
    collisions = [path.name for path in owned_paths if path.exists() or path.is_symlink()]
    if collisions:
        raise PreparationError(f"Refusing to overwrite existing preparation artifacts: {', '.join(collisions)}")

    if scanner is None:
        from repository_kickoff.content_safety import scan_tree

        scanner = scan_tree
    source_report = _normalize_report(scanner(source_root))
    output_directory.mkdir(parents=True, exist_ok=True)
    prepared_root = output_directory / "prepared_repository"

    changes: list[dict[str, Any]] = []
    initial_status = source_report["status"]
    has_reject = any(finding["disposition"] == "reject" for finding in source_report["findings"])
    has_manual_review = any(
        finding["disposition"] == "manual_review" for finding in source_report["findings"]
    )
    inconsistent_clean = initial_status == "clean" and bool(source_report["findings"])
    inconsistent_remediation = initial_status == "remediation_required" and not source_report["findings"]
    if initial_status in {"rejected", "manual_review_required"} or has_reject or has_manual_review:
        status = _blocked_status(source_report)
        final_report = None
    elif inconsistent_clean or inconsistent_remediation:
        status = "manual_review_required"
        final_report = None
    elif initial_status == "remediation_required":
        # Preserve links rather than following them if the source changes after
        # its scan. The mandatory prepared-tree rescan will reject the link.
        shutil.copytree(source_root, prepared_root, symlinks=True)
        try:
            changes = _remediate_copy(prepared_root, source_report["findings"])
        except PreparationError:
            shutil.rmtree(prepared_root)
            status = "manual_review_required"
            final_report = None
        else:
            final_report = _normalize_report(scanner(prepared_root))
            status = "sanitized_clean" if final_report["status"] == "clean" and not final_report["findings"] else _blocked_status(final_report)
            if status != "sanitized_clean":
                shutil.rmtree(prepared_root)
    else:
        shutil.copytree(source_root, prepared_root, symlinks=True)
        final_report = _normalize_report(scanner(prepared_root))
        status = "clean" if final_report["status"] == "clean" and not final_report["findings"] else _blocked_status(final_report)
        if status != "clean":
            shutil.rmtree(prepared_root)

    safety_report = {
        "status": status,
        "source_scan": source_report,
        "prepared_scan": final_report,
    }
    report_path = output_directory / "content_safety_report.json"
    report_path.write_bytes(_canonical_json(safety_report))

    category_counts: dict[str, int] = defaultdict(int)
    for finding in source_report["findings"]:
        category_counts[finding["category"]] += 1
    manifest = {
        "status": status,
        "relative_paths": sorted({finding["relative_path"] for finding in source_report["findings"]}),
        "categories": sorted(category_counts),
        "counts": {
            "source_findings": len(source_report["findings"]),
            "replacements": sum(change["replacement_count"] for change in changes),
            "by_category": dict(sorted(category_counts.items())),
        },
        "fingerprints": sorted({finding["fingerprint"] for finding in source_report["findings"]}),
        "placeholders": sorted({change["placeholder"] for change in changes}),
    }
    manifest_path = output_directory / "sanitization_manifest.json"
    manifest_path.write_bytes(_canonical_json(manifest))
    manifest_sha256 = _sha256_file(manifest_path)

    archive_path: Path | None = None
    prepared_archive_sha256: str | None = None
    workspace_state: str | None = None
    if status in {"clean", "sanitized_clean"}:
        archive_path = output_directory / "upload_ready_repository.zip"
        _write_reproducible_zip(prepared_root, archive_path)
        prepared_archive_sha256 = _sha256_file(archive_path)
        workspace_state = "clean_upstream" if status == "clean" else "sanitized_derivative"

    identity = {
        "upstream_commit_sha": upstream_commit_sha.lower(),
        "original_archive_sha256": original_archive_sha256.lower(),
        "prepared_archive_sha256": prepared_archive_sha256,
        "workspace_state": workspace_state,
        "sanitization_manifest_sha256": manifest_sha256,
        "safety_status": status,
    }
    return {
        "status": status,
        "prepared_root": str(prepared_root) if prepared_root.exists() else None,
        "archive_path": str(archive_path) if archive_path else None,
        "report_path": str(report_path),
        "manifest_path": str(manifest_path),
        "source_report": source_report,
        "final_report": final_report,
        "identity": identity,
    }
