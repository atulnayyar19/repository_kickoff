"""Conservative, local-only repository screening before any external upload.

This is heuristic screening, not a guarantee that a tree contains no sensitive
data. It never imports repository code and never emits matched values. Unknown
encodings, opaque files and incomplete scans fail closed for manual review.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from collections import Counter
from pathlib import Path


MAX_TEXT_BYTES = 2 * 1024 * 1024
MAX_FILES = 100_000
EMAIL_RE = re.compile(r"(?<![\w.+-])[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9-]+(?:\.[A-Z0-9-]+)+", re.I)
PHONE_RE = re.compile(r"(?<![\w.])(?:\+\d[\d ()-]{7,18}\d|(?:\(\d{3}\)|\d{3})[ .-]\d{3}[ .-]\d{4})(?![\w.])")
SSN_RE = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----|-----BEGIN PGP PRIVATE KEY BLOCK-----|PuTTY-User-Key-File-[23]:")
TOKEN_RE = re.compile(r"\b(?:AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-(?:proj-)?[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{15,}|AIza[A-Za-z0-9_-]{35})\b")
ASSIGNMENT_RE = re.compile(
    r'''(?ix)(?<![\w])(?P<key>(?:[a-z0-9]+[_-])*(?:api[_-]?key|access[_-]?token|auth[_-]?token|refresh[_-]?token|client[_-]?secret|secret[_-]?access[_-]?key|secret[_-]?key|private[_-]?key|password|passwd|pwd|token|secret))["']?\s*[:=]\s*(?:[rubf]*(?P<quote>["'])(?P<quoted>[^\r\n]*?)(?P=quote)|(?P<bare>[^\s,;#}\]]+))'''
)
STRUCTURED_RE = re.compile(
    r'''(?ix)\b(?:ssn|social[_ -]?security(?:[_ -]?number)?|passport(?:[_ -]?(?:number|no))?|national[_ -]?id|tax[_ -]?id|date[_ -]?of[_ -]?birth|dob|credit[_ -]?card(?:[_ -]?number)?|card[_ -]?number|iban)["']?\s*[:=,]\s*["']?([A-Z0-9][A-Z0-9 /.-]{3,40})'''
)
NAME_RE = re.compile(
    r'''(?ix)\b(full[_ -]?name|first[_ -]?name|last[_ -]?name|person[_ -]?name|customer[_ -]?name|patient[_ -]?name)["']?\s*[:=,]\s*["']([A-Z][A-Z .'’-]{1,70})["']'''
)
ATTRIBUTION_FIELD_RE = re.compile(
    r'''(?ix)\b(?:author|maintainer|copyright(?:[_ -]?holder)?|owner)["']?\s*[:=]\s*(?:\[?\{?\s*)?["']([A-Z][A-Z .'’&()-]{1,100})["']'''
)
COPYRIGHT_NAME_RE = re.compile(
    r'''(?ix)\bcopyright(?:\s*\(c\))?(?:\s+\d{4}(?:\s*[-–]\s*\d{4})?)?\s+([A-Z][A-Z0-9 .'’&(),_-]{1,100}?)(?=\s*<|\s*$)'''
)
OWNERSHIP_RE = re.compile(r"\b(?:confidential|trade secret|internal use only|not for (?:public )?distribution|proprietary (?:and confidential|information|software|code|material)|all rights reserved)\b", re.I)
OPAQUE_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".tif", ".tiff", ".heic",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".zip", ".gz", ".bz2", ".xz", ".tar", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".pyc", ".pyo", ".class", ".jar", ".wasm", ".db", ".sqlite", ".sqlite3",
    ".mp3", ".mp4", ".mov", ".wav", ".woff", ".woff2", ".ttf", ".otf", ".pkl", ".pickle", ".npy", ".npz",
}
SENSITIVE_NAMES = {".netrc", "_netrc", ".npmrc", ".pypirc", ".git-credentials", "credentials", "credentials.json", "credentials.ini", "secrets.json", "secrets.yaml", "secrets.yml", "secrets.toml", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "authorized_keys", "known_hosts"}
SAFE_VALUES = {"", "none", "null", "false", "true", "redacted", "[redacted]", "<redacted>", "your_api_key_here", "your_api_key", "your_token_here", "your_password_here", "example", "example-key", "example-token", "example-password", "test user", "example user", "example contributor", "test", "user"}
PLACEHOLDER_VALUES = {
    "changeme", "change-me", "password", "password123", "abc123", "testkey",
    "test-token", "dummy", "placeholder", "secret", "pass",
}
EXAMPLE_PATH_PARTS = {"doc", "docs", "documentation", "test", "tests", "fixture", "fixtures", "example", "examples", "sample", "samples", "testdata"}


def fingerprint(value: str | bytes) -> str:
    """One-way identifier; callers must never put the input in the report."""
    data = value.encode("utf-8", errors="surrogatepass") if isinstance(value, str) else value
    return hashlib.sha256(b"repository-content-safety-v1\0" + data).hexdigest()


def _safe_value(value: str) -> bool:
    lower = value.strip().lower()
    return (
        lower in SAFE_VALUES
        or lower.startswith(("${", "{{", "<your", "your_", "redacted_"))
        or bool(re.fullmatch(r"<[^<>\r\n]{1,80}>", lower))
        or bool(re.fullmatch(r"synthetic-id-[0-9a-f]+", lower))
        or bool(re.fullmatch(r"[0x* _-]+", lower))
    )


def _is_example_path(path: Path, root: Path) -> bool:
    relative = path.relative_to(root)
    return any(part.casefold() in EXAMPLE_PATH_PARTS for part in relative.parts[:-1]) or path.suffix.casefold() in {
        ".md", ".mdx", ".rst", ".adoc",
    }


def _placeholder_secret(value: str, path: Path, root: Path) -> bool:
    """Recognize bounded synthetic examples without accepting token-shaped data."""
    normalized = value.strip()
    lower = normalized.casefold()
    if lower in PLACEHOLDER_VALUES:
        return True
    if not _is_example_path(path, root) or not normalized or len(normalized) > 16:
        return False
    # Short literals in tests and documentation are safe to replace in the
    # prepared copy. Known provider tokens and private keys are rejected by
    # earlier, higher-priority detectors.
    return bool(re.fullmatch(r"[A-Za-z0-9_.@+-]+", normalized))


def _example_email(value: str) -> bool:
    domain = value.rsplit("@", 1)[-1].lower()
    return domain in {"example.com", "example.org", "example.net", "localhost"} or domain.endswith((".example.com", ".example.org", ".example.net", ".invalid", ".test", ".example"))


def _phone_is_placeholder(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    return len(digits) >= 10 and digits[-7:-4] == "555"


def _path_label(relative: str) -> tuple[str, bool]:
    """Keep usable relative paths while withholding PII embedded in filenames."""
    label = relative
    for pattern in (EMAIL_RE, PHONE_RE, SSN_RE, TOKEN_RE):
        label = pattern.sub(lambda match: "[redacted-" + fingerprint(match.group())[:12] + "]", label)
    return label, label != relative


def _is_link(metadata: os.stat_result) -> bool:
    return stat.S_ISLNK(metadata.st_mode) or bool(getattr(metadata, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 1024))


def scan_tree(root: Path) -> dict:
    """Return JSON-ready findings without raw matches, snippets or absolute paths.

    Finding dispositions are ``remediate``, ``manual_review`` or ``reject``.
    Only a ``clean`` result permits upload. Remediation must be followed by a
    complete rescan. The source tree is read only; symlinks/junctions are blocked.
    """
    root = Path(root)
    findings: list[dict] = []
    files_seen = 0
    files_scanned = 0

    def add(category: str, disposition: str, relative: str, detector: str, value: str | bytes, line: int | None = None) -> None:
        label, hidden = _path_label(relative)
        if hidden and disposition == "remediate":
            disposition = "manual_review"
        item = {
            "category": category,
            "severity": {"remediate": "medium", "manual_review": "high", "reject": "critical"}[disposition],
            "disposition": disposition,
            "relative_path": label,
            "detector": detector,
            "fingerprint": fingerprint(value),
        }
        if line is not None:
            item["line"] = line
        findings.append(item)

    def scan_file(path: Path, relative: str, metadata: os.stat_result) -> None:
        nonlocal files_scanned
        name = path.name.lower()
        suffix = path.suffix.lower()
        if _path_label(relative)[1]:
            add("text_pii", "manual_review", relative, "sensitive_path", relative)
        if name == ".env" or name.startswith(".env.") or name.endswith(".env"):
            add("sensitive_filename", "reject", relative, "environment_file", name)
        elif name in SENSITIVE_NAMES or suffix in {".key", ".pem", ".p12", ".pfx", ".jks", ".keystore"} or re.search(r"(?:service[-_]?account|client[-_]?secret|credentials?|secrets?)[-_.]", name):
            add("sensitive_filename", "manual_review", relative, "credential_file", name)
        if suffix in {".csv", ".tsv", ".log", ".sql", ".jsonl", ".ndjson"}:
            add("data_export", "manual_review", relative, "structured_export", name)
        if suffix in OPAQUE_SUFFIXES:
            add("uninspectable", "manual_review", relative, "opaque_file", name)
            return
        if metadata.st_size > MAX_TEXT_BYTES:
            add("uninspectable", "manual_review", relative, "file_size_limit", relative)
            return
        try:
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
            descriptor = os.open(path, flags)
            with os.fdopen(descriptor, "rb") as source:
                opened = os.fstat(source.fileno())
                if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                    add("uninspectable", "reject", relative, "file_changed_during_scan", relative)
                    return
                data = source.read(MAX_TEXT_BYTES + 1)
        except OSError:
            add("uninspectable", "manual_review", relative, "unreadable_file", relative)
            return
        if len(data) > MAX_TEXT_BYTES:
            add("uninspectable", "manual_review", relative, "file_size_limit", relative)
            return
        if b"\0" in data:
            add("uninspectable", "manual_review", relative, "binary_or_encoding", data)
            return
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError:
            add("uninspectable", "manual_review", relative, "unknown_encoding", data)
            return
        if any(ord(character) < 32 and character not in "\t\n\r\f" for character in text):
            add("uninspectable", "manual_review", relative, "binary_control_characters", data)
            return
        files_scanned += 1
        if suffix == ".svg" and re.search(r"(?:<image\b|data\s*:\s*image/)", text, re.I):
            add("uninspectable", "manual_review", relative, "embedded_raster_image", data)
        attribution_list_file = name.startswith(("authors", "contributors"))
        for number, line in enumerate(text.splitlines(), 1):
            stripped_line = line.strip()
            whole_attribution_line = bool(
                attribution_list_file
                and stripped_line
                and not _safe_value(stripped_line)
                and not stripped_line.startswith(("#", "..", "=="))
                and re.search(r"[A-Za-z]", stripped_line)
            )
            if whole_attribution_line:
                add("text_pii", "remediate", relative, "attribution_name", stripped_line, number)
            else:
                for pattern in (ATTRIBUTION_FIELD_RE, COPYRIGHT_NAME_RE):
                    for match in pattern.finditer(line):
                        if not _safe_value(match.group(1)):
                            add("text_pii", "remediate", relative, "attribution_name", match.group(1), number)
            for match in PRIVATE_KEY_RE.finditer(line):
                add("secret", "reject", relative, "private_key", match.group(), number)
            for match in TOKEN_RE.finditer(line):
                add("secret", "reject", relative, "known_token", match.group(), number)
            for match in ASSIGNMENT_RE.finditer(line):
                key = match.group("key")
                value = match.group("quoted") if match.group("quote") else match.group("bare")
                if key.casefold() == "id-token" and value.casefold() in {"read", "write", "none"}:
                    # GitHub Actions permission, not a credential assignment.
                    continue
                if _safe_value(value):
                    continue
                # Bare expressions are code references, not literal credentials.
                if not match.group("quote") and suffix in {".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".java", ".rs", ".c", ".cpp"} and (re.search(r"[().\[\]{}]", value) or re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", value)):
                    continue
                placeholder = _placeholder_secret(value, path, root)
                add("placeholder_secret" if placeholder else "secret", "remediate" if placeholder else "reject", relative, "placeholder_secret" if placeholder else "secret_assignment", value, number)
            for match in EMAIL_RE.finditer(line):
                if not whole_attribution_line and not _example_email(match.group()):
                    add("text_pii", "remediate", relative, "email", match.group(), number)
            for match in PHONE_RE.finditer(line):
                if 10 <= len(re.sub(r"\D", "", match.group())) <= 15 and not _phone_is_placeholder(match.group()):
                    add("text_pii", "remediate", relative, "phone", match.group(), number)
            for match in SSN_RE.finditer(line):
                if not _safe_value(match.group()):
                    add("text_pii", "remediate", relative, "structured_id", match.group(), number)
            for match in STRUCTURED_RE.finditer(line):
                if not _safe_value(match.group(1)):
                    add("text_pii", "remediate", relative, "structured_id", match.group(1), number)
            for match in NAME_RE.finditer(line):
                if not _safe_value(match.group(2)):
                    fixture = any(part.lower() in {"test", "tests", "fixtures", "examples", "samples", "testdata"} for part in path.relative_to(root).parts[:-1])
                    add("fixture_name" if fixture else "text_pii", "remediate", relative, "fixture_name" if fixture else "personal_name", match.group(2), number)
            for match in OWNERSHIP_RE.finditer(line):
                # Standard open-source notices commonly reserve copyright rights.
                if match.group().lower() == "all rights reserved":
                    continue
                add("ownership", "manual_review", relative, "ownership_indicator", match.group(), number)

    try:
        root_metadata = root.lstat()
    except OSError:
        add("uninspectable", "reject", ".", "missing_root", "missing_root")
    else:
        if _is_link(root_metadata) or not stat.S_ISDIR(root_metadata.st_mode):
            add("uninspectable", "reject", ".", "unsafe_root", "unsafe_root")
        else:
            pending = [root]
            stop = False
            while pending and not stop:
                directory = pending.pop()
                try:
                    if _is_link(directory.lstat()):
                        add("symlink", "reject", directory.relative_to(root).as_posix(), "symlink_or_junction", "symlink")
                        continue
                    with os.scandir(directory) as entries:
                        children = sorted(entries, key=lambda entry: entry.name)
                except OSError:
                    add("uninspectable", "manual_review", directory.relative_to(root).as_posix(), "unreadable_directory", "directory")
                    continue
                for entry in children:
                    path = Path(entry.path)
                    relative = path.relative_to(root).as_posix()
                    try:
                        # Windows DirEntry.stat may report zero device/inode;
                        # lstat supplies the identity checked after opening.
                        metadata = path.lstat()
                    except OSError:
                        add("uninspectable", "manual_review", relative, "unreadable_entry", relative)
                        continue
                    if _is_link(metadata):
                        add("symlink", "reject", relative, "symlink_or_junction", relative)
                    elif stat.S_ISDIR(metadata.st_mode):
                        pending.append(path)
                    elif stat.S_ISREG(metadata.st_mode):
                        files_seen += 1
                        if files_seen > MAX_FILES:
                            add("uninspectable", "manual_review", ".", "file_count_limit", "file_count_limit")
                            stop = True
                            break
                        scan_file(path, relative, metadata)
                    else:
                        add("uninspectable", "reject", relative, "special_file", relative)
    dispositions = Counter(item["disposition"] for item in findings)
    status = "rejected" if dispositions["reject"] else "manual_review_required" if dispositions["manual_review"] else "remediation_required" if findings else "clean"
    return {
        "schema_version": 1,
        "status": status,
        "counts": {
            "files_seen": files_seen,
            "files_scanned": files_scanned,
            "findings": len(findings),
            "by_category": dict(sorted(Counter(item["category"] for item in findings).items())),
            "by_disposition": dict(sorted(dispositions.items())),
        },
        "findings": findings,
        "limitations": ["Heuristic local screening cannot prove absence of sensitive content.", "Only bounded UTF-8 text is inspected; opaque or unreadable content requires manual review."],
    }
