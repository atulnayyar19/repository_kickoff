#!/usr/bin/env python3
"""Select, risk-report, and generate a source-grounded engineering task.

The workflow deliberately uses two independent model calls:

1. a repository finder with web search and a strict eligibility contract;
2. an engineering-task writer grounded in the selected repository and pinned commit.

Successful runs append to a local repository registry and save an inspectable
Markdown result and JSON stage records. Only clean repositories receive an
upload-ready archive. Downloaded content is never installed or executed.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
from http.client import HTTPException
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import quote, quote_plus, urlparse
from urllib.request import Request, urlopen

# A direct ``python repository_kickoff/repository_kickoff.py`` launch puts this
# directory ahead of its parent and would otherwise shadow the namespace
# package with this file. Keep the documented script invocation working.
if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from repository_kickoff.archive_preparation import (
    MAX_ARCHIVE_BYTES,
    ArchivePreparationError,
    download_github_archive,
    safely_extract_archive,
)
from repository_kickoff.content_safety import scan_tree
from repository_kickoff.sanitization import PreparationError, prepare_repository


TOOL_DIRECTORY = Path(__file__).resolve().parent
PROMPT_DIRECTORY = TOOL_DIRECTORY / "prompts"
LEDGER_PATH = TOOL_DIRECTORY / "data" / "used_repositories.json"
DEFAULT_OUTPUT_DIRECTORY = TOOL_DIRECTORY / "outputs"
DEFAULT_REPOSITORY_DIRECTORY = TOOL_DIRECTORY / "selected_repositories"

DEFAULT_FINDER_MODEL = "gpt-5.6-sol"
DEFAULT_FINDER_REASONING = "xhigh"
DEFAULT_WRITER_MODEL = "gpt-5.6-sol"
DEFAULT_WRITER_REASONING = "high"
DEFAULT_MAX_OUTPUT_TOKENS = 40_000
REASONING_EFFORTS = ("none", "low", "medium", "high", "xhigh", "max")
REPOSITORY_STATUSES = {"used_for_task", "potential_pii"}

MIN_STARS_EXCLUSIVE = 500
RECENT_ACTIVITY_DAYS = 2 * 365
PREFLIGHT_TARGET_CANDIDATES = 2
PREFLIGHT_MAX_INSPECTIONS = 40
PREFLIGHT_SEED_LIMIT = 8
MIN_TRACKED_FILES = 50
MIN_SOURCE_PYTHON_FILES = 8
MIN_TEST_PYTHON_FILES = 8
MIN_TOTAL_PYTHON_FILES = 20
PREFLIGHT_SEARCH_QUERIES = (
    f"language:Python stars:>{MIN_STARS_EXCLUSIVE} archived:false fork:false topic:library",
    f"language:Python stars:>{MIN_STARS_EXCLUSIVE} archived:false fork:false topic:testing",
)
ALLOWED_LICENSES = {
    "MIT", "MIT-0", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause",
    "ISC", "Zlib", "0BSD", "Unlicense", "CC0-1.0",
}
EXCLUDED_DOMAIN_TERMS = {
    "cybersecurity", "cyber-security", "penetration testing", "pentest", "exploit",
    "malware", "ransomware", "phishing", "red team", "red-team", "keylogger",
    "bioinformatics", "biotech", "biotechnology", "genomics", "genome", "proteomics",
    "drug discovery", "molecular biology", "protein folding", "synthetic biology", "pathogen",
}
DOTENV_KEYS = {"OPENAI_API_KEY", "GITHUB_TOKEN"}
GITHUB_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40}$")
OPENING_APPROACHES = (
    "lifecycle_and_state", "cross_boundary_contract", "configuration_and_environment",
    "testability_and_observability", "data_ownership_and_transformation", "maintainer_risk_review",
)
LONG_HORIZON_DIMENSIONS = {
    "design", "implementation", "debugging", "testing", "maintenance",
    "compatibility", "migration", "observability", "failure_recovery",
}
TASK_SECTION_HEADINGS = (
    "# Goal", "# Context", "# Scope", "# Expected Outcome", "# Guardrails",
)
TASK_LIST_FIELDS = ("scope", "expected_outcome", "guardrails")
WRITER_REPOSITORY_FIELDS = (
    "full_name", "url", "description", "default_branch", "commit_sha",
    "evidence_commit_sha", "workflow_theme", "entry_points", "collaborators",
    "test_surfaces", "ci_surfaces", "documented_commands", "risks",
    "source_evidence",
)
TASK_SOURCE_CONTEXT_PATTERNS = (
    (re.compile(r"\b(?:upload[- ]ready|safety[- ]reviewed|(?:safety[- ])?sanitized[- ]derivative)\b", re.IGNORECASE),
     "repository preparation status"),
    (re.compile(r"\b(?:content[- ](?:risk|safety)|advisory|risk|prepared[- ]tree)\s+(?:review|scan|gate)\b", re.IGNORECASE),
     "content-review status"),
    (re.compile(r"\bcontent_safety_findings(?:\.md)?\b|\b(?:PII|secret|credential)\s+findings?\b", re.IGNORECASE),
     "content-risk report context"),
    (re.compile(r"\bupload\s+safety\b|\b(?:repository|codebase|workspace|archive)\s+is\s+(?:safe|ready)\s+to\s+upload\b", re.IGNORECASE),
     "repository upload status"),
)
TASK_META_LANGUAGE_PATTERNS = (
    (re.compile(r"\b(?:next(?:\s+best)?|recommended(?:\s+next)?)\s+implementation(?:\s+slice)?\b", re.IGNORECASE),
     "next or recommended implementation"),
    (re.compile(r"\brecommend(?:ed|ing)?\b[^.\n]{0,80}\bnext\s+(?:best\s+)?implementation\b", re.IGNORECASE),
     "recommended next implementation"),
    (re.compile(r"\bimplementation\s+slice\b", re.IGNORECASE), "implementation slice"),
    (re.compile(r"\b(?:later|future|subsequent)\s+(?:implementation|change|task|work)\b", re.IGNORECASE),
     "later or future work"),
    (re.compile(r"\bfollow[- ]?(?:up|on)\s+(?:implementation|change|task|turn|work)\b", re.IGNORECASE),
     "follow-up work"),
    (re.compile(r"\b(?:foundation|basis)\s+for\s+(?:a\s+)?(?:later|future|subsequent)\b", re.IGNORECASE),
     "foundation for later work"),
    (re.compile(r"\b(?:later|future|subsequent|next)\s+(?:adaptive\s+)?turns?\b", re.IGNORECASE),
     "future turns"),
    (re.compile(r"\b(?:coding|AI)\s+(?:agent|model)\b", re.IGNORECASE), "AI or coding-agent framing"),
    (re.compile(r"\b(?:coding[- ]model|software[- ]engineering|long[- ]horizon)\s+(?:evaluation|benchmark)\b", re.IGNORECASE),
     "evaluation or benchmark framing"),
    (re.compile(r"\blong[- ]horizon\b", re.IGNORECASE), "long-horizon framing"),
    (re.compile(r"\bgrader\b|\btoken\s+(?:budget|exhaustion)\b", re.IGNORECASE),
     "grader or token-budget framing"),
)


class KickoffError(RuntimeError):
    """An actionable local, API, or validation error."""


def load_local_dotenv(path: Path) -> bool:
    """Load only supported keys without overriding the process environment."""
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise KickoffError(f"Cannot read configuration file {path}: {exc}") from exc
    loaded = False
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, separator, value = line.partition("=")
        key = key.strip()
        if not separator or key not in DOTENV_KEYS:
            continue
        value = value.strip()
        if len(value) >= 2 and value[:1] == value[-1:] and value[:1] in {"'", '"'}:
            value = value[1:-1]
        if value and key not in os.environ:
            os.environ[key] = value
            loaded = True
    return loaded


def load_prompt(name: str) -> str:
    path = PROMPT_DIRECTORY / name
    try:
        value = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise KickoffError(f"Cannot read prompt {path}: {exc}") from exc
    if not value.strip():
        raise KickoffError(f"Prompt {path} is empty.")
    return value


def normalize_github_url(value: str) -> str:
    parsed = urlparse(value.strip())
    if parsed.scheme != "https" or parsed.hostname not in {"github.com", "www.github.com"}:
        raise KickoffError(f"Not a public GitHub repository URL: {value!r}")
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) != 2:
        raise KickoffError(f"GitHub URL must identify exactly owner/repository: {value!r}")
    full_name = f"{parts[0]}/{parts[1].removesuffix('.git')}"
    if not GITHUB_NAME_RE.fullmatch(full_name):
        raise KickoffError(f"Invalid GitHub owner/repository name: {full_name!r}")
    return f"https://github.com/{full_name}"


def full_name_from_url(value: str) -> str:
    return "/".join(normalize_github_url(value).split("/")[-2:])


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except FileNotFoundError as exc:
        raise KickoffError(f"Required file does not exist: {path}") from exc
    except OSError as exc:
        raise KickoffError(f"Cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise KickoffError(f"Invalid JSON in {path}: {exc}") from exc


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    for attempt in range(5):
        try:
            temporary.replace(path)
            return
        except PermissionError:
            if attempt == 4:
                raise
            time.sleep(0.05 * (attempt + 1))


def _markdown_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace("[", "\\[").replace("]", "\\]").replace("|", "\\|")


def _github_finding_url(full_name: str, commit_sha: str, relative_path: str, line: int | None = None) -> str:
    base = f"https://github.com/{full_name}"
    if relative_path == "." or "[redacted-" in relative_path:
        return f"{base}/tree/{commit_sha}"
    encoded_path = quote(relative_path, safe="/-._~")
    suffix = f"#L{line}" if line is not None else ""
    return f"{base}/blob/{commit_sha}/{encoded_path}{suffix}"


def render_content_safety_findings_markdown(
    full_name: str,
    commit_sha: str,
    source_report: Mapping[str, Any],
    *,
    preparation_status: str | None = None,
    prepared_scan_status: str | None = None,
) -> str:
    """Render safe, pinned links for every file flagged by the local scanner."""
    if not GITHUB_NAME_RE.fullmatch(full_name) or not COMMIT_RE.fullmatch(commit_sha):
        raise KickoffError("Cannot render a content-safety report without a valid repository and commit.")
    raw_findings = source_report.get("findings") if isinstance(source_report, Mapping) else None
    findings = [dict(item) for item in raw_findings or [] if isinstance(item, Mapping)]
    grouped: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        relative_path = str(finding.get("relative_path") or ".")
        grouped.setdefault(relative_path, []).append(finding)

    counts = source_report.get("counts") if isinstance(source_report.get("counts"), Mapping) else {}
    risk_level = {
        "clean": "low (no findings detected)",
        "remediation_required": "elevated (findings require review)",
        "manual_review_required": "high (files require manual inspection)",
        "rejected": "critical (potential credentials or other hard findings)",
    }.get(str(source_report.get("status")), "unknown")
    lines = [
        f"# Content-safety findings: {full_name}",
        "",
        f"- Repository: [{full_name}](https://github.com/{full_name})",
        f"- Pinned commit: `{commit_sha}`",
        f"- Risk scan status: `{source_report.get('status', 'unknown')}`",
        f"- Review risk factor: {risk_level}",
        f"- Potential findings: `{len(findings)}` across `{len(grouped)}` files",
        f"- Files scanned: `{counts.get('files_scanned', 'unknown')}`",
        "- Selection and prompt-writing effect: advisory only",
        f"- Upload preparation status: `{preparation_status or 'not_run'}`",
        f"- Prepared-tree rescan status: `{prepared_scan_status or 'not_run'}`",
        "",
        "This report links to the original public GitHub snapshot. It intentionally omits matched values, snippets, and fingerprints. A finding is a heuristic review signal, not proof that a value is sensitive.",
        "",
    ]
    if not findings:
        lines.extend(["No potential PII, credential, key, ownership, export, or uninspectable-file findings were reported.", ""])
        return "\n".join(lines)

    lines.extend([
        "| Flagged file | Categories | Detectors | Dispositions | Findings | Flagged lines |",
        "| --- | --- | --- | --- | ---: | --- |",
    ])
    for relative_path in sorted(grouped, key=str.casefold):
        records = grouped[relative_path]
        line_numbers = sorted({
            int(record["line"]) for record in records
            if type(record.get("line")) is int and int(record["line"]) > 0
        })
        first_line = line_numbers[0] if line_numbers else None
        file_url = _github_finding_url(full_name, commit_sha, relative_path, first_line)
        if "[redacted-" in relative_path:
            file_label = "path withheld because its filename may contain sensitive data"
        elif relative_path == ".":
            file_label = "repository root"
        else:
            file_label = relative_path
        file_link = f"[{_markdown_label(file_label)}]({file_url})"
        categories = ", ".join(sorted({_markdown_label(str(record.get("category") or "unknown")) for record in records}))
        detectors = ", ".join(sorted({_markdown_label(str(record.get("detector") or "unknown")) for record in records}))
        dispositions = ", ".join(sorted({_markdown_label(str(record.get("disposition") or "unknown")) for record in records}))
        if line_numbers and "[redacted-" not in relative_path and relative_path != ".":
            line_links = ", ".join(
                f"[L{number}]({_github_finding_url(full_name, commit_sha, relative_path, number)})"
                for number in line_numbers
            )
        elif line_numbers:
            line_links = ", ".join(f"L{number}" for number in line_numbers)
        else:
            line_links = "file-level"
        lines.append(
            f"| {file_link} | {categories} | {detectors} | {dispositions} | {len(records)} | {line_links} |"
        )
    lines.extend(["", "These findings require human review before using or uploading the repository. A registry status is not a content-safety certification; only a clean prepared-tree rescan can authorize an upload-ready archive.", ""])
    return "\n".join(lines)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def repository_key(value: str) -> str:
    return full_name_from_url(value).casefold()


def load_ledger(path: Path = LEDGER_PATH) -> dict[str, Any]:
    payload = read_json(path)
    repositories = payload.get("repositories") if isinstance(payload, Mapping) else None
    if not isinstance(repositories, list):
        raise KickoffError("Used-repositories ledger must contain a repositories array.")
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in repositories:
        if not isinstance(entry, Mapping):
            raise KickoffError("Every used-repository ledger entry must be an object.")
        url = normalize_github_url(str(entry.get("url", "")))
        key = repository_key(url)
        if key in seen:
            raise KickoffError(f"Duplicate repository in registry: {key}")
        status = entry.get("status")
        if status not in REPOSITORY_STATUSES:
            raise KickoffError(f"Repository registry has invalid status for {key}: {status!r}")
        seen.add(key)
        normalized.append({**dict(entry), "full_name": full_name_from_url(url), "url": url})
    return {"schema_version": 1, "repositories": normalized}


def source_evidence_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "claim": {"type": "string"},
            "url": {"type": "string"},
        },
        "required": ["claim", "url"],
        "additionalProperties": False,
    }


def finder_schema() -> dict[str, Any]:
    candidate = {
        "type": "object",
        "properties": {
            "full_name": {"type": "string"},
            "url": {"type": "string"},
            "stars": {"type": "integer"},
            "license_spdx": {"type": "string"},
            "commit_sha": {"type": "string"},
            "pushed_at": {"type": "string"},
            "workflow_theme": {"type": "string"},
            "assessment": {"type": "string"},
            "source_urls": {"type": "array", "items": {"type": "string"}},
        },
        "required": [
            "full_name", "url", "stars", "license_spdx", "commit_sha", "pushed_at",
            "workflow_theme", "assessment", "source_urls",
        ],
        "additionalProperties": False,
    }
    selected_properties = {
        "full_name": {"type": "string"},
        "url": {"type": "string"},
        "description": {"type": "string"},
        "default_branch": {"type": "string"},
        "commit_sha": {"type": "string"},
        "stars": {"type": "integer"},
        "license_spdx": {"type": "string"},
        "pushed_at": {"type": "string"},
        "opening_approach": {"type": "string", "enum": list(OPENING_APPROACHES)},
        "approach_reuse_reason": {"type": ["string", "null"]},
        "workflow_theme": {"type": "string"},
        "entry_points": {"type": "array", "items": {"type": "string"}},
        "collaborators": {"type": "array", "items": {"type": "string"}},
        "test_surfaces": {"type": "array", "items": {"type": "string"}},
        "ci_surfaces": {"type": "array", "items": {"type": "string"}},
        "documented_commands": {"type": "array", "items": {"type": "string"}},
        "risks": {"type": "array", "items": {"type": "string"}},
        "screening_limitations": {"type": "array", "items": {"type": "string"}},
        "source_evidence": {"type": "array", "items": source_evidence_schema()},
        "long_horizon_fit": {
            "type": "object",
            "properties": {
                "verdict": {"type": "string", "enum": ["strong_candidate"]},
                "boundary_chain": {"type": "array", "items": {"type": "string"}},
                "maintainer_dimensions": {
                    "type": "array", "items": {"type": "string", "enum": sorted(LONG_HORIZON_DIMENSIONS)},
                },
                "test_and_fixture_evidence": {"type": "array", "items": {"type": "string"}},
                "failure_recovery_complexity": {"type": "array", "items": {"type": "string"}},
                "local_feasibility": {"type": "string"},
                "disqualifiers": {"type": "array", "items": {"type": "string"}},
            },
            "required": [
                "verdict", "boundary_chain", "maintainer_dimensions", "test_and_fixture_evidence",
                "failure_recovery_complexity", "local_feasibility", "disqualifiers",
            ],
            "additionalProperties": False,
        },
    }
    return {
        "type": "object",
        "properties": {
            "selected_repository": {
                "type": "object",
                "properties": selected_properties,
                "required": list(selected_properties),
                "additionalProperties": False,
            },
            "selection_reason": {"type": "string"},
            "strongest_alternative": {"type": "string"},
            "candidates_considered": {"type": "array", "items": candidate},
            "uncertainties": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["selected_repository", "selection_reason", "strongest_alternative", "candidates_considered", "uncertainties"],
        "additionalProperties": False,
    }


def writer_schema() -> dict[str, Any]:
    task_properties = {
        "goal": {"type": "string"},
        "context": {"type": "string"},
        "scope": {"type": "array", "items": {"type": "string"}},
        "expected_outcome": {"type": "array", "items": {"type": "string"}},
        "guardrails": {"type": "array", "items": {"type": "string"}},
    }
    return {
        "type": "object",
        "properties": {
            "repository_url": {"type": "string"},
            "commit_sha": {"type": "string"},
            "request_type": {"type": "string", "enum": ["system_level_investigation"]},
            "task": {
                "type": "object",
                "properties": task_properties,
                "required": list(task_properties),
                "additionalProperties": False,
            },
            "citations": {"type": "array", "items": source_evidence_schema()},
            "grounding_notes": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["repository_url", "commit_sha", "request_type", "task", "citations", "grounding_notes"],
        "additionalProperties": False,
    }


def validate_url_list(values: Any, field: str) -> None:
    if not isinstance(values, list) or not values:
        raise KickoffError(f"{field} must be a non-empty list.")
    for value in values:
        parsed = urlparse(str(value))
        if parsed.scheme != "https" or not parsed.netloc:
            raise KickoffError(f"{field} contains a non-HTTPS URL: {value!r}")


def require_nonempty_string_list(value: Any, field: str) -> None:
    if not isinstance(value, list) or not value or any(not isinstance(item, str) or not item.strip() for item in value):
        raise KickoffError(f"{field} must be a non-empty list of non-empty strings.")


def parse_github_timestamp(value: Any, field: str) -> dt.datetime:
    if not isinstance(value, str) or not value.strip():
        raise KickoffError(f"{field} must be a non-empty ISO-8601 timestamp.")
    normalized = value.strip().replace("Z", "+00:00")
    try:
        parsed = dt.datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise KickoffError(f"{field} is not a valid ISO-8601 timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        raise KickoffError(f"{field} must include a timezone: {value!r}")
    return parsed.astimezone(dt.timezone.utc)


def activity_classification(value: Any, *, now: dt.datetime | None = None) -> dict[str, Any]:
    pushed_at = parse_github_timestamp(value, "pushed_at")
    reference = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    age = reference - pushed_at
    if age < dt.timedelta(days=-1):
        raise KickoffError(f"pushed_at is unexpectedly in the future: {value!r}")
    age_days = max(age.days, 0)
    return {
        "activity_status": "recent" if age_days <= RECENT_ACTIVITY_DAYS else "older",
        "activity_age_days": age_days,
    }


def validate_pinned_github_file_url(value: Any, full_name: str, commit_sha: str, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise KickoffError(f"{field} must contain non-empty URLs.")
    parsed = urlparse(value.strip())
    if parsed.scheme != "https" or parsed.hostname not in {"github.com", "www.github.com"}:
        raise KickoffError(f"{field} must use a GitHub HTTPS file URL: {value!r}")
    parts = [part for part in parsed.path.split("/") if part]
    expected_owner, expected_repository = full_name.split("/", 1)
    if len(parts) < 5 or parts[2] != "blob":
        raise KickoffError(f"{field} must use a commit-pinned GitHub blob URL: {value!r}")
    if parts[0].casefold() != expected_owner.casefold() or parts[1].casefold() != expected_repository.casefold():
        raise KickoffError(f"{field} cites a different repository: {value!r}")
    if parts[3].casefold() != commit_sha.casefold():
        raise KickoffError(f"{field} is not pinned to commit {commit_sha}: {value!r}")
    return value.strip()


def validate_source_evidence(
    records: Any, full_name: str, commit_sha: str, field: str, *, minimum: int,
) -> None:
    if not isinstance(records, list) or len(records) < minimum:
        raise KickoffError(f"{field} must contain at least {minimum} records.")
    seen_urls: set[str] = set()
    for record in records:
        if not isinstance(record, Mapping) or not isinstance(record.get("claim"), str) or not record["claim"].strip():
            raise KickoffError(f"Every {field} record must pair a non-empty claim with a URL.")
        url = validate_pinned_github_file_url(record.get("url"), full_name, commit_sha, field)
        if url in seen_urls:
            raise KickoffError(f"{field} contains a duplicate URL: {url}")
        seen_urls.add(url)


def validate_candidate(
    candidate: Any, used_keys: set[str], index: int, *, authoritative_metadata: bool = True,
    candidate_allowlist: Mapping[str, str] | None = None,
) -> tuple[str, str]:
    field = f"candidates_considered[{index}]"
    if not isinstance(candidate, dict):
        raise KickoffError(f"{field} must be an object.")
    url = normalize_github_url(str(candidate.get("url", "")))
    full_name = full_name_from_url(url)
    if str(candidate.get("full_name", "")).casefold() != full_name.casefold():
        raise KickoffError(f"{field} name does not match its URL.")
    if full_name.casefold() in used_keys:
        raise KickoffError(f"{field} is already used: {full_name}")
    if authoritative_metadata:
        stars = candidate.get("stars")
        if type(stars) is not int or stars <= MIN_STARS_EXCLUSIVE:
            raise KickoffError(f"{field} must have more than {MIN_STARS_EXCLUSIVE} stars: {stars!r}")
        if candidate.get("license_spdx") not in ALLOWED_LICENSES:
            raise KickoffError(f"{field} has a disallowed license: {candidate.get('license_spdx')!r}")
    commit_sha = str(candidate.get("commit_sha", ""))
    if not COMMIT_RE.fullmatch(commit_sha):
        raise KickoffError(f"{field} must provide a 40-character commit SHA.")
    if candidate_allowlist is not None:
        allowed_commit = candidate_allowlist.get(full_name.casefold())
        if allowed_commit is None:
            raise KickoffError(f"{field} is not in the deterministic preflight allowlist: {full_name}")
        if commit_sha.casefold() != allowed_commit.casefold():
            raise KickoffError(
                f"{field} commit does not match its deterministic preflight commit: {commit_sha}"
            )
    evidence_commit_sha = str(candidate.get("evidence_commit_sha", commit_sha))
    if not COMMIT_RE.fullmatch(evidence_commit_sha):
        raise KickoffError(f"{field} has an invalid evidence commit SHA.")
    if authoritative_metadata:
        parse_github_timestamp(candidate.get("pushed_at"), f"{field}.pushed_at")
    for name in ("workflow_theme", "assessment"):
        if not isinstance(candidate.get(name), str) or not candidate[name].strip():
            raise KickoffError(f"{field}.{name} must be a non-empty string.")
    source_urls = candidate.get("source_urls")
    if not isinstance(source_urls, list) or len(source_urls) < 2:
        raise KickoffError(f"{field}.source_urls must contain at least two pinned source files.")
    normalized_sources = [
        validate_pinned_github_file_url(value, full_name, evidence_commit_sha, f"{field}.source_urls")
        for value in source_urls
    ]
    if len(set(normalized_sources)) != len(normalized_sources):
        raise KickoffError(f"{field}.source_urls contains duplicate URLs.")
    candidate["url"] = url
    candidate["full_name"] = full_name
    return full_name, commit_sha


def validate_finder_result(
    result: Any, used_keys: set[str], recent_approaches: Sequence[str] = (), *,
    authoritative_metadata: bool = True,
    candidate_allowlist: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    if not isinstance(result, dict):
        raise KickoffError("Repository finder returned a non-object result.")
    selected = result.get("selected_repository")
    if not isinstance(selected, dict):
        raise KickoffError("Repository finder omitted selected_repository.")
    url = normalize_github_url(str(selected.get("url", "")))
    full_name = full_name_from_url(url)
    if str(selected.get("full_name", "")).casefold() != full_name.casefold():
        raise KickoffError("Finder repository name does not match its URL.")
    if full_name.casefold() in used_keys:
        raise KickoffError(f"Finder selected an already-used repository: {full_name}")
    if authoritative_metadata:
        if selected.get("license_spdx") not in ALLOWED_LICENSES:
            raise KickoffError(f"Finder selected a disallowed license: {selected.get('license_spdx')!r}")
        stars = selected.get("stars")
        if type(stars) is not int or stars <= MIN_STARS_EXCLUSIVE:
            raise KickoffError(f"Finder selection must have more than {MIN_STARS_EXCLUSIVE} stars: {stars!r}")
    if not COMMIT_RE.fullmatch(str(selected.get("commit_sha", ""))):
        raise KickoffError("Finder must provide a 40-character commit SHA.")
    if candidate_allowlist is not None:
        allowed_commit = candidate_allowlist.get(full_name.casefold())
        if allowed_commit is None:
            raise KickoffError(f"Finder selected a repository outside the deterministic preflight allowlist: {full_name}")
        if str(selected["commit_sha"]).casefold() != allowed_commit.casefold():
            raise KickoffError("Finder selected a commit other than the deterministic preflight commit.")
    if authoritative_metadata:
        parse_github_timestamp(selected.get("pushed_at"), "selected_repository.pushed_at")
    if not isinstance(selected.get("workflow_theme"), str) or not selected["workflow_theme"].strip():
        raise KickoffError("Finder workflow_theme must be a non-empty string.")
    approach = selected.get("opening_approach")
    if approach not in OPENING_APPROACHES:
        raise KickoffError(f"Finder returned an unsupported opening approach: {approach!r}")
    reuse_reason = selected.get("approach_reuse_reason")
    if reuse_reason is not None and (not isinstance(reuse_reason, str) or not reuse_reason.strip()):
        raise KickoffError("approach_reuse_reason must be null or a non-empty string.")
    if approach in recent_approaches and not reuse_reason:
        raise KickoffError(f"Opening approach {approach!r} was recently used and needs a repository-specific reuse reason.")
    for field in ("entry_points", "collaborators", "test_surfaces", "ci_surfaces", "documented_commands", "risks", "screening_limitations"):
        require_nonempty_string_list(selected.get(field), field)
    selected_evidence_commit = str(selected.get("evidence_commit_sha", selected["commit_sha"]))
    if not COMMIT_RE.fullmatch(selected_evidence_commit):
        raise KickoffError("selected_repository has an invalid evidence commit SHA.")
    validate_source_evidence(
        selected.get("source_evidence"), full_name, selected_evidence_commit,
        "source_evidence", minimum=3,
    )
    long_horizon = selected.get("long_horizon_fit")
    if not isinstance(long_horizon, Mapping) or long_horizon.get("verdict") != "strong_candidate":
        raise KickoffError("Selected repository must have a strong_candidate long-horizon verdict.")
    require_nonempty_string_list(long_horizon.get("boundary_chain"), "long_horizon_fit.boundary_chain")
    if len(long_horizon["boundary_chain"]) < 3:
        raise KickoffError("Long-horizon workflow must cross at least three named boundaries.")
    require_nonempty_string_list(long_horizon.get("maintainer_dimensions"), "long_horizon_fit.maintainer_dimensions")
    dimensions = set(long_horizon["maintainer_dimensions"])
    if len(dimensions) < 3 or not dimensions <= LONG_HORIZON_DIMENSIONS:
        raise KickoffError("Long-horizon fit needs at least three supported maintainer dimensions.")
    require_nonempty_string_list(
        long_horizon.get("test_and_fixture_evidence"), "long_horizon_fit.test_and_fixture_evidence",
    )
    require_nonempty_string_list(
        long_horizon.get("failure_recovery_complexity"), "long_horizon_fit.failure_recovery_complexity",
    )
    if not isinstance(long_horizon.get("local_feasibility"), str) or not long_horizon["local_feasibility"].strip():
        raise KickoffError("Long-horizon fit must explain local feasibility.")
    if not isinstance(long_horizon.get("disqualifiers"), list) or long_horizon["disqualifiers"]:
        raise KickoffError("Selected repository has unresolved long-horizon disqualifiers.")
    candidates = result.get("candidates_considered")
    if not isinstance(candidates, list):
        raise KickoffError("candidates_considered must be a list.")
    selected_is_listed = any(
        isinstance(candidate, Mapping)
        and str(candidate.get("full_name", "")).casefold() == full_name.casefold()
        for candidate in candidates
    )
    if not selected_is_listed and candidates:
        # The selected dossier is a strict superset of the shortlist record.
        # Some models return only the strongest alternative in the comparison
        # array. Reconstructing the redundant selected record is deterministic
        # and preserves the requirement that a real alternative was compared.
        source_evidence = selected.get("source_evidence")
        candidates.insert(0, {
            "full_name": full_name,
            "url": url,
            "stars": selected.get("stars"),
            "license_spdx": selected.get("license_spdx"),
            "commit_sha": selected.get("commit_sha"),
            "pushed_at": selected.get("pushed_at"),
            "workflow_theme": selected.get("workflow_theme"),
            "assessment": result.get("selection_reason"),
            "source_urls": [
                record.get("url") for record in source_evidence
                if isinstance(record, Mapping)
            ] if isinstance(source_evidence, list) else [],
        })
    if len(candidates) < 2:
        raise KickoffError("Finder must compare at least two candidates.")
    candidate_keys: set[str] = set()
    selected_candidate: Mapping[str, Any] | None = None
    for index, candidate in enumerate(candidates):
        candidate_name, _ = validate_candidate(
            candidate, used_keys, index, authoritative_metadata=authoritative_metadata,
            candidate_allowlist=candidate_allowlist,
        )
        key = candidate_name.casefold()
        if key in candidate_keys:
            raise KickoffError(f"Finder compared the same repository more than once: {candidate_name}")
        candidate_keys.add(key)
        if key == full_name.casefold():
            selected_candidate = candidate
    if selected_candidate is None:
        raise KickoffError("The selected repository must also appear in candidates_considered.")
    # Cross-check factual identity/eligibility data. ``workflow_theme`` is
    # intentionally excluded: the shortlist carries a concise comparison
    # summary while the selected dossier may expand the same theme into a
    # writer-ready investigation focus.
    compared_fields = ("stars", "license_spdx", "commit_sha", "pushed_at") if authoritative_metadata else ("commit_sha",)
    for field in compared_fields:
        if selected.get(field) != selected_candidate.get(field):
            raise KickoffError(f"Selected repository field {field!r} disagrees with candidates_considered.")
    for field in ("selection_reason", "strongest_alternative"):
        if not isinstance(result.get(field), str) or not result[field].strip():
            raise KickoffError(f"{field} must be a non-empty string.")
    require_nonempty_string_list(result.get("uncertainties"), "uncertainties")
    selected["url"] = url
    selected["full_name"] = full_name
    return result


def github_headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "taiga-repository-kickoff/1",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def fetch_json(url: str) -> dict[str, Any]:
    request = Request(url, headers=github_headers())
    for attempt in range(3):
        try:
            with urlopen(request, timeout=30) as response:
                payload = json.loads(response.read().decode("utf-8"))
            break
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            raise KickoffError(f"GitHub verification failed ({exc.code}): {detail}") from exc
        except (URLError, TimeoutError, OSError, HTTPException) as exc:
            if attempt == 2:
                raise KickoffError(
                    f"Cannot reach GitHub for deterministic verification after 3 attempts: {exc}"
                ) from exc
            time.sleep(0.5 * (attempt + 1))
        except json.JSONDecodeError as exc:
            raise KickoffError("GitHub verification returned invalid JSON.") from exc
    if not isinstance(payload, dict):
        raise KickoffError("GitHub verification returned an unexpected payload.")
    return payload


def git_remote_head(full_name: str, default_branch: str) -> str:
    """Resolve a public branch head without consuming GitHub REST core quota."""
    if not GITHUB_NAME_RE.fullmatch(full_name):
        raise KickoffError(f"Invalid GitHub repository for remote-head lookup: {full_name!r}")
    if (
        not isinstance(default_branch, str)
        or not default_branch
        or default_branch.startswith("-")
        or any(character.isspace() or ord(character) < 32 for character in default_branch)
    ):
        raise KickoffError(f"Invalid default branch for remote-head lookup: {default_branch!r}")
    reference = f"refs/heads/{default_branch}"
    environment = os.environ.copy()
    environment["GIT_TERMINAL_PROMPT"] = "0"
    try:
        completed = subprocess.run(
            ["git", "ls-remote", "--exit-code", f"https://github.com/{full_name}.git", reference],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise KickoffError(f"Cannot resolve the GitHub branch head for {full_name}.") from exc
    if completed.returncode != 0:
        raise KickoffError(f"GitHub branch-head lookup failed for {full_name}.")
    lines = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
    matches = [
        line.split("\t", 1)[0]
        for line in lines
        if "\t" in line and line.split("\t", 1)[1] == reference
    ]
    if len(matches) != 1 or not COMMIT_RE.fullmatch(matches[0]):
        raise KickoffError(f"GitHub did not return one valid branch head for {full_name}.")
    return matches[0].lower()


def prior_candidate_names(output_directory: Path = DEFAULT_OUTPUT_DIRECTORY) -> list[str]:
    """Recover recent model suggestions as untrusted seeds for cheaper GitHub preflight."""
    names: list[str] = []
    seen: set[str] = set()
    paths = sorted(output_directory.glob("*/repository_finder_response.json"), reverse=True)
    for path in paths:
        try:
            receipt = read_json(path)
            payload = json.loads(str(receipt.get("output_text", "")))
        except (KickoffError, json.JSONDecodeError, AttributeError):
            continue
        selected = payload.get("selected_repository") if isinstance(payload, Mapping) else None
        candidates = payload.get("candidates_considered") if isinstance(payload, Mapping) else None
        raw_names = [selected.get("full_name")] if isinstance(selected, Mapping) else []
        if isinstance(candidates, list):
            raw_names.extend(
                candidate.get("full_name") for candidate in candidates if isinstance(candidate, Mapping)
            )
        for raw_name in raw_names:
            name = str(raw_name or "")
            key = name.casefold()
            if GITHUB_NAME_RE.fullmatch(name) and key not in seen:
                seen.add(key)
                names.append(name)
    return names


def repository_structure_summary(root: Path, tracked_file_count: int) -> dict[str, Any]:
    """Apply a cheap, deterministic floor before claiming long-horizon suitability."""
    python_files = [path for path in root.rglob("*.py") if path.is_file()]
    test_parts = {"test", "tests", "testing", "testdata"}
    test_files = [
        path for path in python_files
        if path.name.startswith("test_")
        or any(part.casefold() in test_parts for part in path.relative_to(root).parts[:-1])
    ]
    test_set = set(test_files)
    source_files = [path for path in python_files if path not in test_set]
    workflow_root = root / ".github" / "workflows"
    ci_files = [
        path for path in workflow_root.glob("*")
        if path.is_file() and path.suffix.casefold() in {".yml", ".yaml"}
    ] if workflow_root.is_dir() else []
    packaging_files = [
        name for name in ("pyproject.toml", "setup.cfg", "setup.py")
        if (root / name).is_file()
    ]
    failures: list[str] = []
    checks = (
        (tracked_file_count >= MIN_TRACKED_FILES, f"tracked_files<{MIN_TRACKED_FILES}"),
        (len(source_files) >= MIN_SOURCE_PYTHON_FILES, f"source_python_files<{MIN_SOURCE_PYTHON_FILES}"),
        (len(test_files) >= MIN_TEST_PYTHON_FILES, f"test_python_files<{MIN_TEST_PYTHON_FILES}"),
        (len(python_files) >= MIN_TOTAL_PYTHON_FILES, f"total_python_files<{MIN_TOTAL_PYTHON_FILES}"),
        (bool(ci_files), "no_github_actions_workflow"),
        (bool(packaging_files), "no_python_packaging_file"),
    )
    failures.extend(reason for passed, reason in checks if not passed)
    return {
        "tracked_file_count": tracked_file_count,
        "source_python_files": len(source_files),
        "test_python_files": len(test_files),
        "total_python_files": len(python_files),
        "ci_workflow_files": len(ci_files),
        "packaging_files": packaging_files,
        "status": "passed" if not failures else "failed",
        "failures": failures,
    }


def preflight_candidate_archive(item: Mapping[str, Any]) -> dict[str, Any]:
    """Inspect one candidate in isolation; treat content findings as advisory."""
    full_name = str(item["full_name"])
    default_branch = str(item["default_branch"])
    search_url = str(item["_preflight_search_url"])
    try:
        commit_sha = git_remote_head(full_name, default_branch)
    except KickoffError as exc:
        return {
            "eligible": None,
            "rejected": {"full_name": full_name, "reason": "github_preflight_error", "detail": str(exc)[:300]},
        }
    try:
        with tempfile.TemporaryDirectory(prefix="repository-candidate-preflight-") as temporary:
            temporary_root = Path(temporary)
            archive = download_github_archive(
                full_name, commit_sha, temporary_root / "source.zip",
            )
            extracted_root, archive_review = safely_extract_archive(
                temporary_root / "source.zip", temporary_root / "extracted",
            )
            structure = repository_structure_summary(
                extracted_root, int(archive_review["file_count"]),
            )
            if structure["status"] != "passed":
                return {
                    "eligible": None,
                    "rejected": {
                        "full_name": full_name,
                        "reason": "long_horizon_structure_gate",
                        "structure": structure,
                    },
                }
            safety_report = scan_tree(extracted_root)
    except (ArchivePreparationError, OSError) as exc:
        return {
            "eligible": None,
            "rejected": {
                "full_name": full_name,
                "reason": "archive_or_preparation_error",
                "detail": type(exc).__name__,
            },
        }
    safety_counts = safety_report.get("counts") if isinstance(safety_report, Mapping) else {}
    license_info = item.get("license") if isinstance(item.get("license"), Mapping) else {}
    eligible = {
        "full_name": full_name,
        "url": normalize_github_url(str(item.get("html_url") or f"https://github.com/{full_name}")),
        "github_repository_id": item["id"],
        "github_node_id": item["node_id"],
        "stars": int(item["stargazers_count"]),
        "license_spdx": str(license_info.get("spdx_id") or ""),
        "pushed_at": str(item.get("pushed_at") or ""),
        "description": str(item.get("description") or ""),
        "default_branch": default_branch,
        "commit_sha": commit_sha,
        "archive_size_bytes": int(archive["archive_size_bytes"]),
        "tracked_file_count": int(archive_review["file_count"]),
        "structure": structure,
        "content_safety_advisory": {
            "status": str(safety_report.get("status") or "unknown"),
            "counts": dict(safety_counts) if isinstance(safety_counts, Mapping) else {},
            "eligibility_effect": "none_during_candidate_discovery",
        },
        "workspace_state": "not_prepared",
        "preflight": "passed_archive_extraction_structure_and_advisory_content_scan",
        "metadata_source": search_url,
        "commit_source": f"git ls-remote https://github.com/{full_name}.git refs/heads/{default_branch}",
    }
    return {"eligible": eligible, "rejected": None}


def discover_preflight_candidates(
    used_keys: set[str], used_repository_ids: set[int], *,
    target: int = PREFLIGHT_TARGET_CANDIDATES,
    max_inspections: int = PREFLIGHT_MAX_INSPECTIONS,
    progress_callback: Callable[[Mapping[str, Any]], None] | None = None,
    search_queries: Sequence[str] = PREFLIGHT_SEARCH_QUERIES,
) -> dict[str, Any]:
    """Build a current shortlist that has already passed local archive preparation."""
    if target < 2 or max_inspections < target:
        raise KickoffError("Candidate preflight requires at least two targets and enough inspections.")
    if not search_queries:
        raise KickoffError("Candidate preflight requires at least one GitHub search query.")
    search_urls: list[str] = []
    items: list[dict[str, Any]] = []
    returned_names: set[str] = set()
    for raw_query in search_queries:
        search_url = (
            "https://api.github.com/search/repositories"
            f"?q={quote_plus(raw_query)}&sort=updated&order=desc&per_page=100"
        )
        search_urls.append(search_url)
        search = fetch_json(search_url)
        search_items = search.get("items")
        if not isinstance(search_items, list):
            raise KickoffError("GitHub repository search returned no candidate list.")
        for raw_item in search_items:
            if not isinstance(raw_item, Mapping):
                continue
            full_name = str(raw_item.get("full_name") or "")
            key = full_name.casefold()
            if key in returned_names:
                continue
            returned_names.add(key)
            items.append({**dict(raw_item), "_preflight_search_url": search_url})
    seed_names = prior_candidate_names()[:PREFLIGHT_SEED_LIMIT]
    seed_rank = {name.casefold(): index for index, name in enumerate(seed_names)}
    items = sorted(
        items,
        key=lambda item: (
            seed_rank.get(str(item.get("full_name", "")).casefold(), len(seed_rank)),
            int(item.get("size") or 2**63 - 1),
            str(item.get("full_name", "")).casefold(),
        ) if isinstance(item, Mapping) else (len(seed_rank) + 1, 2**63 - 1, ""),
    )
    candidate_items: list[Mapping[str, Any]] = []
    for item in items:
        if len(candidate_items) >= max_inspections:
            break
        if not isinstance(item, Mapping):
            continue
        full_name = str(item.get("full_name") or "")
        repository_id = item.get("id")
        node_id = item.get("node_id")
        license_info = item.get("license") if isinstance(item.get("license"), Mapping) else {}
        license_spdx = str(license_info.get("spdx_id") or "")
        if (
            not GITHUB_NAME_RE.fullmatch(full_name)
            or full_name.casefold() in used_keys
            or type(repository_id) is not int
            or repository_id in used_repository_ids
            or not isinstance(node_id, str)
            or not node_id
            or item.get("fork") is True
            or item.get("archived") is True
            or str(item.get("language") or "").casefold() != "python"
            or int(item.get("stargazers_count") or -1) <= MIN_STARS_EXCLUSIVE
            or license_spdx not in ALLOWED_LICENSES
        ):
            continue
        domain_text = " ".join([
            full_name,
            str(item.get("description") or ""),
            *[str(topic) for topic in item.get("topics", []) if isinstance(topic, str)],
        ]).casefold()
        if any(term in domain_text for term in EXCLUDED_DOMAIN_TERMS):
            continue
        default_branch = str(item.get("default_branch") or "")
        if not default_branch:
            continue
        candidate_items.append(item)
    eligible: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    inspected = 0
    batch_size = 4
    for start in range(0, len(candidate_items), batch_size):
        batch = candidate_items[start:start + batch_size]
        with ThreadPoolExecutor(max_workers=len(batch), thread_name_prefix="repository-preflight") as executor:
            outcomes = list(executor.map(preflight_candidate_archive, batch))
        inspected += len(batch)
        for outcome in outcomes:
            if isinstance(outcome.get("eligible"), Mapping):
                eligible.append(dict(outcome["eligible"]))
            elif isinstance(outcome.get("rejected"), Mapping):
                rejected.append(dict(outcome["rejected"]))
        progress = {
            "status": "running" if len(eligible) < target else "enough_candidates",
            "search_urls": search_urls,
            "inspected_count": inspected,
            "eligible_candidates": eligible,
            "rejected_candidates": rejected,
        }
        if progress_callback is not None:
            try:
                progress_callback(progress)
            except OSError:
                # Progress is diagnostic only and must never decide eligibility.
                pass
        if len(eligible) >= target:
            break
    if len(eligible) < 2:
        raise KickoffError(
            f"Deterministic archive and structure preflight found only {len(eligible)} eligible candidates "
            f"after inspecting {inspected}; at least two are required."
        )
    return {
        "searched_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "search_urls": search_urls,
        "scheduling_note": "GitHub size metadata affected inspection order only; it was not an eligibility rule.",
        "inspected_count": inspected,
        "eligible_candidates": eligible,
        "rejected_candidates": rejected,
    }


def preflight_repository_snapshot(record: Mapping[str, Any]) -> dict[str, Any]:
    """Revalidate a search/archive preflight record and refresh only its branch head."""
    full_name = str(record.get("full_name") or "")
    url = normalize_github_url(str(record.get("url") or ""))
    if full_name.casefold() != full_name_from_url(url).casefold():
        raise KickoffError("Preflight repository name does not match its URL.")
    stars = record.get("stars")
    if type(stars) is not int or stars <= MIN_STARS_EXCLUSIVE:
        raise KickoffError(f"Preflight stars for {full_name} must be more than {MIN_STARS_EXCLUSIVE}.")
    license_spdx = str(record.get("license_spdx") or "")
    if license_spdx not in ALLOWED_LICENSES:
        raise KickoffError(f"Preflight license for {full_name} is not allowed: {license_spdx!r}")
    repository_id = record.get("github_repository_id")
    node_id = record.get("github_node_id")
    if type(repository_id) is not int or repository_id <= 0 or not isinstance(node_id, str) or not node_id:
        raise KickoffError(f"Preflight record has no stable GitHub identity for {full_name}.")
    default_branch = str(record.get("default_branch") or "")
    commit_sha = git_remote_head(full_name, default_branch)
    pushed_at = str(record.get("pushed_at") or "")
    activity = activity_classification(pushed_at)
    return {
        "url": url,
        "full_name": full_name,
        "description": str(record.get("description") or ""),
        "default_branch": default_branch,
        "commit_sha": commit_sha,
        "stars": stars,
        "license_spdx": license_spdx,
        "pushed_at": pushed_at,
        "github_repository_id": repository_id,
        "github_node_id": node_id,
        **activity,
        "metadata_source": str(record.get("metadata_source") or "GitHub repository search"),
        "commit_source": f"git ls-remote https://github.com/{full_name}.git refs/heads/{default_branch}",
    }


def github_repository_snapshot(full_name: str) -> dict[str, Any]:
    """Fetch and validate authoritative metadata for one shortlisted repository."""
    metadata = fetch_json(f"https://api.github.com/repos/{full_name}")
    if metadata.get("private") or metadata.get("archived") or metadata.get("fork"):
        raise KickoffError(f"Shortlisted repository {full_name} is private, archived, or a fork.")
    if str(metadata.get("language") or "").casefold() != "python":
        raise KickoffError(
            f"Shortlisted repository {full_name} is not Python-focused according to GitHub: "
            f"{metadata.get('language')!r}"
        )
    stars = int(metadata.get("stargazers_count", -1))
    license_info = metadata.get("license") if isinstance(metadata.get("license"), Mapping) else {}
    license_spdx = str(license_info.get("spdx_id") or "")
    if stars <= MIN_STARS_EXCLUSIVE:
        raise KickoffError(f"Current GitHub stars for {full_name} must be more than {MIN_STARS_EXCLUSIVE}: {stars}")
    if license_spdx not in ALLOWED_LICENSES:
        raise KickoffError(f"Current GitHub license for {full_name} is not allowed: {license_spdx!r}")
    topics = metadata.get("topics") if isinstance(metadata.get("topics"), list) else []
    domain_text = " ".join([
        str(metadata.get("full_name") or full_name),
        str(metadata.get("description") or ""),
        *[str(topic) for topic in topics],
    ]).casefold()
    matched_terms = sorted(term for term in EXCLUDED_DOMAIN_TERMS if term in domain_text)
    if matched_terms:
        raise KickoffError(f"Shortlisted repository {full_name} matches excluded domain terms: {', '.join(matched_terms)}")
    default_branch = str(metadata.get("default_branch") or "")
    if not default_branch:
        raise KickoffError(f"GitHub did not return a default branch for {full_name}.")
    commit = fetch_json(f"https://api.github.com/repos/{full_name}/commits/{default_branch}")
    commit_sha = str(commit.get("sha") or "")
    if not COMMIT_RE.fullmatch(commit_sha):
        raise KickoffError(f"GitHub did not return a valid default-branch commit SHA for {full_name}.")
    repository_id = metadata.get("id")
    node_id = metadata.get("node_id")
    if type(repository_id) is not int or repository_id <= 0 or not isinstance(node_id, str) or not node_id:
        raise KickoffError(f"GitHub did not return stable repository identity for {full_name}.")
    pushed_at = str(metadata.get("pushed_at") or "")
    activity = activity_classification(pushed_at)
    canonical_name = str(metadata.get("full_name") or full_name)
    canonical_url = normalize_github_url(str(metadata.get("html_url") or f"https://github.com/{canonical_name}"))
    return {
        "url": canonical_url,
        "full_name": canonical_name,
        "description": str(metadata.get("description") or ""),
        "default_branch": default_branch,
        "commit_sha": commit_sha,
        "stars": stars,
        "license_spdx": license_spdx,
        "pushed_at": pushed_at,
        "github_repository_id": repository_id,
        "github_node_id": node_id,
        **activity,
        "metadata_source": f"https://api.github.com/repos/{full_name}",
        "commit_source": f"https://api.github.com/repos/{full_name}/commits/{default_branch}",
    }


def verify_github_selection(
    result: dict[str, Any], used_repository_ids: set[int] | None = None,
    preflight_candidates: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Verify every compared candidate and replace model-reported metadata."""
    selected = result["selected_repository"]
    selected_evidence_commit_sha = str(selected["commit_sha"])
    selected_key = str(selected["full_name"]).casefold()
    used_ids = used_repository_ids or set()
    verified_candidates: list[dict[str, Any]] = []
    seen_ids: set[int] = set()
    selected_snapshot: dict[str, Any] | None = None
    for candidate in result["candidates_considered"]:
        original_name = str(candidate["full_name"])
        is_selected = original_name.casefold() == selected_key
        evidence_commit_sha = str(candidate["commit_sha"])
        if preflight_candidates is None:
            snapshot = github_repository_snapshot(original_name)
        else:
            preflight = preflight_candidates.get(original_name.casefold())
            if preflight is None:
                raise KickoffError(f"Shortlisted repository is missing from preflight: {original_name}")
            snapshot = preflight_repository_snapshot(preflight)
        repository_id = int(snapshot["github_repository_id"])
        if repository_id in used_ids:
            raise KickoffError(f"Shortlisted repository was already used under this or an earlier name: {original_name}")
        if repository_id in seen_ids:
            raise KickoffError(f"Shortlist contains duplicate GitHub repository identity: {repository_id}")
        seen_ids.add(repository_id)
        candidate.update(snapshot)
        candidate["evidence_commit_sha"] = evidence_commit_sha
        verified_candidates.append({**dict(snapshot), "evidence_commit_sha": evidence_commit_sha})
        if is_selected:
            selected_snapshot = snapshot
    if selected_snapshot is None:
        raise KickoffError("Selected repository was not found in the verified shortlist.")
    selected.update(selected_snapshot)
    selected["evidence_commit_sha"] = selected_evidence_commit_sha
    return {
        "verified_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "source": selected_snapshot["metadata_source"],
        "commit_source": selected_snapshot["commit_source"],
        "selected_repository": selected,
        "verified_candidates": verified_candidates,
    }


def validate_preparation_result(
    preparation: Any,
    selected: Mapping[str, Any],
    archive_download: Mapping[str, Any],
    run_directory: Path,
) -> dict[str, Any]:
    """Verify the safety boundary before exposing an upload-ready archive."""
    if not isinstance(preparation, Mapping) or preparation.get("status") not in {"clean", "sanitized_clean"}:
        status = preparation.get("status") if isinstance(preparation, Mapping) else "invalid_result"
        raise KickoffError(f"Repository did not pass the pre-upload content-safety gate: {status}.")
    identity = preparation.get("identity")
    if not isinstance(identity, Mapping):
        raise KickoffError("Repository preparation omitted its identity record.")
    expected_workspace = "clean_upstream" if preparation["status"] == "clean" else "sanitized_derivative"
    expected = {
        "upstream_commit_sha": str(selected["commit_sha"]).lower(),
        "original_archive_sha256": str(archive_download["original_archive_sha256"]).lower(),
        "workspace_state": expected_workspace,
        "safety_status": preparation["status"],
    }
    for field, value in expected.items():
        if str(identity.get(field, "")).lower() != value.lower():
            raise KickoffError(f"Prepared repository identity has an inconsistent {field}.")
    for field in ("prepared_archive_sha256", "sanitization_manifest_sha256"):
        if not re.fullmatch(r"[0-9a-fA-F]{64}", str(identity.get(field, ""))):
            raise KickoffError(f"Prepared repository identity has an invalid {field}.")

    archive_path = run_directory / "upload_ready_repository.zip"
    report_path = run_directory / "content_safety_report.json"
    manifest_path = run_directory / "sanitization_manifest.json"
    if not all(path.is_file() for path in (archive_path, report_path, manifest_path)):
        raise KickoffError("Repository preparation did not create every required safety artifact.")
    if sha256_file(archive_path) != str(identity["prepared_archive_sha256"]).lower():
        raise KickoffError("Upload-ready archive hash does not match its prepared identity.")
    if sha256_file(manifest_path) != str(identity["sanitization_manifest_sha256"]).lower():
        raise KickoffError("Sanitization manifest hash does not match its prepared identity.")
    manifest = read_json(manifest_path)
    if not isinstance(manifest, Mapping) or manifest.get("status") != preparation["status"]:
        raise KickoffError("Sanitization manifest status disagrees with repository preparation.")
    return dict(identity)


def render_engineering_task(task: Mapping[str, Any]) -> str:
    """Render the task-facing brief from validated, non-meta task fields."""
    lines = ["# Goal", "", str(task["goal"]).strip(), "", "# Context", "", str(task["context"]).strip(), ""]
    for heading, field in (
        ("# Scope", "scope"),
        ("# Expected Outcome", "expected_outcome"),
        ("# Guardrails", "guardrails"),
    ):
        lines.extend([heading, ""])
        lines.extend(f"- {str(item).strip()}" for item in task[field])
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def writer_repository_dossier(selected: Mapping[str, Any]) -> dict[str, Any]:
    """Expose engineering evidence while keeping sourcing and review records local."""
    dossier = {
        field: selected[field]
        for field in WRITER_REPOSITORY_FIELDS
        if field in selected
    }
    if "risks" in dossier:
        dossier["risks"] = [
            risk for risk in dossier["risks"]
            if not any(pattern.search(risk) for pattern, _label in TASK_SOURCE_CONTEXT_PATTERNS)
        ]
    return dossier


def validate_writer_result(result: Any, selected: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(result, dict):
        raise KickoffError("Engineering task writer returned a non-object result.")
    if normalize_github_url(str(result.get("repository_url", ""))) != selected["url"]:
        raise KickoffError("Engineering task writer changed the selected repository.")
    if str(result.get("commit_sha", "")).casefold() != str(selected["commit_sha"]).casefold():
        raise KickoffError("Engineering task writer changed the pinned commit.")
    if result.get("request_type") != "system_level_investigation":
        raise KickoffError("Engineering task request type must be system_level_investigation.")
    task = result.get("task")
    if not isinstance(task, Mapping):
        raise KickoffError("Engineering task must be an object.")
    for field in ("goal", "context"):
        value = task.get(field)
        if not isinstance(value, str) or not value.strip():
            raise KickoffError(f"Engineering task {field} must be a non-empty string.")
    minimum_items = {"scope": 3, "expected_outcome": 2, "guardrails": 2}
    for field in TASK_LIST_FIELDS:
        require_nonempty_string_list(task.get(field), f"task.{field}")
        if len(task[field]) < minimum_items[field]:
            raise KickoffError(
                f"Engineering task {field} must contain at least {minimum_items[field]} focused items."
            )
    task_values = [task["goal"], task["context"]]
    task_values.extend(item for field in TASK_LIST_FIELDS for item in task[field])
    if any(re.search(r"(?m)^\s*#", str(value)) for value in task_values):
        raise KickoffError("Engineering task fields must not contain Markdown section headings.")
    if any(
        re.match(r"^\s*(?:[-*+]|\d+[.)])\s+", item)
        for field in TASK_LIST_FIELDS for item in task[field]
    ):
        raise KickoffError("Engineering task list items must not include their own bullet markers.")
    prompt = render_engineering_task(task)
    headings = re.findall(r"(?m)^# .+$", prompt)
    if headings != list(TASK_SECTION_HEADINGS):
        raise KickoffError("Engineering task must contain Goal, Context, Scope, Expected Outcome, and Guardrails in order.")
    words = len(prompt.split())
    if not 250 <= words <= 750:
        raise KickoffError(f"Engineering task must be substantive but bounded (250..750 words); received {words}.")
    if selected["url"] not in prompt or selected["commit_sha"] not in prompt:
        raise KickoffError("Engineering task must include the repository URL and pinned commit.")
    lowered = prompt.casefold()
    if "read-only" not in lowered or not any(phrase in lowered for phrase in ("tree unchanged", "leave the tree unchanged")):
        raise KickoffError("Engineering task must explicitly require a read-only, tree-unchanged investigation.")
    for pattern, label in (*TASK_META_LANGUAGE_PATTERNS, *TASK_SOURCE_CONTEXT_PATTERNS):
        if pattern.search(prompt):
            raise KickoffError(f"Engineering task contains prohibited {label} language.")
    validate_source_evidence(
        result.get("citations"), str(selected["full_name"]), str(selected["commit_sha"]), "citations", minimum=3,
    )
    prepared = selected.get("prepared_repository")
    if isinstance(prepared, Mapping) and prepared.get("workspace_state") == "sanitized_derivative":
        changed_paths = {
            str(path).replace("\\", "/") for path in selected.get("sanitized_paths", [])
            if isinstance(path, str)
        }
        for citation in result.get("citations", []):
            parts = [part for part in urlparse(str(citation["url"])).path.split("/") if part]
            cited_path = "/".join(parts[4:])
            if cited_path in changed_paths:
                raise KickoffError(f"Engineering task cites a file changed by safety sanitization: {cited_path}")
    require_nonempty_string_list(result.get("grounding_notes"), "grounding_notes")
    validated = dict(result)
    validated["task"] = dict(task)
    validated["turn_one_prompt"] = prompt
    return validated


def usage_dict(response: Any) -> dict[str, int]:
    usage = getattr(response, "usage", None)
    input_details = getattr(usage, "input_tokens_details", None)
    output_details = getattr(usage, "output_tokens_details", None)
    return {
        "input_tokens": int(getattr(usage, "input_tokens", 0) or 0),
        "output_tokens": int(getattr(usage, "output_tokens", 0) or 0),
        "total_tokens": int(getattr(usage, "total_tokens", 0) or 0),
        "cached_input_tokens": int(getattr(input_details, "cached_tokens", 0) or 0),
        "reasoning_tokens": int(getattr(output_details, "reasoning_tokens", 0) or 0),
    }


def response_web_sources(response: Any) -> list[str]:
    """Return the source URLs included on Responses API web-search actions."""
    urls: set[str] = set()
    for item in getattr(response, "output", None) or []:
        item_type = item.get("type") if isinstance(item, Mapping) else getattr(item, "type", None)
        if item_type != "web_search_call":
            continue
        action = item.get("action") if isinstance(item, Mapping) else getattr(item, "action", None)
        sources = action.get("sources") if isinstance(action, Mapping) else getattr(action, "sources", None)
        for source in sources or []:
            url = source.get("url") if isinstance(source, Mapping) else getattr(source, "url", None)
            if isinstance(url, str) and url.strip():
                urls.add(url.strip())
        action_url = action.get("url") if isinstance(action, Mapping) else getattr(action, "url", None)
        if isinstance(action_url, str) and action_url.strip():
            urls.add(action_url.strip())
    return sorted(urls)


def parse_structured_output(
    raw: str, schema_name: str, *, usage: Mapping[str, Any] | None = None,
    max_output_tokens: int | None = None, response_status: str | None = None,
    incomplete_reason: str | None = None,
) -> dict[str, Any]:
    output_tokens = usage.get("output_tokens") if isinstance(usage, Mapping) else None
    if incomplete_reason == "max_output_tokens" or (
        isinstance(output_tokens, int) and max_output_tokens is not None
        and output_tokens >= max_output_tokens
    ):
        reasoning_tokens = usage.get("reasoning_tokens", 0) if isinstance(usage, Mapping) else 0
        raise KickoffError(
            f"{schema_name} exhausted max_output_tokens before completing its JSON "
            f"({output_tokens if output_tokens is not None else 'unknown'}/{max_output_tokens or 'unknown'} "
            f"output tokens; {reasoning_tokens} reasoning tokens). "
            "Retry with --max-output-tokens 30000 or higher, or lower this stage's reasoning effort. "
            "The partial response is saved in the local stage receipt."
        )
    if response_status and response_status != "completed":
        raise KickoffError(
            f"{schema_name} response did not complete (status: {response_status}; "
            f"reason: {incomplete_reason or 'unknown'}). Inspect the local stage receipt."
        )
    if not raw.strip():
        raise KickoffError(
            f"{schema_name} returned no visible JSON. The response likely exhausted "
            "max_output_tokens during reasoning; use lower reasoning effort or a larger output budget."
        )
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise KickoffError(
            f"{schema_name} returned invalid JSON at line {exc.lineno}, column {exc.colno}. "
            "Inspect the local stage receipt for the response and token usage."
        ) from exc
    if not isinstance(parsed, dict):
        raise KickoffError(f"{schema_name} returned a non-object JSON value.")
    return parsed


def write_stage_receipt(
    run_directory: Path, stage: str, *, model: str, reasoning_effort: str,
    response_id: str, usage: Mapping[str, Any], web_sources: Sequence[str], output_text: str,
    max_output_tokens: int, response_status: str | None = None,
    incomplete_reason: str | None = None,
) -> None:
    write_json(run_directory / f"{stage}_response.json", {
        "stage": stage,
        "model": model,
        "reasoning_effort": reasoning_effort,
        "response_id": response_id,
        "usage": dict(usage),
        "response_status": response_status,
        "incomplete_reason": incomplete_reason,
        "max_output_tokens": max_output_tokens,
        "web_sources": list(web_sources),
        "output_text": output_text,
    })


def call_structured_stage(
    *, model: str, reasoning_effort: str, instructions: str, payload: Mapping[str, Any],
    schema: dict[str, Any], schema_name: str, max_output_tokens: int,
) -> tuple[str, dict[str, Any], str, list[str], dict[str, str | None]]:
    if not os.getenv("OPENAI_API_KEY"):
        raise KickoffError("OPENAI_API_KEY is not configured. Add it to repository_kickoff/.env or the process environment.")
    try:
        from openai import APIConnectionError, APIStatusError, APITimeoutError, OpenAI
    except ImportError as exc:
        raise KickoffError("The OpenAI SDK is not installed. Run: .\\.venv\\Scripts\\python.exe -m pip install -r .\\repository_kickoff\\requirements.txt") from exc
    client = OpenAI()
    try:
        response = client.responses.create(
            model=model,
            reasoning={"effort": reasoning_effort},
            instructions=instructions,
            input=[{"role": "user", "content": json.dumps(payload, ensure_ascii=False, indent=2)}],
            tools=[{"type": "web_search", "search_context_size": "high"}],
            tool_choice="auto",
            include=["web_search_call.action.sources"],
            text={
                "verbosity": "low",
                "format": {"type": "json_schema", "name": schema_name, "strict": True, "schema": schema},
            },
            max_output_tokens=max_output_tokens,
            prompt_cache_key=f"repository-kickoff-{schema_name}-v2",
            store=False,
        )
    except APITimeoutError as exc:
        raise KickoffError("OpenAI request timed out. No later stage was run.") from exc
    except APIConnectionError as exc:
        raise KickoffError("OpenAI connection failed. Check the network and proxy configuration.") from exc
    except APIStatusError as exc:
        request_id = getattr(exc, "request_id", None)
        suffix = f" Request ID: {request_id}." if request_id else ""
        raise KickoffError(f"OpenAI API returned HTTP {exc.status_code}: {exc.message}.{suffix}") from exc
    raw = str(getattr(response, "output_text", "") or "")
    details = getattr(response, "incomplete_details", None)
    reason = details.get("reason") if isinstance(details, Mapping) else getattr(details, "reason", None)
    return (
        raw, usage_dict(response), str(getattr(response, "id", "") or ""),
        response_web_sources(response),
        {"response_status": getattr(response, "status", None), "incomplete_reason": reason},
    )


def append_ledger(
    ledger: dict[str, Any], selected: Mapping[str, Any], output: Mapping[str, Any],
    run_id: str, path: Path = LEDGER_PATH, *, status: str, finding_count: int,
    handoff_path: Path | None = None,
) -> None:
    if status not in REPOSITORY_STATUSES:
        raise KickoffError(f"Invalid repository registry status: {status!r}")
    repositories = ledger["repositories"]
    key = str(selected["full_name"]).casefold()
    if any(str(entry.get("full_name", "")).casefold() == key for entry in repositories):
        raise KickoffError(f"Refusing to append duplicate repository: {selected['full_name']}")
    repository_id = selected.get("github_repository_id")
    if type(repository_id) is not int or repository_id <= 0:
        raise KickoffError("Refusing to append a repository without verified GitHub identity.")
    if any(entry.get("github_repository_id") == repository_id for entry in repositories):
        raise KickoffError(f"Refusing to append previously used GitHub repository identity: {repository_id}")
    entry = {
        "full_name": selected["full_name"],
        "url": selected["url"],
        "status": status,
        "source_scan_status": selected["source_scan_status"],
        "risk_scan_status": selected["risk_scan_status"],
        "risk_finding_count": finding_count,
        "risk_report": f"outputs/{run_id}/content_safety_findings.md",
        "github_repository_id": repository_id,
        "github_node_id": selected["github_node_id"],
        "commit_sha": selected["commit_sha"],
        "opening_approach": selected["opening_approach"],
        "approach_reuse_reason": selected.get("approach_reuse_reason"),
        "workflow_theme": selected["workflow_theme"],
        "pushed_at": selected["pushed_at"],
        "activity_status": selected["activity_status"],
        "recommended_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "run_id": run_id,
        "turn_one_request_type": output["request_type"],
    }
    if isinstance(selected.get("prepared_repository"), Mapping):
        entry["prepared_repository"] = dict(selected["prepared_repository"])
    if handoff_path is not None:
        try:
            entry["handoff"] = handoff_path.resolve().relative_to(TOOL_DIRECTORY).as_posix()
        except ValueError:
            entry["handoff"] = str(handoff_path.resolve())
    repositories.append(entry)
    write_json(path, ledger)


def render_markdown(
    finder: Mapping[str, Any], writer: Mapping[str, Any], verification: Mapping[str, Any],
    run_id: str, usage: Mapping[str, Mapping[str, int]], models: Mapping[str, str],
) -> str:
    selected = finder["selected_repository"]
    prepared = selected.get("prepared_repository")
    archive_size = selected["archive_size_bytes"]
    lines = [
        f"# Repository kickoff: {selected['full_name']}", "",
        "## Selected repository", "",
        f"- Repository: [{selected['full_name']}]({selected['url']})",
        f"- Pinned commit: `{selected['commit_sha']}`",
        f"- Default branch: `{selected['default_branch']}`",
        f"- License: `{selected['license_spdx']}`",
        f"- Stars: `{selected['stars']}`",
        f"- Downloaded source archive size: `{archive_size:,} bytes` (strictly below `{MAX_ARCHIVE_BYTES:,}`)",
        f"- Source scan status: `{selected['source_scan_status']}`",
        f"- Risk scan status: `{selected['risk_scan_status']}`",
        f"- Registry status: `{selected['review_status']}`",
        "- Potential PII/key file report: [content_safety_findings.md](content_safety_findings.md)",
        f"- Last push: `{selected['pushed_at']}`",
        f"- Activity classification: `{selected['activity_status']}` ({selected['activity_age_days']} days)",
        f"- GitHub repository ID: `{selected['github_repository_id']}`",
        "", "## Engineering task", "", str(writer["turn_one_prompt"]), "",
        "## Source evidence", "",
    ]
    if isinstance(prepared, Mapping):
        lines.insert(11, f"- Upload-ready archive SHA-256: `{prepared['prepared_archive_sha256']}`")
    else:
        lines.insert(11, "- Upload-ready archive: **not created; manual review required before upload**")
    evidence_commit = selected.get("evidence_commit_sha", selected["commit_sha"])
    if evidence_commit != selected["commit_sha"]:
        lines.insert(7, f"- Finder evidence commit: `{evidence_commit}` (the default branch advanced before verification)")
    for record in writer["citations"]:
        lines.append(f"- [{record['claim']}]({record['url']})")
    lines.extend(["", "## Screening limitations", ""])
    lines.extend(f"- {value}" for value in selected["screening_limitations"])
    lines.extend(["", "## Run record", "",
                  f"- Run ID: `{run_id}`",
                  "- Archive size was measured from the complete streamed download.",
                  "- Repository content was downloaded, inspected read-only, and never installed or executed."])
    return "\n".join(lines) + "\n"


def render_repository_handoff(
    selected: Mapping[str, Any], writer: Mapping[str, Any], findings_markdown: str,
) -> str:
    """Render only repository identity, risk findings, and the task-facing brief."""
    if not findings_markdown.startswith("# Content-safety findings:"):
        raise KickoffError("Cannot assemble repository handoff from an invalid risk report.")
    prompt = writer.get("turn_one_prompt")
    if not isinstance(prompt, str) or not prompt.strip():
        raise KickoffError("Cannot assemble repository handoff without a validated engineering task.")
    risk_body = findings_markdown.partition("\n")[2].strip()
    return "\n".join([
        f"# Repository kickoff: {selected['full_name']}", "",
        "## Repository", "",
        f"- Repository: [{selected['full_name']}]({selected['url']})",
        f"- Pinned commit: `{selected['commit_sha']}`",
        f"- Review status: `{selected['review_status']}`",
        "- Potential PII/key file details: [Risk files](#risk-files)", "",
        "## Risk files", "", risk_body, "",
        "## Engineering task", "", prompt.strip(), "",
    ])


def publish_repository_handoff(
    selected: Mapping[str, Any], writer: Mapping[str, Any], findings_markdown: str,
    directory: Path = DEFAULT_REPOSITORY_DIRECTORY,
) -> Path:
    """Create one non-overwriting handoff file in the owner/repository folder."""
    full_name = str(selected.get("full_name", ""))
    if not GITHUB_NAME_RE.fullmatch(full_name):
        raise KickoffError(f"Invalid repository name for handoff folder: {full_name!r}")
    owner, repository = full_name.split("/", 1)
    if owner in {".", ".."} or repository in {".", ".."}:
        raise KickoffError(f"Unsafe repository name for handoff folder: {full_name!r}")
    content = render_repository_handoff(selected, writer, findings_markdown)
    root = Path(directory).resolve()
    owner_directory = root / owner
    repository_directory = owner_directory / repository
    if owner_directory.is_symlink() or repository_directory.is_symlink():
        raise KickoffError("Refusing to publish a repository handoff through a link.")
    repository_directory.mkdir(parents=True, exist_ok=True)
    try:
        repository_directory.resolve().relative_to(root)
    except ValueError as exc:
        raise KickoffError("Repository handoff folder escaped its configured root.") from exc
    handoff_path = repository_directory / "repository_kickoff.md"
    if handoff_path.is_symlink():
        raise KickoffError("Refusing to overwrite a linked repository handoff.")
    try:
        with handoff_path.open("x", encoding="utf-8") as stream:
            stream.write(content)
    except FileExistsError as exc:
        if handoff_path.read_text(encoding="utf-8") != content:
            raise KickoffError(f"Refusing to overwrite an existing repository handoff: {handoff_path}") from exc
    return handoff_path


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Find a fresh Python repository and generate a grounded engineering task.")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIRECTORY)
    parser.add_argument("--repository-dir", type=Path, default=DEFAULT_REPOSITORY_DIRECTORY)
    parser.add_argument("--finder-model", default=DEFAULT_FINDER_MODEL)
    parser.add_argument("--finder-reasoning", choices=REASONING_EFFORTS, default=DEFAULT_FINDER_REASONING)
    parser.add_argument("--writer-model", default=DEFAULT_WRITER_MODEL)
    parser.add_argument("--writer-reasoning", choices=REASONING_EFFORTS, default=DEFAULT_WRITER_REASONING)
    parser.add_argument("--max-output-tokens", type=int, default=DEFAULT_MAX_OUTPUT_TOKENS)
    parser.add_argument(
        "--reuse-finder-response", type=Path,
        help="Reuse a saved repository_finder_response.json in a new run without another finder API call.",
    )
    parser.add_argument("--validate-only", action="store_true", help="Validate local prompts, ledger, and schemas without API calls.")
    arguments = parser.parse_args(argv)
    if not 1_000 <= arguments.max_output_tokens <= 100_000:
        parser.error("--max-output-tokens must be between 1000 and 100000")
    return arguments


def recent_opening_approaches(ledger: Mapping[str, Any], limit: int = 2) -> list[str]:
    recent: list[str] = []
    repositories = ledger.get("repositories") if isinstance(ledger, Mapping) else None
    for entry in reversed(repositories if isinstance(repositories, list) else []):
        approach = entry.get("opening_approach") if isinstance(entry, Mapping) else None
        if isinstance(approach, str) and approach in OPENING_APPROACHES:
            recent.append(approach)
            if len(recent) == limit:
                break
    return recent


def run(arguments: argparse.Namespace) -> Path | None:
    load_local_dotenv(TOOL_DIRECTORY / ".env")
    finder_instructions = load_prompt("repository_finder.md")
    writer_instructions = load_prompt("turn_one_prompt_writer.md")
    ledger = load_ledger()
    used_keys = {str(entry["full_name"]).casefold() for entry in ledger["repositories"]}
    used_repository_ids = {
        entry["github_repository_id"] for entry in ledger["repositories"]
        if type(entry.get("github_repository_id")) is int and entry["github_repository_id"] > 0
    }
    recent_approaches = recent_opening_approaches(ledger)
    # Serializing both schemas here catches accidental non-JSON values before a paid request.
    json.dumps(finder_schema())
    json.dumps(writer_schema())
    if arguments.validate_only:
        print(json.dumps({
            "valid": True,
            "recorded_repository_count": len(used_keys),
            "used_repository_id_count": len(used_repository_ids),
            "recent_opening_approaches": recent_approaches,
            "finder_prompt_characters": len(finder_instructions),
            "writer_prompt_characters": len(writer_instructions),
            "finder_model": arguments.finder_model,
            "finder_reasoning": arguments.finder_reasoning,
            "writer_model": arguments.writer_model,
            "writer_reasoning": arguments.writer_reasoning,
        }, indent=2))
        return None

    run_id = f"{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
    run_directory = arguments.output_dir.resolve() / run_id
    run_directory.mkdir(parents=True, exist_ok=False)
    stage = "repository_finder"
    write_json(run_directory / "status.json", {"status": "running", "stage": stage})
    models = {
        "finder_model": arguments.finder_model,
        "finder_reasoning": arguments.finder_reasoning,
        "writer_model": arguments.writer_model,
        "writer_reasoning": arguments.writer_reasoning,
    }
    finder_input: dict[str, Any] = {
        "run_id": run_id,
        "run_nonce": uuid.uuid4().hex,
        "eligibility": {
            "stars": {"minimum_exclusive": MIN_STARS_EXCLUSIVE, "maximum": None},
            "downloaded_archive_bytes": {"maximum_exclusive": MAX_ARCHIVE_BYTES},
            "preferred_activity_within_days": RECENT_ACTIVITY_DAYS,
            "allowed_licenses": sorted(ALLOWED_LICENSES),
            "preupload_tree": {
                "candidate_content_findings": "advisory_only_during_repository_selection",
                "candidate_findings_are_not_eligibility_rules": True,
                "selected_repository_verification": (
                    "stream, safely extract, scan, and report linked risk files; continue to prompt writing "
                    "even when manual review is needed, but create an upload artifact only after a clean rescan"
                ),
            },
        },
        "recorded_repositories": ledger["repositories"],
        "recent_opening_approaches": recent_approaches,
        "request": "Find one fresh eligible repository. Use current public evidence and return the structured selection dossier only.",
    }
    try:
        reuse_path = getattr(arguments, "reuse_finder_response", None)
        candidate_allowlist: dict[str, str] | None = None
        preflight_candidate_records: dict[str, Mapping[str, Any]] | None = None
        if reuse_path is None:
            stage = "candidate_preflight"
            write_json(run_directory / "status.json", {"status": "running", "stage": stage})
            preflight = discover_preflight_candidates(
                used_keys,
                used_repository_ids,
                progress_callback=lambda progress: write_json(
                    run_directory / "candidate_preflight_progress.json", progress,
                ),
            )
            write_json(run_directory / "candidate_preflight.json", preflight)
            eligible_candidates = preflight["eligible_candidates"]
            candidate_allowlist = {
                str(candidate["full_name"]).casefold(): str(candidate["commit_sha"])
                for candidate in eligible_candidates
            }
            preflight_candidate_records = {
                str(candidate["full_name"]).casefold(): candidate
                for candidate in eligible_candidates
            }
            finder_input["deterministic_preflight_candidates"] = eligible_candidates
            finder_input["request"] = (
                "Select and compare repositories only from deterministic_preflight_candidates. "
                "Use each listed commit exactly, inspect current pinned source evidence, and return "
                "the structured selection dossier only. Do not introduce another repository."
            )
            stage = "repository_finder"
            write_json(run_directory / "status.json", {"status": "running", "stage": stage})
        write_json(run_directory / "finder_input.json", finder_input)
        if reuse_path is not None:
            saved_receipt = read_json(reuse_path.resolve())
            if not isinstance(saved_receipt, Mapping) or saved_receipt.get("stage") != "repository_finder":
                raise KickoffError("--reuse-finder-response must point to a repository finder receipt.")
            finder_raw = str(saved_receipt.get("output_text", ""))
            saved_usage = saved_receipt.get("usage")
            finder_usage = dict(saved_usage) if isinstance(saved_usage, Mapping) else {}
            finder_response_id = str(saved_receipt.get("response_id", ""))
            saved_sources = saved_receipt.get("web_sources")
            finder_web_sources = list(saved_sources) if isinstance(saved_sources, list) else []
            finder_completion = {
                "response_status": saved_receipt.get("response_status"),
                "incomplete_reason": saved_receipt.get("incomplete_reason"),
            }
            finder_max_output_tokens = saved_receipt.get("max_output_tokens")
            models["finder_model"] = str(saved_receipt.get("model", arguments.finder_model))
            models["finder_reasoning"] = str(
                saved_receipt.get("reasoning_effort", arguments.finder_reasoning)
            )
            write_json(run_directory / "repository_finder_response.json", {
                **dict(saved_receipt), "reused_from": str(reuse_path.resolve()),
            })
        else:
            finder_raw, finder_usage, finder_response_id, finder_web_sources, finder_completion = call_structured_stage(
                model=arguments.finder_model,
                reasoning_effort=arguments.finder_reasoning,
                instructions=finder_instructions,
                payload=finder_input,
                schema=finder_schema(),
                schema_name="repository_finder",
                max_output_tokens=arguments.max_output_tokens,
            )
            write_stage_receipt(
                run_directory, "repository_finder", model=arguments.finder_model,
                reasoning_effort=arguments.finder_reasoning, response_id=finder_response_id,
                usage=finder_usage, web_sources=finder_web_sources, output_text=finder_raw,
                max_output_tokens=arguments.max_output_tokens, **finder_completion,
            )
            finder_max_output_tokens = arguments.max_output_tokens
        finder = parse_structured_output(
            finder_raw, "repository_finder", usage=finder_usage,
            max_output_tokens=finder_max_output_tokens if isinstance(finder_max_output_tokens, int) else None,
            **finder_completion,
        )
        finder = validate_finder_result(
            finder, used_keys, recent_approaches, authoritative_metadata=False,
            candidate_allowlist=candidate_allowlist,
        )
        write_json(run_directory / "finder_result.json", finder)
        stage = "github_verification"
        write_json(run_directory / "status.json", {"status": "running", "stage": stage})
        verification = verify_github_selection(
            finder, used_repository_ids, preflight_candidates=preflight_candidate_records,
        )
        write_json(run_directory / "github_verification.json", verification)
        # Re-run local eligibility after authoritative metadata replaced model values.
        finder = validate_finder_result(finder, used_keys, recent_approaches)
        selected = finder["selected_repository"]
        with tempfile.TemporaryDirectory(prefix="repository-kickoff-") as temporary_directory:
            temporary_root = Path(temporary_directory)
            stage = "archive_download"
            write_json(run_directory / "status.json", {"status": "running", "stage": stage})
            archive_path = temporary_root / "source.zip"
            try:
                archive_download = download_github_archive(
                    str(selected["full_name"]), str(selected["commit_sha"]), archive_path,
                )
                extracted_root, archive_review = safely_extract_archive(
                    archive_path, temporary_root / "extracted",
                )
            except ArchivePreparationError as exc:
                raise KickoffError(str(exc)) from exc
            archive_review = {**archive_download, **archive_review}
            write_json(run_directory / "archive_review.json", archive_review)
            selected["archive_size_bytes"] = archive_download["archive_size_bytes"]

            stage = "content_safety_review"
            write_json(run_directory / "status.json", {"status": "running", "stage": stage})
            initial_safety_report = scan_tree(extracted_root)
            report_scan = initial_safety_report
            write_json(run_directory / "initial_content_safety_scan.json", initial_safety_report)
            selected["source_scan_status"] = str(initial_safety_report["status"])
            selected["review_status"] = (
                "used_for_task" if initial_safety_report["status"] == "clean" else "potential_pii"
            )
            findings_path = run_directory / "content_safety_findings.md"
            findings_path.write_text(
                render_content_safety_findings_markdown(
                    str(selected["full_name"]),
                    str(selected["commit_sha"]),
                    initial_safety_report,
                ),
                encoding="utf-8",
            )
            preparation_status = "not_created_manual_review"
            prepared_scan_status = None
            if initial_safety_report["status"] == "clean":
                stage = "preparation_and_rescan"
                write_json(run_directory / "status.json", {"status": "running", "stage": stage})
                initial_root = extracted_root.resolve()
                initial_report_consumed = False

                def scan_with_cached_initial(root: Path) -> dict[str, Any]:
                    nonlocal initial_report_consumed
                    if not initial_report_consumed and root.resolve() == initial_root:
                        initial_report_consumed = True
                        return initial_safety_report
                    return scan_tree(root)

                try:
                    preparation = prepare_repository(
                        extracted_root,
                        run_directory,
                        upstream_commit_sha=str(selected["commit_sha"]),
                        original_archive_sha256=str(archive_download["original_archive_sha256"]),
                        scanner=scan_with_cached_initial,
                    )
                except (PreparationError, OSError) as exc:
                    raise KickoffError(f"Repository safety preparation failed: {exc}") from exc
                preparation_status = str(preparation.get("status") or "unknown")
                final_report = preparation.get("final_report")
                prepared_scan_status = (
                    str(final_report.get("status")) if isinstance(final_report, Mapping) else None
                )
                if preparation_status == "clean":
                    identity = validate_preparation_result(preparation, selected, archive_download, run_directory)
                    write_json(run_directory / "prepared_repository_identity.json", identity)
                    selected["prepared_repository"] = identity
                else:
                    selected["review_status"] = "potential_pii"
                    if isinstance(final_report, Mapping):
                        report_scan = final_report
                        write_json(run_directory / "review_scan.json", report_scan)
            else:
                write_json(run_directory / "content_safety_report.json", {
                    "status": "review_pending",
                    "source_scan": initial_safety_report,
                    "prepared_scan": None,
                })
            findings_path.write_text(
                render_content_safety_findings_markdown(
                    str(selected["full_name"]),
                    str(selected["commit_sha"]),
                    report_scan,
                    preparation_status=preparation_status,
                    prepared_scan_status=prepared_scan_status,
                ),
                encoding="utf-8",
            )
            selected["risk_scan_status"] = str(report_scan["status"])

        stage = "turn_one_writer"
        write_json(run_directory / "status.json", {"status": "running", "stage": stage})
        writer_input = {
            "repository": writer_repository_dossier(selected),
            "request": "Create the task-facing engineering investigation from this repository evidence.",
        }
        write_json(run_directory / "writer_input.json", writer_input)
        writer_raw, writer_usage, writer_response_id, writer_web_sources, writer_completion = call_structured_stage(
            model=arguments.writer_model,
            reasoning_effort=arguments.writer_reasoning,
            instructions=writer_instructions,
            payload=writer_input,
            schema=writer_schema(),
            schema_name="turn_one_prompt_writer",
            max_output_tokens=arguments.max_output_tokens,
        )
        write_stage_receipt(
            run_directory, "turn_one_writer", model=arguments.writer_model,
            reasoning_effort=arguments.writer_reasoning, response_id=writer_response_id,
            usage=writer_usage, web_sources=writer_web_sources, output_text=writer_raw,
            max_output_tokens=arguments.max_output_tokens, **writer_completion,
        )
        writer = parse_structured_output(
            writer_raw, "turn_one_prompt_writer", usage=writer_usage,
            max_output_tokens=arguments.max_output_tokens, **writer_completion,
        )
        writer = validate_writer_result(writer, finder["selected_repository"])
        write_json(run_directory / "writer_result.json", writer)
        usage = {"finder": finder_usage, "writer": writer_usage}
        write_json(run_directory / "usage.json", usage)
        write_json(run_directory / "responses.json", {
            "finder_response_id": finder_response_id,
            "writer_response_id": writer_response_id,
            "finder_web_sources": finder_web_sources,
            "writer_web_sources": writer_web_sources,
            **models,
        })
        markdown = render_markdown(finder, writer, verification, run_id, usage, models)
        result_path = run_directory / "repository_kickoff.md"
        result_path.write_text(markdown, encoding="utf-8")
        handoff_directory = getattr(
            arguments, "repository_dir", arguments.output_dir.resolve() / "selected_repositories",
        )
        handoff_path = publish_repository_handoff(
            selected, writer, findings_path.read_text(encoding="utf-8"), handoff_directory,
        )
        append_ledger(
            ledger, finder["selected_repository"], writer, run_id,
            status=selected["review_status"],
            finding_count=int(report_scan["counts"]["findings"]),
            handoff_path=handoff_path,
        )
        write_json(run_directory / "status.json", {
            "status": "completed", "result": str(result_path), "usage": usage,
            "repository_handoff": str(handoff_path),
            "review_status": selected["review_status"],
            "upload_ready": isinstance(selected.get("prepared_repository"), Mapping),
        })
        return result_path
    except KeyboardInterrupt:
        write_json(run_directory / "status.json", {"status": "interrupted", "stage": stage})
        raise
    except OSError as exc:
        try:
            write_json(
                run_directory / "status.json",
                {"status": "failed", "stage": stage, "error": "Local filesystem operation failed."},
            )
        except OSError:
            pass
        raise KickoffError(f"Local filesystem operation failed during {stage}: {type(exc).__name__}") from exc
    except KickoffError as exc:
        write_json(run_directory / "status.json", {"status": "failed", "stage": stage, "error": str(exc)})
        raise KickoffError(f"{exc} Local stage record: {run_directory}") from exc


def main(argv: Sequence[str] | None = None) -> int:
    try:
        arguments = parse_args(argv or sys.argv[1:])
        result = run(arguments)
    except KickoffError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
    if result is not None:
        print(f"Repository kickoff created: {result}")
        print(f"Repository handoff created: {read_json(result.parent / 'status.json')['repository_handoff']}")
        print(f"Repository registry updated: {LEDGER_PATH}")
        if read_json(result.parent / "status.json").get("review_status") == "potential_pii":
            print("Manual review required before upload; no upload-ready archive was created.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
