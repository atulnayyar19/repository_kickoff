# Repository Kickoff

**Find a Python repository. Generate an engineering investigation grounded in its source.**

Repository Kickoff is a command-line tool that discovers public GitHub projects,
verifies a specific commit, inspects the source archive, and produces a read-only
engineering brief. It combines deterministic checks with separate repository-finder
and task-writer model stages.

Each completed run provides:

- A repository recommendation with a pinned commit and source citations.
- An engineering task organized into **Goal**, **Context**, **Scope**, **Expected Outcome**, and **Guardrails**.
- A content-review report with links to flagged files and lines.
- A prepared source archive when both the initial scan and the prepared-copy rescan are clean.

Downloaded repository code is inspected locally; it is never installed or executed.

[Quick start](#quick-start) · [Configuration](#configuration) · [Outputs](#outputs) · [How it works](#how-it-works) · [Troubleshooting](#troubleshooting) · [Development](#development)

## Requirements

- **Python:** tested with Python 3.12.
- **Git:** available on your system's `PATH`.
- **OpenAI API access:** an API key and access to models supporting the application's web-search, reasoning, and structured-output settings.
- **Network access:** GitHub, source-archive downloads, and the OpenAI API.

The commands below use **Windows PowerShell** and run from the cloned repository root.

## Quick start

### 1. Clone the repository and install dependencies

```powershell
git clone https://github.com/atulnayyar19/repository_kickoff.git
cd repository_kickoff
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r .\repository_kickoff\requirements.txt
```

The commands invoke the virtual environment directly, so activation is optional.

### 2. Initialize your local configuration and registry

Run these copy commands once on a fresh checkout. Keep existing files when updating
an installation; the registry preserves your selection history.

```powershell
Copy-Item .\repository_kickoff\.env.example .\repository_kickoff\.env
Copy-Item .\repository_kickoff\data\used_repositories.example.json .\repository_kickoff\data\used_repositories.json
```

Edit `repository_kickoff/.env` and add your credentials:

```dotenv
OPENAI_API_KEY=your_openai_api_key
GITHUB_TOKEN=
```

| Variable | Purpose |
| --- | --- |
| `OPENAI_API_KEY` | Required for generation. |
| `GITHUB_TOKEN` | Optional. Increases the GitHub API rate limit. |

You can also set these variables in the process environment. Existing environment
values take precedence over `.env`. Credentials and the runtime registry are ignored
by Git; keep credentials out of prompts and generated files.

### 3. Validate the local setup

```powershell
.\.venv\Scripts\python.exe .\repository_kickoff\repository_kickoff.py --validate-only
```

A successful check prints JSON containing `"valid": true`. It checks prompts, the
registry, and output schemas without API calls. It does not verify credentials,
network access, or model availability.

### 4. Generate a repository kickoff

```powershell
.\.venv\Scripts\python.exe .\repository_kickoff\repository_kickoff.py
```

Generation makes paid API calls. A normal successful run invokes two model stages;
[reusing a finder response](#reuse-a-saved-finder-response) avoids another finder call.

The console prints the result and handoff paths. Start with the consolidated brief:

```text
repository_kickoff/selected_repositories/<owner>/<repository>/repository_kickoff.md
```

It contains the repository link, pinned commit, content-review findings, and engineering
task. Selection rationale, model settings, and token usage remain in the separate run
records. Existing handoffs are never overwritten with different content.

## Configuration

### Command-line options

| Option | Default | Purpose |
| --- | --- | --- |
| `--finder-model` | `gpt-5.6-sol` | Model used to compare repository candidates. |
| `--finder-reasoning` | `xhigh` | Reasoning effort for the finder. |
| `--writer-model` | `gpt-5.6-sol` | Model used to write the engineering brief. |
| `--writer-reasoning` | `high` | Reasoning effort for the writer. |
| `--max-output-tokens` | `40000` | Output limit per model request, including reasoning and visible JSON. Accepts `1000`–`100000`. |
| `--output-dir` | `repository_kickoff/outputs` | Directory for run records and artifacts. |
| `--repository-dir` | `repository_kickoff/selected_repositories` | Directory for consolidated handoffs. |
| `--reuse-finder-response` | Not set | Path to a saved `repository_finder_response.json` receipt. |
| `--validate-only` | Off | Check local inputs without API calls. |

These model names are application defaults, not a guarantee of account availability.
Use `--finder-model` and `--writer-model` to select models available to your account.
Reasoning choices are `none`, `low`, `medium`, `high`, `xhigh`, and `max`; the selected
model must support the requested setting.

For example, configure the two stages explicitly:

```powershell
.\.venv\Scripts\python.exe .\repository_kickoff\repository_kickoff.py `
  --finder-model gpt-5.6-sol --finder-reasoning xhigh `
  --writer-model gpt-5.6-sol --writer-reasoning high
```

Run with `--help` to see all options. If you choose custom output directories inside
the checkout, add them to `.gitignore` before committing generated data.

### Reuse a saved finder response

If a run saved a finder receipt before failing at a later stage, you can start a new
run with that receipt. Replace the example path with your saved file:

```powershell
.\.venv\Scripts\python.exe .\repository_kickoff\repository_kickoff.py `
  --reuse-finder-response "path\to\repository_finder_response.json"
```

This skips candidate discovery and the finder model call. The application still
validates the saved selection, checks current GitHub metadata, downloads and scans
the selected source, and invokes the writer if those stages succeed. Previously
recorded repositories remain ineligible.

## Outputs

Run artifacts are stored in `repository_kickoff/outputs/<run-id>/` by default.

| File or location | What to use it for |
| --- | --- |
| `selected_repositories/<owner>/<repository>/repository_kickoff.md` | Consolidated handoff under `repository_kickoff/`: repository identity, risk report, and copy-ready task. |
| `outputs/<run-id>/repository_kickoff.md` | Run summary with repository metadata, engineering task, source evidence, and screening limitations. |
| `content_safety_findings.md` | Linked findings grouped by file, plus preparation or review status. |
| `status.json` | Current stage and completion, failure, or interruption status. |
| `usage.json` and response receipts | Per-stage token usage, response IDs, source URLs, and structured output. |
| `upload_ready_repository.zip` | Prepared source archive, created only after clean scans. |

The first two paths are relative to `repository_kickoff/`; other filenames are
relative to the run directory.

<details>
<summary>Full artifact reference for a standard successful run</summary>

```text
repository_kickoff/outputs/<run-id>/
  candidate_preflight_progress.json
  candidate_preflight.json
  finder_input.json
  repository_finder_response.json
  finder_result.json
  github_verification.json
  archive_review.json
  initial_content_safety_scan.json
  content_safety_findings.md
  content_safety_report.json
  sanitization_manifest.json         # when preparation is attempted
  prepared_repository_identity.json  # clean preparation only
  prepared_repository/               # clean preparation only
  upload_ready_repository.zip        # clean preparation only
  writer_input.json
  turn_one_writer_response.json
  writer_result.json
  usage.json
  responses.json
  repository_kickoff.md
  status.json
```

Reused finder responses skip the candidate-preflight artifacts. Failed or interrupted
runs retain the records written before they stopped. Model receipts are saved before
response validation, and the findings report is saved as soon as the selected source
has been scanned, so both can remain available after later failures.

</details>

## How it works

1. **Discover candidates.** Search GitHub, download pinned archives, check repository
   structure, and record advisory content findings.
2. **Compare source evidence.** The finder researches only the preflight allowlist
   and compares candidates at their recorded commits.
3. **Verify the selection.** Refresh GitHub identity, stars, license, activity, branch,
   and commit information; then download and scan the selected snapshot.
4. **Prepare eligible source.** Copy an initially clean tree to an isolated directory
   and rescan it before producing an archive. Findings require manual review instead.
5. **Write and record the task.** The independent writer produces a read-only
   investigation; the application saves the handoff, run records, and registry entry.

If the default branch advances during research, the finder-evidence commit is retained
separately. The writer and final task must cite the newly verified download commit.
The two model stages have no shared chat history. The writer receives a reduced
engineering dossier; candidate scoring, selection strategy, model settings, run IDs,
and content-review metadata stay outside that dossier.

The task requests findings from the current investigation. Source-review status stays
in the risk report, while the brief focuses on engineering behavior, evidence, scope,
and guardrails. It does not request a later implementation or roadmap.

### Repository-selection criteria

| Criterion | Current policy |
| --- | --- |
| Repository | Public, Python-focused, not archived, and not a fork. |
| Popularity | More than **500 stars**, with no upper limit. |
| License | One of the permitted SPDX identifiers listed below. |
| Download size | Strictly below **50 MiB** (52,428,800 bytes), measured from the complete download rather than GitHub size metadata. |
| Structure | At least 50 files, 8 Python source files, 8 Python test files, and 20 Python files overall; packaging metadata and CI are also required. |
| Engineering depth | At least three connected workflow boundaries, multiple maintainer concerns, useful tests or fixtures, local feasibility, meaningful failure/recovery behavior, and no unresolved disqualifiers. |
| Exclusions | Previously recorded repositories and excluded subject areas, including cybersecurity, malware/exploitation, biology/biotech, genomics, and drug discovery. |

Permitted licenses: `MIT`, `MIT-0`, `Apache-2.0`, `BSD-2-Clause`, `BSD-3-Clause`,
`ISC`, `Zlib`, `0BSD`, `Unlicense`, and `CC0-1.0`.

Archive extraction rejects traversal, links, path collisions, excessive expansion,
suspicious compression ratios, and excessive file counts. Local content findings
are advisory during candidate selection and task writing; they control archive
preparation separately.

### Content review and archive preparation

| Scan outcome | Result |
| --- | --- |
| Initial scan and prepared-copy rescan are clean | Generate the brief, linked report, prepared archive, and `clean_upstream` identity. |
| Findings require review | Generate the brief and linked report when the remaining stages succeed; do not create an upload-ready archive. |
| Download, extraction, or scan execution fails | Stop before the writer call and retain available diagnostic records. |

Keys, tokens, sensitive configuration, proprietary indicators, unreadable files,
raster images/screenshots, binaries, and ambiguous exports are blocked from automatic
preparation or require review. Plain UTF-8 SVG XML is text-scanned; SVG files containing
embedded raster data require review. The kickoff command does not automatically
rewrite flagged files.

JSON scan reports record categories, locations, detector names, counts, and one-way
fingerprints, without matched secret or personal values. The Markdown findings report
provides pinned file/line links without matched values, source snippets, or fingerprints.

The source tree and original archive are never modified. Temporary downloads are
removed when inspection/preparation ends. Screening is heuristic: a clean scan is
not proof that sensitive content is absent. Review findings before using or uploading
flagged source; manual remediation still requires a clean scan and rescan before
upload preparation.

### Local repository registry

`repository_kickoff/data/used_repositories.json` starts empty and stays local. A
completed run adds one of these statuses:

| Status | Meaning |
| --- | --- |
| `used_for_task` | The initial scan was clean and the prepared copy passed its rescan. |
| `potential_pii` | Findings require manual review; the entry links the run's report and handoff. |

Both statuses prevent repeat recommendations. Failed runs do not add an entry.
After reviewing a flagged repository, you may update its status to `used_for_task`
for bookkeeping. Changing a registry status does not certify source safety or create
an upload-ready archive.

## Troubleshooting

| Problem | Next step |
| --- | --- |
| Missing registry or configuration | Complete quick-start step 2. Preserve existing files when updating. |
| API key or model error | Check `.env` and process environment values; select models and reasoning settings available to your API account. |
| GitHub rate-limit or network failure | Configure the optional `GITHUB_TOKEN`, check connectivity and Git availability, and inspect `status.json`. |
| Incomplete model response | Inspect the saved receipt. Increase `--max-output-tokens` within the supported range or lower the affected stage's reasoning effort. Reasoning uses part of the output budget. |
| Later-stage failure after the finder finished | Inspect the stage records and consider `--reuse-finder-response` to avoid repeating the finder call. |
| Existing handoff has different content | Preserve it and choose another `--repository-dir`; the tool refuses to overwrite it. |

## Development

Run the existing regression suite from the repository root:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s repository_kickoff -t . -p "test_*.py"
```

Tests use temporary directories and mocked external calls, without paid API requests.
Symlink coverage may be skipped when the host does not permit creating symlinks.

| Component | Responsibility |
| --- | --- |
| [repository_kickoff.py](repository_kickoff/repository_kickoff.py) | CLI, GitHub checks, model stages, registry, and handoffs. |
| [archive_preparation.py](repository_kickoff/archive_preparation.py) | Bounded downloads and safe ZIP extraction. |
| [content_safety.py](repository_kickoff/content_safety.py) | Local heuristic content scanning. |
| [sanitization.py](repository_kickoff/sanitization.py) | Isolated preparation, rescan, and archive generation. |
| [prompts/](repository_kickoff/prompts/) | Finder and task-writer instructions. |
| [test_*.py](repository_kickoff/test_repository_kickoff.py) | Regression tests alongside the application modules. |
| [chat_fallback.md](repository_kickoff/chat_fallback.md) | Optional manual workflow for a web-enabled chat. |

Credentials, selection history, generated handoffs, run outputs, virtual environments,
and archived legacy material are excluded from version control by default.
