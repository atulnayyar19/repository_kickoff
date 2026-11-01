# Repository Kickoff

Find a public Python repository and generate a source-grounded, read-only
engineering investigation. Repository Kickoff combines deterministic GitHub
checks, bounded archive inspection, local content screening, and two independent
model stages in a repeatable command-line workflow:

1. A deterministic GitHub search and pinned-archive preflight streams candidate
   downloads, enforces the under-50-MiB limit, extracts them safely, applies a
   structural floor for a meaningful tracked tree, Python source and tests,
   packaging metadata, and CI, and records content-safety findings as advisory
   metadata. Potential PII, credentials, keys, and other content findings do not
   exclude a public GitHub repository during discovery; the model must establish
   connected architectural depth from source evidence.
2. `prompts/repository_finder.md` directs a web-enabled scout to compare only
   the current, pinned repositories on that preflight allowlist.
3. A deterministic GitHub check verifies the full shortlist, including the
   immutable repository identity and current default-branch commit. If a branch
   advances during research, the immutable finder-evidence commit is preserved
   separately from the newly verified download commit.
4. The selected commit archive is streamed to a temporary directory. The
   complete downloaded byte count must be strictly less than 50 MiB
   (52,428,800 bytes); GitHub repository-size metadata is not used.
5. Safe ZIP extraction rejects traversal, links, path collisions, excessive
   expansion, suspicious compression ratios, and excessive file counts.
6. After selection, a local content-safety scanner checks the extracted tree
   and writes a linked risk-file report. Findings are advisory for selection
   and prompt creation, but not permission to upload the source.
7. A repository clean on the initial scan is copied to an isolated prepared
   tree and rescanned before an upload-ready archive is created. A repository
   with findings instead awaits manual review; no upload-ready archive is made.
8. `prompts/turn_one_prompt_writer.md` creates one read-only engineering
   investigation in either case. The result links the risk report.

The two model stages do not share a chat. The writer receives a deliberately
reduced engineering dossier. Content-review status, scan findings, screening
limitations, and prepared-repository identity stay in the local risk report and
run records. Scan-related notes are filtered from the writer's risk notes;
engineering risks remain available. Candidate comparisons, selection scoring,
opening-variation data, long-horizon fit, run identifiers, and model settings
also remain orchestration metadata and are not sent to the task writer.
GitHub verification replaces
model-reported identity, activity, stars, license, branch, and commit with
current values. Finder evidence remains pinned to the immutable commit it
actually inspected, while the writer and final task must cite the current
verified/downloaded commit. Repository code is downloaded for local inspection,
but is never installed or executed.

The writer returns structured task fields rather than free-form Markdown. The
application renders them as `Goal`, `Context`, `Scope`, `Expected Outcome`, and
`Guardrails`. The task asks only for findings within the current investigation;
it does not request a subsequent implementation, roadmap, follow-up turn, or
explanation of the evaluation setup. Repository sourcing, manual content-risk
review, sanitization, and upload-readiness statements are excluded from all
task fields; the separate risk report retains that information.

The repository rule is **more than 500 stars**, with no upper bound. The selected
repository must also pass a structured long-horizon-fit gate: at least three
connected workflow boundaries, multiple maintainer dimensions, useful tests or
fixtures, local feasibility, meaningful failure/recovery behavior, and no
unresolved disqualifiers.

## Risk report and upload boundary

The scanner never includes matched secret or PII values in its JSON reports.
It records only categories, locations, detector names, counts, and one-way
fingerprints.

Candidate discovery and engineering-task creation do not treat scanner findings as
eligibility failures for public GitHub repositories. The report gives a risk
factor and pinned links to every flagged file and line. A selected repository
with findings yields the repository recommendation, engineering task, and report,
but no upload-ready archive. Manual review remains necessary before using or
uploading that codebase.

- Real keys, tokens, private keys, proprietary indicators, sensitive config,
  unreadable content, raster images/screenshots, binaries, and ambiguous exports are
  rejected or require manual review. They are never automatically rewritten.
- Plain UTF-8 SVG XML is text-scanned; SVG files with embedded raster data
  require manual review.
- The kickoff command does not automatically rewrite flagged files. After
  manual review, remediation and upload preparation still require a clean scan;
  changing the registry flag does not certify source safety.
- The source tree and original archive are never modified. The original archive
  exists only in a temporary directory and is deleted when preparation ends.
- A clean selected tree produces a `clean`/`clean_upstream` prepared archive.
  A flagged tree has no prepared archive or prepared identity in the kickoff.

This is conservative heuristic screening, not a proof that sensitive content is
absent. Opaque content requires review rather than being silently accepted.

## Setup

Tested with Python 3.12. From the cloned repository root:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r .\repository_kickoff\requirements.txt
Copy-Item .\repository_kickoff\data\used_repositories.example.json .\repository_kickoff\data\used_repositories.json
```

The registry starts empty. Its runtime copy is ignored by Git so personal
selection history stays local. Run the copy command once during setup; preserve
an existing registry when updating the application.

The script reads `OPENAI_API_KEY` from the process environment or
`repository_kickoff/.env`. You can copy the local example if needed:

```powershell
Copy-Item .\repository_kickoff\.env.example .\repository_kickoff\.env
```

An optional `GITHUB_TOKEN` increases the GitHub API rate limit. Never place keys
in prompts or output files.

## Validate locally without spending API tokens

```powershell
.\.venv\Scripts\python.exe .\repository_kickoff\repository_kickoff.py --validate-only
```

## Run the local tests

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s repository_kickoff -t . -p "test_*.py"
```

The tests use temporary directories and mocked external calls; no paid API
requests are needed.

## Generate a repository and engineering task

```powershell
.\.venv\Scripts\python.exe .\repository_kickoff\repository_kickoff.py
```

Each completed selection also creates a consolidated handoff at
`repository_kickoff/selected_repositories/<owner>/<repository>/repository_kickoff.md`.
It includes the repository link and pinned commit, risk factor and linked
file/line findings when present, and the task-facing engineering request.
Selection rationale, model settings, and token usage remain in detailed JSON
stage receipts under `outputs/<run-id>/`; they are not included in the
consolidated handoff. Use `--repository-dir` to choose a different handoff root.
Existing handoffs are never overwritten with different content.

Each successful run creates the finder, verification, scan, writer, Markdown,
and status files below. Prepared-tree files are created only for clean scans:

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
  sanitization_manifest.json        # clean scans only
  prepared_repository_identity.json # clean scans only
  prepared_repository/              # clean scans only
  upload_ready_repository.zip       # clean scans only
  writer_input.json
  turn_one_writer_response.json
  writer_result.json
  usage.json
  responses.json
  repository_kickoff.md
  status.json
```

The two response receipts are written immediately after their paid API calls and
contain response IDs, usage, included web-source URLs, and structured output
text. They remain available if a later validation stage fails. The Markdown file
is the main result. The single repository registry is
`repository_kickoff/data/used_repositories.json`, initialized from the empty
example during setup. Once both model stages and local validation succeed, a new
recommendation is added as `used_for_task` only if
the initial selected-tree scan was clean and the prepared copy passed its clean
rescan. Otherwise it is added as `potential_pii`, with its run ID and relative
paths to the risk report and consolidated handoff. Both statuses prevent
duplicate recommendations.
After reviewing a flagged repository, you can change that one status to
`used_for_task` in the JSON file; this is bookkeeping, **not** an upload-safety
certificate. A failed run does not add a registry entry.

`content_safety_findings.md` is written immediately after the selected snapshot
is scanned, so it remains available even when later stages fail. It contains a
pinned GitHub link for every flagged file and flagged line, grouped by file with
its categories, detectors, and dispositions. It never includes matched values,
source snippets, or fingerprints. It also records whether an upload-ready copy
was created or manual review is pending.

## Model defaults

Both stages default to `gpt-5.6-sol`. The finder defaults to `xhigh` reasoning
because it compares candidates, checks source evidence, and judges long-horizon
fit. The narrower engineering-task writer defaults to `high`. This is a quality-first
starting point, not a measured claim that `xhigh` always wins; compare results
on representative runs before raising writer effort. The shared 40,000-token
output budget includes both reasoning and visible JSON; a smaller budget can
stop a response mid-object.
These are the application defaults. Override the model names with models
available to your API account when needed:

```powershell
.\.venv\Scripts\python.exe .\repository_kickoff\repository_kickoff.py `
  --finder-model gpt-5.6-sol --finder-reasoning xhigh `
  --writer-model gpt-5.6-sol --writer-reasoning high
```

The tool performs exactly two OpenAI requests on a successful run. Both use web
search and strict structured output. The local output includes per-stage token
usage and web-source receipts so cost and discovery provenance can be reviewed
after every call, including runs that fail later validation. No writer request
is made when archive download, extraction, or scan execution fails. Scanner
findings alone do not prevent the writer request.
An incomplete response is saved with its status, reason, output limit, and token
usage. When the output limit is exhausted, the error recommends increasing
`--max-output-tokens` or lowering the affected stage's reasoning effort.

## Repository contents

- `repository_kickoff/repository_kickoff.py`: CLI, GitHub preflight, stage orchestration, and handoffs.
- `repository_kickoff/archive_preparation.py`: bounded download and safe ZIP extraction.
- `repository_kickoff/content_safety.py`: local heuristic content screening.
- `repository_kickoff/sanitization.py`: isolated preparation and archive generation.
- `repository_kickoff/prompts/`: finder and task-writer instructions.
- `repository_kickoff/test_*.py`: local regression coverage.
- `repository_kickoff/chat_fallback.md`: optional manual chat workflow.

Credentials, selection history, generated handoffs, run outputs, downloaded
repositories, virtual environments, and archived legacy material stay local.
