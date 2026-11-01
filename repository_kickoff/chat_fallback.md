# Repository kickoff — chat-only fallback

This is a fallback for manually reproducing the repository kickoff in a
web-enabled chat. The executable workflow under `repository_kickoff/` is the
source of truth. Keep selection policy in the setup message; do not repeat it in
the engineering task.

## Setup message

Find one fresh public Python repository and create one source-grounded,
read-only engineering investigation request for it.

### Background selection policy

Apply these rules while selecting the repository, but do not mention the rules,
candidate comparison, scoring, model configuration, or sequencing strategy in
the copy-ready task:

- Select a public, Python-focused repository that is not archived or a fork.
- Require more than 500 GitHub stars and a permissive license: MIT, MIT-0,
  Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, Zlib, 0BSD, Unlicense, or
  CC0-1.0.
- Do not use GitHub repository-size metadata. The downloaded source archive must
  be strictly less than 50 MiB when that measurement can be performed.
- Exclude cybersecurity, malware, exploitation, biology, biotech, genomics, and
  drug-discovery repositories.
- Exclude repositories already present in the supplied registry, including
  renamed repositories and obvious mirrors.
- Prefer recent activity and a workflow that crosses at least three meaningful
  boundaries with useful tests, failure paths, and feasible local verification.
- Potential PII, credentials, keys, screenshots, exports, or opaque files are
  advisory during public-repository selection. Report the affected file links
  without reproducing values. Never claim a repository is safe to upload from a
  web inspection alone.

Inspect current GitHub metadata and pin every source claim to the exact
40-character commit. Compare at least two eligible candidates using connected
architecture, current workflow depth, test evidence, compatibility boundaries,
failure/recovery behavior, and local feasibility. These comparison details are
selection records, not task content.

### Engineering task contract

The copy-ready task must contain exactly these sections:

1. **Goal** — one concrete outcome for understanding the repository's current
   behavior.
2. **Context** — the repository URL, pinned commit, and only the repository
   facts needed to understand the request.
3. **Scope** — named entry points, collaborators, state or data ownership,
   ordering, configuration, invariants, failure/recovery paths, tests, and
   material exclusions.
4. **Expected Outcome** — source-backed findings, confirmed behavior,
   reasonable inference, unresolved questions, compatibility boundaries, and
   existing test evidence or evidence gaps.
5. **Guardrails** — read-only authorization, an unchanged repository tree,
   safety boundaries, and explicit exclusions.

Ask only for findings from the current investigation. Do not ask for a next or
recommended implementation, implementation slice, subsequent task, future turn,
follow-up work, roadmap, or acceptance criteria for a hypothetical change. Do
not describe the investigation as a foundation for later work. Do not mention
an AI, coding model, grader, benchmark, long-horizon evaluation, token target,
candidate comparison, opening-variation scheme, or model setting.

Keep repository sourcing, content-risk review, sanitization, and upload-
preparation status in the separate risk-file report, outside every task
section. Do not add review-status disclaimers or upload-readiness claims to
the copy-ready task.

Use direct maintainer language. Do not assert an unverified defect, manufacture
urgency, request private reasoning, or prescribe a patch. Name enough real
paths, symbols, tests, and workflow boundaries that the request cannot be moved
to an unrelated repository unchanged.

The task is read-only: do not install dependencies, run downloaded code or
tests, modify files, access credentials, contact external services, or perform
production actions. Clearly distinguish inspected source and documentation from
checks actually executed.

### Output

Return:

1. The selected repository URL and pinned commit.
2. A concise selection record and the strongest alternative, kept outside the
   copy-ready task.
3. A risk-file report containing links and classifications but no matched
   secret or personal values.
4. The copy-ready engineering task using **Goal**, **Context**, **Scope**,
   **Expected Outcome**, and **Guardrails**.
5. The updated used-repositories registry.

Historical generated tasks may retain older wording. Do not treat them as
templates for new tasks.
