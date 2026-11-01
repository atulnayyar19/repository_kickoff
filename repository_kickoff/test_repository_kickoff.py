from __future__ import annotations

import argparse
import hashlib
from http.client import IncompleteRead
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from repository_kickoff.repository_kickoff import (
    KickoffError,
    append_ledger,
    discover_preflight_candidates,
    fetch_json,
    finder_schema,
    git_remote_head,
    load_ledger,
    parse_args,
    parse_structured_output,
    publish_repository_handoff,
    response_web_sources,
    repository_structure_summary,
    render_content_safety_findings_markdown,
    run,
    validate_finder_result,
    validate_writer_result,
    verify_github_selection,
    write_json,
    writer_repository_dossier,
    writer_schema,
)


COMMIT = "a" * 40
ARCHIVE_SHA = "c" * 64


def clean_scan() -> dict:
    return {
        "schema_version": 1,
        "status": "clean",
        "counts": {"files_seen": 1, "files_scanned": 1, "findings": 0, "by_category": {}, "by_disposition": {}},
        "findings": [],
        "limitations": ["Heuristic scan."],
    }


def preparation_result(output_directory: Path) -> dict:
    (output_directory / "content_safety_report.json").write_text(
        json.dumps({"status": "clean", "source_scan": clean_scan(), "prepared_scan": clean_scan()}), encoding="utf-8",
    )
    (output_directory / "sanitization_manifest.json").write_text(
        json.dumps({"status": "clean", "relative_paths": [], "counts": {"replacements": 0}}), encoding="utf-8",
    )
    (output_directory / "upload_ready_repository.zip").write_bytes(b"prepared")
    identity = {
        "upstream_commit_sha": COMMIT,
        "original_archive_sha256": ARCHIVE_SHA,
        "prepared_archive_sha256": hashlib.sha256(b"prepared").hexdigest(),
        "workspace_state": "clean_upstream",
        "sanitization_manifest_sha256": hashlib.sha256(
            (output_directory / "sanitization_manifest.json").read_bytes()
        ).hexdigest(),
        "safety_status": "clean",
    }
    return {
        "status": "clean",
        "prepared_root": str(output_directory / "prepared_repository"),
        "archive_path": str(output_directory / "upload_ready_repository.zip"),
        "report_path": str(output_directory / "content_safety_report.json"),
        "manifest_path": str(output_directory / "sanitization_manifest.json"),
        "source_report": clean_scan(),
        "final_report": clean_scan(),
        "identity": identity,
    }


def finder_result() -> dict:
    return {
        "selected_repository": {
            "full_name": "example/fresh-python-project",
            "url": "https://github.com/example/fresh-python-project",
            "description": "A useful Python project.",
            "default_branch": "main",
            "commit_sha": COMMIT,
            "stars": 501,
            "license_spdx": "MIT",
            "pushed_at": "2026-09-01T00:00:00Z",
            "opening_approach": "cross_boundary_contract",
            "approach_reuse_reason": None,
            "workflow_theme": "Trace the CLI request through execution and persistence.",
            "entry_points": ["src/example/cli.py"],
            "collaborators": ["src/example/service.py", "src/example/store.py"],
            "test_surfaces": ["tests/test_cli.py"],
            "ci_surfaces": [".github/workflows/tests.yml"],
            "documented_commands": ["python -m unittest"],
            "risks": ["Public CLI compatibility"],
            "screening_limitations": ["Public source screening is heuristic."],
            "source_evidence": [
                {"claim": "CLI entry point", "url": f"https://github.com/example/fresh-python-project/blob/{COMMIT}/src/example/cli.py"},
                {"claim": "Service boundary", "url": f"https://github.com/example/fresh-python-project/blob/{COMMIT}/src/example/service.py"},
                {"claim": "Tests", "url": f"https://github.com/example/fresh-python-project/blob/{COMMIT}/tests/test_cli.py"},
            ],
            "long_horizon_fit": {
                "verdict": "strong_candidate",
                "boundary_chain": ["CLI parsing", "service execution", "persistent store"],
                "maintainer_dimensions": ["design", "debugging", "testing", "maintenance"],
                "test_and_fixture_evidence": ["tests/test_cli.py exercises the workflow"],
                "failure_recovery_complexity": ["Service failures must not corrupt stored state"],
                "local_feasibility": "The documented unit suite runs without a paid service.",
                "disqualifiers": [],
            },
        },
        "selection_reason": "The workflow crosses three concrete boundaries with tests.",
        "strongest_alternative": "Another project had weaker local verification.",
        "candidates_considered": [
            {
                "full_name": "example/fresh-python-project",
                "url": "https://github.com/example/fresh-python-project",
                "stars": 501,
                "license_spdx": "MIT",
                "commit_sha": COMMIT,
                "pushed_at": "2026-09-01T00:00:00Z",
                "workflow_theme": "Trace the CLI request through execution and persistence.",
                "assessment": "Selected for connected depth.",
                "source_urls": [
                    f"https://github.com/example/fresh-python-project/blob/{COMMIT}/src/example/cli.py",
                    f"https://github.com/example/fresh-python-project/blob/{COMMIT}/tests/test_cli.py",
                ],
            },
            {
                "full_name": "example/alternative",
                "url": "https://github.com/example/alternative",
                "stars": 601,
                "license_spdx": "Apache-2.0",
                "commit_sha": "b" * 40,
                "pushed_at": "2026-08-15T00:00:00Z",
                "workflow_theme": "Configuration flow",
                "assessment": "Useful but less connected.",
                "source_urls": [
                    f"https://github.com/example/alternative/blob/{'b' * 40}/src/alternative/config.py",
                    f"https://github.com/example/alternative/blob/{'b' * 40}/tests/test_config.py",
                ],
            },
        ],
        "uncertainties": ["Archive Content-Length was unavailable."],
    }


def preflight_result() -> dict:
    result = finder_result()
    return {
        "searched_at": "2026-09-20T00:00:00+00:00",
        "search_urls": ["https://api.github.com/search/repositories?q=example"],
        "inspected_count": 2,
        "eligible_candidates": [
            {
                "full_name": candidate["full_name"],
                "url": candidate["url"],
                "github_repository_id": index + 1,
                "github_node_id": f"R_{index + 1}",
                "stars": candidate["stars"],
                "license_spdx": candidate["license_spdx"],
                "pushed_at": candidate["pushed_at"],
                "description": "Candidate",
                "default_branch": "main",
                "commit_sha": candidate["commit_sha"],
                "archive_size_bytes": 100,
                "tracked_file_count": 10,
                "structure": {
                    "tracked_file_count": 50,
                    "source_python_files": 8,
                    "test_python_files": 12,
                    "total_python_files": 20,
                    "ci_workflow_files": 1,
                    "packaging_files": ["pyproject.toml"],
                    "status": "passed",
                    "failures": [],
                },
                "content_safety_advisory": {
                    "status": "clean",
                    "counts": clean_scan()["counts"],
                    "eligibility_effect": "none_during_candidate_discovery",
                },
                "workspace_state": "not_prepared",
                "preflight": "passed_archive_extraction_structure_and_advisory_content_scan",
            }
            for index, candidate in enumerate(result["candidates_considered"])
        ],
        "rejected_candidates": [],
    }


def writer_result(selected: dict) -> dict:
    return {
        "repository_url": selected["url"],
        "commit_sha": selected["commit_sha"],
        "request_type": "system_level_investigation",
        "task": {
            "goal": (
                "Investigate how the current CLI implementation carries one request from argument parsing "
                "through service execution and persistent storage, and document the behavior that keeps the "
                "result deterministic and observable when validation or execution fails."
            ),
            "context": (
                f"Use repository {selected['url']} at pinned commit {selected['commit_sha']}. The command "
                "enters through src/example/cli.py, delegates work to src/example/service.py, and records "
                "state through src/example/store.py. Existing tests provide evidence for the normal command "
                "path, while the inspected source must establish the ownership and failure contracts. No "
                "repository code or tests were executed while preparing this request."
            ),
            "scope": [
                "Trace parsing, normalization, dispatch, service execution, and persistence through the named functions and classes, recording the owner and representation of request state at every boundary.",
                "Explain ordering requirements, configuration precedence, validation rules, and the invariants that connect command output, stored state, exceptions, and process exit status.",
                "Follow malformed input, service exceptions, partial writes, retryable failures, and cleanup paths, distinguishing explicit recovery behavior from assumptions that are not established by source.",
                "Map tests and fixtures in tests/test_cli.py to the behavior they prove, and record the documented local commands without executing them during this investigation.",
                "Keep unrelated services, packaging mechanics, release automation, and broad refactoring outside the investigation unless they directly constrain the selected CLI contract.",
            ],
            "expected_outcome": [
                "Provide a source-backed workflow map using concrete paths and symbols, together with the state, ownership, and ordering invariants observed at each boundary.",
                "Report confirmed failure and recovery behavior, compatibility constraints, and any differences between displayed output, persisted results, raised exceptions, and exit status.",
                "Summarize the existing test evidence and its gaps, clearly separating inspected files and documented commands from checks that were actually executed.",
                "List unresolved questions as questions, explain what present evidence is missing, and distinguish those uncertainties from confirmed findings without turning them into a work plan.",
            ],
            "guardrails": [
                "Treat this as a read-only investigation and leave the tree unchanged; do not create caches, generated files, or other workspace artifacts.",
                "Do not install dependencies, execute downloaded code, run tests, contact external services, access credentials, or disclose secret or personal values.",
                "Base every repository-specific conclusion on the pinned source or checked-in documentation, label inference explicitly, and keep the report within the stated CLI workflow.",
            ],
        },
        "citations": selected["source_evidence"],
        "grounding_notes": ["The request names inspected source and tests."],
    }


class CandidatePreflightTests(unittest.TestCase):
    def test_json_receipt_retries_a_transient_windows_replace_collision(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.object(
            Path, "replace", side_effect=[PermissionError("busy"), None],
        ) as replace, patch("repository_kickoff.repository_kickoff.time.sleep") as pause:
            write_json(Path(directory) / "receipt.json", {"status": "running"})
        self.assertEqual(replace.call_count, 2)
        pause.assert_called_once()

    def test_long_horizon_structure_floor_requires_source_tests_ci_and_packaging(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src" / "package").mkdir(parents=True)
            (root / "tests").mkdir()
            (root / ".github" / "workflows").mkdir(parents=True)
            for index in range(8):
                (root / "src" / "package" / f"module_{index}.py").write_text("VALUE = 1\n", encoding="utf-8")
            for index in range(12):
                (root / "tests" / f"test_{index}.py").write_text("def test_value(): pass\n", encoding="utf-8")
            (root / ".github" / "workflows" / "tests.yml").write_text("name: tests\n", encoding="utf-8")
            (root / "pyproject.toml").write_text("[project]\nname='example'\n", encoding="utf-8")
            self.assertEqual(repository_structure_summary(root, 50)["status"], "passed")
            failed = repository_structure_summary(root, 49)
            self.assertEqual(failed["status"], "failed")
            self.assertIn("tracked_files<50", failed["failures"])

    def test_git_remote_head_parses_one_exact_branch_without_a_shell(self) -> None:
        completed = SimpleNamespace(
            returncode=0,
            stdout=f"{'a' * 40}\trefs/heads/main\n",
            stderr="",
        )
        with patch("repository_kickoff.repository_kickoff.subprocess.run", return_value=completed) as runner:
            self.assertEqual(git_remote_head("example/project", "main"), "a" * 40)
        arguments = runner.call_args.args[0]
        self.assertEqual(arguments[:3], ["git", "ls-remote", "--exit-code"])
        self.assertEqual(arguments[-1], "refs/heads/main")
        self.assertNotIn("shell", runner.call_args.kwargs)

    def test_git_remote_head_rejects_unsafe_branch_before_launch(self) -> None:
        with patch("repository_kickoff.repository_kickoff.subprocess.run") as runner:
            with self.assertRaisesRegex(KickoffError, "Invalid default branch"):
                git_remote_head("example/project", "main --upload-pack=evil")
        runner.assert_not_called()

    def test_preflight_uses_archives_and_advisory_scanning_without_tree_api_calls(self) -> None:
        items = []
        for index, (name, license_spdx) in enumerate((
            ("example/one", "MIT"), ("example/two", "Apache-2.0"),
        ), 1):
            items.append({
                "full_name": name,
                "html_url": f"https://github.com/{name}",
                "id": index,
                "node_id": f"R_{index}",
                "license": {"spdx_id": license_spdx},
                "fork": False,
                "archived": False,
                "language": "Python",
                "stargazers_count": 500 + index,
                "description": "Candidate",
                "topics": [],
                "default_branch": "main",
                "pushed_at": "2026-09-20T00:00:00Z",
                "size": index,
            })
        archive = {
            "archive_size_bytes": 100,
            "original_archive_sha256": ARCHIVE_SHA,
        }
        advisory_scan = clean_scan()
        advisory_scan.update({
            "status": "rejected",
            "counts": {
                **advisory_scan["counts"],
                "findings": 2,
                "by_category": {"secret": 1, "text_pii": 1},
                "by_disposition": {"reject": 1, "remediate": 1},
            },
            "findings": [
                {
                    "category": "secret", "severity": "high", "disposition": "reject",
                    "relative_path": "example.py", "detector": "credential", "fingerprint": "a" * 64,
                },
                {
                    "category": "text_pii", "severity": "medium", "disposition": "remediate",
                    "relative_path": "docs.md", "detector": "email", "fingerprint": "b" * 64,
                },
            ],
        })
        structure = {
            "tracked_file_count": 50,
            "source_python_files": 8,
            "test_python_files": 12,
            "total_python_files": 20,
            "ci_workflow_files": 1,
            "packaging_files": ["pyproject.toml"],
            "status": "passed",
            "failures": [],
        }
        progress = []
        with patch(
            "repository_kickoff.repository_kickoff.fetch_json", return_value={"items": items},
        ) as fetch, patch(
            "repository_kickoff.repository_kickoff.prior_candidate_names", return_value=[],
        ), patch(
            "repository_kickoff.repository_kickoff.git_remote_head",
            side_effect=lambda full_name, _branch: ("a" if full_name.endswith("/one") else "b") * 40,
        ), patch(
            "repository_kickoff.repository_kickoff.download_github_archive", return_value=archive,
        ) as download, patch(
            "repository_kickoff.repository_kickoff.safely_extract_archive",
            return_value=(Path("source"), {"file_count": 10}),
        ), patch(
            "repository_kickoff.repository_kickoff.repository_structure_summary",
            return_value=structure,
        ), patch(
            "repository_kickoff.repository_kickoff.scan_tree", return_value=advisory_scan,
        ) as scan, patch(
            "repository_kickoff.repository_kickoff.prepare_repository",
        ) as prepare:
            result = discover_preflight_candidates(
                set(), set(), target=2, max_inspections=2,
                progress_callback=progress.append,
                search_queries=("language:Python stars:>500",),
            )
        self.assertEqual([item["full_name"] for item in result["eligible_candidates"]], ["example/one", "example/two"])
        self.assertEqual(fetch.call_count, 1)
        self.assertEqual(download.call_count, 2)
        self.assertEqual(scan.call_count, 2)
        prepare.assert_not_called()
        self.assertEqual(result["rejected_candidates"], [])
        self.assertEqual(
            [item["content_safety_advisory"]["status"] for item in result["eligible_candidates"]],
            ["rejected", "rejected"],
        )
        self.assertTrue(all(
            item["content_safety_advisory"]["eligibility_effect"] == "none_during_candidate_discovery"
            for item in result["eligible_candidates"]
        ))
        self.assertEqual(progress[-1]["status"], "enough_candidates")


class RepositoryKickoffTests(unittest.TestCase):
    def setUp(self) -> None:
        preflight = patch(
            "repository_kickoff.repository_kickoff.discover_preflight_candidates",
            return_value=preflight_result(),
        )
        preflight.start()
        self.addCleanup(preflight.stop)
        ledger = patch(
            "repository_kickoff.repository_kickoff.load_ledger",
            return_value={"schema_version": 1, "repositories": []},
        )
        ledger.start()
        self.addCleanup(ledger.stop)

    def test_finder_result_accepts_fresh_eligible_repository(self) -> None:
        result = finder_result()
        self.assertIs(validate_finder_result(result, {"already/used"}), result)

    def test_repository_kickoff_defaults_to_sol_with_stage_specific_effort(self) -> None:
        arguments = parse_args([])
        self.assertEqual(arguments.finder_model, "gpt-5.6-sol")
        self.assertEqual(arguments.writer_model, "gpt-5.6-sol")
        self.assertEqual(arguments.finder_reasoning, "xhigh")
        self.assertEqual(arguments.writer_reasoning, "high")
        self.assertEqual(arguments.max_output_tokens, 40_000)

    def test_repository_handoff_embeds_risk_links_and_refuses_overwrite(self) -> None:
        selected = finder_result()["selected_repository"]
        selected.update({"full_name": "example/project", "url": "https://github.com/example/project", "review_status": "potential_pii"})
        selected["source_evidence"] = [
            {"claim": item["claim"], "url": item["url"].replace("example/fresh-python-project", "example/project")}
            for item in selected["source_evidence"]
        ]
        writer = writer_result(selected)
        writer["task"]["context"] = writer["task"]["context"].replace(
            "https://github.com/example/fresh-python-project", "https://github.com/example/project",
        )
        writer = validate_writer_result(writer, selected)
        report = (
            "# Content-safety findings: example/project\n\n"
            "- Review risk factor: high\n"
            f"- [Flagged file](https://github.com/example/project/blob/{COMMIT}/tests/test_api.py#L5)\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = publish_repository_handoff(selected, writer, report, Path(directory))
            self.assertEqual(path, (Path(directory) / "example" / "project" / "repository_kickoff.md").resolve())
            rendered = path.read_text(encoding="utf-8")
            self.assertIn("## Risk files", rendered)
            self.assertIn("Review risk factor: high", rendered)
            self.assertIn("## Engineering task", rendered)
            self.assertIn("# Expected Outcome", rendered)
            self.assertIn("tests/test_api.py#L5", rendered)
            self.assertNotIn("Why this opening works", rendered)
            self.assertNotIn("Opening approach", rendered)
            self.assertNotIn("Strongest alternative", rendered)
            self.assertNotIn("gpt-5.6-sol", rendered)
            self.assertEqual(publish_repository_handoff(selected, writer, report, Path(directory)), path)
            changed_writer = dict(writer)
            changed_writer["turn_one_prompt"] += "Changed.\n"
            with self.assertRaisesRegex(KickoffError, "Refusing to overwrite"):
                publish_repository_handoff(selected, changed_writer, report, Path(directory))
            unsafe = dict(selected)
            unsafe["full_name"] = "../project"
            with self.assertRaisesRegex(KickoffError, "Unsafe repository name"):
                publish_repository_handoff(unsafe, writer, report, Path(directory))

    def test_content_safety_markdown_links_every_flagged_file_without_fingerprints(self) -> None:
        report = clean_scan()
        report.update({
            "status": "rejected",
            "counts": {
                **report["counts"], "files_seen": 2, "files_scanned": 2, "findings": 3,
                "by_category": {"secret": 1, "text_pii": 2},
                "by_disposition": {"reject": 1, "remediate": 2},
            },
            "findings": [
                {
                    "category": "text_pii", "severity": "medium", "disposition": "remediate",
                    "relative_path": "docs/people.md", "detector": "email", "line": 7,
                    "fingerprint": "a" * 64,
                },
                {
                    "category": "text_pii", "severity": "medium", "disposition": "remediate",
                    "relative_path": "docs/people.md", "detector": "phone", "line": 11,
                    "fingerprint": "b" * 64,
                },
                {
                    "category": "secret", "severity": "critical", "disposition": "reject",
                    "relative_path": "examples/config.py", "detector": "known_token", "line": 3,
                    "fingerprint": "c" * 64,
                },
            ],
        })
        rendered = render_content_safety_findings_markdown(
            "example/project", COMMIT, report,
            preparation_status="rejected", prepared_scan_status=None,
        )
        self.assertIn(
            f"https://github.com/example/project/blob/{COMMIT}/docs/people.md#L7", rendered,
        )
        self.assertIn(
            f"https://github.com/example/project/blob/{COMMIT}/examples/config.py#L3", rendered,
        )
        self.assertIn("[L11]", rendered)
        self.assertIn("known_token", rendered)
        self.assertIn("Review risk factor: critical", rendered)
        self.assertNotIn("a" * 64, rendered)
        self.assertNotIn("b" * 64, rendered)
        self.assertNotIn("c" * 64, rendered)

    def test_selected_workflow_theme_may_expand_its_shortlist_summary(self) -> None:
        result = finder_result()
        result["selected_repository"]["workflow_theme"] = (
            "Trace the CLI request through parsing, execution, failure recovery, "
            "persistent state, and observable output."
        )
        self.assertIs(validate_finder_result(result, set()), result)

    def test_selected_factual_metadata_must_still_match_shortlist(self) -> None:
        result = finder_result()
        result["selected_repository"]["stars"] += 1
        with self.assertRaisesRegex(KickoffError, "field 'stars' disagrees"):
            validate_finder_result(result, set())

    def test_preverification_allows_noncanonical_model_metadata_for_authoritative_replacement(self) -> None:
        result = finder_result()
        result["selected_repository"].update({
            "stars": 1,
            "license_spdx": "model-guess",
            "pushed_at": "2026-09-active",
        })
        result["candidates_considered"][0].update({
            "stars": 2,
            "license_spdx": "another-guess",
            "pushed_at": "active recently",
        })
        result["candidates_considered"][1].update({
            "stars": -1,
            "license_spdx": "unknown",
            "pushed_at": "unknown",
        })
        self.assertIs(
            validate_finder_result(result, set(), authoritative_metadata=False),
            result,
        )
        with self.assertRaises(KickoffError):
            validate_finder_result(result, set())

    def test_preflight_allowlist_restricts_repository_and_commit(self) -> None:
        result = finder_result()
        allowlist = {
            candidate["full_name"].casefold(): candidate["commit_sha"]
            for candidate in result["candidates_considered"]
        }
        self.assertIs(
            validate_finder_result(
                result, set(), authoritative_metadata=False,
                candidate_allowlist=allowlist,
            ),
            result,
        )
        result["selected_repository"]["commit_sha"] = "d" * 40
        result["candidates_considered"][0]["commit_sha"] = "d" * 40
        with self.assertRaisesRegex(KickoffError, "preflight commit"):
            validate_finder_result(
                result, set(), authoritative_metadata=False,
                candidate_allowlist=allowlist,
            )

    def test_missing_selected_shortlist_record_is_reconstructed_from_dossier(self) -> None:
        result = finder_result()
        result["candidates_considered"] = [result["candidates_considered"][1]]
        self.assertIs(validate_finder_result(result, set()), result)
        self.assertEqual(len(result["candidates_considered"]), 2)
        self.assertEqual(
            result["candidates_considered"][0]["full_name"],
            result["selected_repository"]["full_name"],
        )

    def test_single_selected_candidate_still_fails_without_real_alternative(self) -> None:
        result = finder_result()
        result["candidates_considered"] = [result["candidates_considered"][0]]
        with self.assertRaisesRegex(KickoffError, "at least two candidates"):
            validate_finder_result(result, set())

    def test_empty_structured_output_has_actionable_budget_error(self) -> None:
        with self.assertRaisesRegex(KickoffError, "max_output_tokens"):
            parse_structured_output("", "repository_finder")

    def test_github_json_read_retries_interrupted_transfer(self) -> None:
        interrupted = MagicMock()
        interrupted.__enter__.return_value.read.side_effect = IncompleteRead(b"partial", 10)
        complete = MagicMock()
        complete.__enter__.return_value.read.return_value = b'{"items":[]}'
        with patch(
            "repository_kickoff.repository_kickoff.urlopen",
            side_effect=[interrupted, complete],
        ) as open_url, patch("repository_kickoff.repository_kickoff.time.sleep") as pause:
            self.assertEqual(fetch_json("https://api.github.com/search/repositories"), {"items": []})
        self.assertEqual(open_url.call_count, 2)
        pause.assert_called_once_with(0.5)

    def test_partial_json_at_output_cap_has_actionable_error_without_raw_content(self) -> None:
        partial = '{"url":"https://example.com/private-value"'
        with self.assertRaisesRegex(KickoffError, "exhausted max_output_tokens") as caught:
            parse_structured_output(
                partial, "repository_finder",
                usage={"output_tokens": 14_000, "reasoning_tokens": 12_289},
                max_output_tokens=14_000,
                response_status="incomplete", incomplete_reason="max_output_tokens",
            )
        self.assertNotIn("private-value", str(caught.exception))

    def test_incomplete_response_is_rejected_even_when_json_parses(self) -> None:
        with self.assertRaisesRegex(KickoffError, "did not complete"):
            parse_structured_output(
                "{}", "repository_finder", response_status="incomplete",
                incomplete_reason="unknown",
            )

    def test_star_rule_is_strictly_more_than_500_without_an_upper_bound(self) -> None:
        result = finder_result()
        result["selected_repository"]["stars"] = 500
        result["candidates_considered"][0]["stars"] = 500
        with self.assertRaisesRegex(KickoffError, "more than 500"):
            validate_finder_result(result, set())
        result = finder_result()
        result["selected_repository"]["stars"] = 5_000_000
        result["candidates_considered"][0]["stars"] = 5_000_000
        self.assertIs(validate_finder_result(result, set()), result)

    def test_long_horizon_gate_rejects_weak_or_disqualified_selection(self) -> None:
        result = finder_result()
        result["selected_repository"]["long_horizon_fit"]["boundary_chain"] = ["CLI", "service"]
        with self.assertRaisesRegex(KickoffError, "at least three named boundaries"):
            validate_finder_result(result, set())
        result = finder_result()
        result["selected_repository"]["long_horizon_fit"]["disqualifiers"] = ["Requires private service"]
        with self.assertRaisesRegex(KickoffError, "unresolved long-horizon disqualifiers"):
            validate_finder_result(result, set())

    def test_finder_result_rejects_used_repository(self) -> None:
        with self.assertRaisesRegex(KickoffError, "already-used"):
            validate_finder_result(finder_result(), {"example/fresh-python-project"})

    def test_writer_result_enforces_grounded_read_only_prompt(self) -> None:
        selected = finder_result()["selected_repository"]
        result = writer_result(selected)
        validated = validate_writer_result(result, selected)
        self.assertEqual(
            [line for line in validated["turn_one_prompt"].splitlines() if line.startswith("# ")],
            ["# Goal", "# Context", "# Scope", "# Expected Outcome", "# Guardrails"],
        )
        self.assertIn("current CLI implementation", validated["turn_one_prompt"])
        self.assertNotIn("why_opening_works", validated)

    def test_writer_requires_complete_structured_task(self) -> None:
        selected = finder_result()["selected_repository"]
        for field in ("goal", "context", "scope", "expected_outcome", "guardrails"):
            with self.subTest(field=field):
                result = writer_result(selected)
                del result["task"][field]
                with self.assertRaises(KickoffError):
                    validate_writer_result(result, selected)

    def test_writer_rejects_future_task_and_evaluation_framing(self) -> None:
        selected = finder_result()["selected_repository"]
        phrases = (
            "Recommend the next implementation slice.",
            "Propose the next best implementation.",
            "Establish a basis for later implementation.",
            "Describe the follow-on work.",
            "Define acceptance criteria for a future change.",
            "Optimize this for a coding-model evaluation.",
            "This is part of a long-horizon benchmark.",
            "Explain what the grader should reward.",
        )
        for phrase in phrases:
            with self.subTest(phrase=phrase):
                result = writer_result(selected)
                result["task"]["expected_outcome"].append(phrase)
                with self.assertRaisesRegex(KickoffError, "prohibited"):
                    validate_writer_result(result, selected)

    def test_writer_language_check_allows_repository_domain_terms(self) -> None:
        selected = finder_result()["selected_repository"]
        result = writer_result(selected)
        result["task"]["scope"].append(
            "Document the current implementation, trace the domain model through rule evaluation, "
            "and identify which state transition runs next when a Future object completes."
        )
        result["task"]["expected_outcome"].append(
            "State the acceptance criteria used to judge whether the current investigation is complete."
        )
        self.assertIn("Future object", validate_writer_result(result, selected)["turn_one_prompt"])

    def test_writer_dossier_keeps_engineering_risks_without_review_metadata(self) -> None:
        selected = finder_result()["selected_repository"]
        engineering_risk = "Partial writes can leave stored state inconsistent with CLI output."
        selected.update({
            "risks": [
                engineering_risk,
                "The advisory scan reported eight text-PII findings and one uninspectable file.",
                "The repository is not upload-ready while review is pending.",
            ],
            "screening_limitations": ["Manual content-risk review remains pending."],
            "source_scan_status": "manual_review_required",
            "risk_scan_status": "rejected",
            "review_status": "potential_pii",
            "prepared_repository": {"workspace_state": "sanitized_derivative"},
            "sanitized_paths": ["tests/test_api.py"],
        })
        dossier = writer_repository_dossier(selected)
        self.assertEqual(dossier["risks"], [engineering_risk])
        self.assertEqual(dossier["source_evidence"], selected["source_evidence"])
        for field in (
            "screening_limitations", "source_scan_status", "risk_scan_status",
            "review_status", "prepared_repository", "sanitized_paths",
        ):
            self.assertNotIn(field, dossier)

    def test_writer_rejects_sourcing_and_review_context_in_every_task_section(self) -> None:
        selected = finder_result()["selected_repository"]
        phrases = (
            "Manual content-risk review remains pending, so this repository must not be "
            "described as safety-reviewed or upload-ready.",
            "The content safety scan requires manual review.",
            "The workspace is a safety-sanitized derivative.",
            "Consult the linked content_safety_findings.md report.",
            "The repository is safe to upload.",
        )
        for field in ("goal", "context", "scope", "expected_outcome", "guardrails"):
            for phrase in phrases:
                with self.subTest(field=field, phrase=phrase):
                    result = writer_result(selected)
                    if isinstance(result["task"][field], list):
                        result["task"][field].append(phrase)
                    else:
                        result["task"][field] += " " + phrase
                    with self.assertRaisesRegex(KickoffError, "prohibited"):
                        validate_writer_result(result, selected)

    def test_writer_allows_engineering_review_and_secret_handling_guardrails(self) -> None:
        selected = finder_result()["selected_repository"]
        result = writer_result(selected)
        result["task"]["scope"].append(
            "Review the CLI error paths and identify whether credential handling can expose secrets in logs."
        )
        result["task"]["guardrails"].append(
            "Do not disclose, reconstruct, quote, or request secret or personal values."
        )
        self.assertIn("Review the CLI error paths", validate_writer_result(result, selected)["turn_one_prompt"])

    def test_finder_rejects_unpinned_or_unrelated_evidence(self) -> None:
        result = finder_result()
        result["selected_repository"]["source_evidence"][0]["url"] = (
            "https://github.com/example/fresh-python-project/blob/main/src/example/cli.py"
        )
        with self.assertRaisesRegex(KickoffError, "not pinned"):
            validate_finder_result(result, set())

    def test_finder_validates_every_compared_candidate(self) -> None:
        result = finder_result()
        result["candidates_considered"][1]["stars"] = -1
        with self.assertRaisesRegex(KickoffError, r"candidates_considered\[1\].*stars"):
            validate_finder_result(result, set())

    def test_writer_rejects_unrelated_citations(self) -> None:
        selected = finder_result()["selected_repository"]
        result = writer_result(selected)
        result["citations"][0]["url"] = "https://example.com/unrelated"
        with self.assertRaisesRegex(KickoffError, "GitHub HTTPS file URL"):
            validate_writer_result(result, selected)

    def test_sanitized_derivative_needs_no_prompt_disclosure_but_rejects_changed_citations(self) -> None:
        selected = finder_result()["selected_repository"]
        selected["prepared_repository"] = {
            "workspace_state": "sanitized_derivative", "safety_status": "sanitized_clean",
        }
        selected["sanitized_paths"] = []
        result = writer_result(selected)
        self.assertNotIn("sanitized derivative", validate_writer_result(result, selected)["turn_one_prompt"])
        selected["sanitized_paths"] = ["src/example/cli.py"]
        with self.assertRaisesRegex(KickoffError, "file changed by safety sanitization"):
            validate_writer_result(result, selected)

    def test_recent_opening_approach_requires_a_specific_reason(self) -> None:
        with self.assertRaisesRegex(KickoffError, "recently used"):
            validate_finder_result(finder_result(), set(), ["cross_boundary_contract"])
        result = finder_result()
        result["selected_repository"]["approach_reuse_reason"] = (
            "The CLI-to-store contract is the only approach supported by the inspected workflow."
        )
        self.assertIs(validate_finder_result(result, set(), ["cross_boundary_contract"]), result)

    def test_ledger_appends_only_validated_success(self) -> None:
        selected = finder_result()["selected_repository"]
        selected.update({
            "github_repository_id": 101,
            "github_node_id": "R_101",
            "activity_status": "recent",
            "source_scan_status": "clean",
            "risk_scan_status": "clean",
            "prepared_repository": {
                "upstream_commit_sha": COMMIT,
                "original_archive_sha256": ARCHIVE_SHA,
                "prepared_archive_sha256": "d" * 64,
                "workspace_state": "clean_upstream",
                "sanitization_manifest_sha256": "e" * 64,
                "safety_status": "clean",
            },
        })
        output = writer_result(selected)
        ledger = {"schema_version": 1, "repositories": []}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ledger.json"
            append_ledger(ledger, selected, output, "run-1", path, status="used_for_task", finding_count=0)
            saved = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(saved["repositories"][0]["full_name"], selected["full_name"])
        self.assertEqual(saved["repositories"][0]["status"], "used_for_task")
        self.assertEqual(saved["repositories"][0]["opening_approach"], "cross_boundary_contract")

    def test_registry_pending_status_can_be_manually_changed_without_certifying_archive(self) -> None:
        selected = finder_result()["selected_repository"]
        selected.update({
            "github_repository_id": 101,
            "github_node_id": "R_101",
            "activity_status": "recent",
            "source_scan_status": "rejected",
            "risk_scan_status": "rejected",
        })
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "registry.json"
            append_ledger(
                {"schema_version": 1, "repositories": []}, selected,
                writer_result(selected), "run-1", path,
                status="potential_pii", finding_count=3,
            )
            registry = load_ledger(path)
            entry = registry["repositories"][0]
            self.assertEqual(entry["status"], "potential_pii")
            self.assertEqual(entry["risk_report"], "outputs/run-1/content_safety_findings.md")
            self.assertNotIn("prepared_repository", entry)
            entry["status"] = "used_for_task"
            write_json(path, registry)
            self.assertEqual(load_ledger(path)["repositories"][0]["status"], "used_for_task")

    def test_validate_only_never_calls_model(self) -> None:
        arguments = argparse.Namespace(
            output_dir=Path("unused"), finder_model="gpt-5.6-sol", finder_reasoning="max",
            writer_model="gpt-5.6-sol", writer_reasoning="max", max_output_tokens=14_000,
            validate_only=True,
        )
        with patch("repository_kickoff.repository_kickoff.call_structured_stage") as call:
            self.assertIsNone(run(arguments))
            call.assert_not_called()

    def test_failed_run_records_the_precise_stage(self) -> None:
        selected_result = finder_result()
        finder_call = (json.dumps(selected_result), {"total_tokens": 10}, "finder-response", ["https://example.com"], {})
        cases = (
            ("repository_finder", [KickoffError("finder failed")], None),
            ("github_verification", [finder_call], KickoffError("verification failed")),
            (
                "turn_one_writer",
                [finder_call, KickoffError("writer failed")],
                {},
            ),
        )
        for expected_stage, model_result, verification_result in cases:
            with self.subTest(stage=expected_stage), tempfile.TemporaryDirectory() as directory:
                arguments = argparse.Namespace(
                    output_dir=Path(directory), finder_model="gpt-5.6-sol", finder_reasoning="max",
                    writer_model="gpt-5.6-sol", writer_reasoning="max", max_output_tokens=14_000,
                    validate_only=False,
                )
                with patch("repository_kickoff.repository_kickoff.call_structured_stage") as call, patch(
                    "repository_kickoff.repository_kickoff.verify_github_selection"
                ) as verify, patch(
                    "repository_kickoff.repository_kickoff.download_github_archive",
                    return_value={"archive_size_bytes": 100, "original_archive_sha256": ARCHIVE_SHA},
                ), patch(
                    "repository_kickoff.repository_kickoff.safely_extract_archive",
                    return_value=(Path(directory), {"file_count": 1}),
                ), patch(
                    "repository_kickoff.repository_kickoff.scan_tree", return_value=clean_scan(),
                ), patch(
                    "repository_kickoff.repository_kickoff.prepare_repository",
                    side_effect=lambda _source, output, **_kwargs: preparation_result(Path(output)),
                ):
                    call.side_effect = model_result
                    if isinstance(verification_result, Exception):
                        verify.side_effect = verification_result
                    else:
                        verify.return_value = verification_result
                    with self.assertRaises(KickoffError):
                        run(arguments)
                run_directory = next(Path(directory).iterdir())
                status = json.loads((run_directory / "status.json").read_text(encoding="utf-8"))
                self.assertEqual(status["status"], "failed")
                self.assertEqual(status["stage"], expected_stage)

    def test_paid_stage_receipt_survives_later_validation_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            arguments = parse_args([
                "--output-dir", directory,
                "--repository-dir", str(Path(directory) / "handoffs"),
            ])
            call_result = (
                json.dumps(finder_result()), {"total_tokens": 123}, "resp_paid",
                ["https://github.com/example/fresh-python-project"],
                {"response_status": "completed", "incomplete_reason": None},
            )
            with patch(
                "repository_kickoff.repository_kickoff.call_structured_stage", return_value=call_result,
            ), patch(
                "repository_kickoff.repository_kickoff.verify_github_selection",
                side_effect=KickoffError("verification failed"),
            ):
                with self.assertRaises(KickoffError):
                    run(arguments)
            run_directory = next(Path(directory).iterdir())
            receipt = json.loads((run_directory / "repository_finder_response.json").read_text(encoding="utf-8"))
            self.assertEqual(receipt["response_id"], "resp_paid")
            self.assertEqual(receipt["usage"]["total_tokens"], 123)
            self.assertEqual(receipt["web_sources"], ["https://github.com/example/fresh-python-project"])
            self.assertEqual(receipt["response_status"], "completed")
            self.assertEqual(receipt["max_output_tokens"], 40_000)

    def test_writer_continues_when_content_safety_rejects_upload(self) -> None:
        finder = finder_result()
        writer = writer_result(finder["selected_repository"])

        def verify(result: dict, _used_ids: set[int], preflight_candidates=None) -> dict:
            result["selected_repository"].update({
                "github_repository_id": 101,
                "github_node_id": "R_101",
                "activity_status": "recent",
                "activity_age_days": 17,
            })
            return {"selected_repository": result["selected_repository"], "verified_candidates": result["candidates_considered"]}

        rejected_scan = clean_scan()
        rejected_scan["status"] = "rejected"
        rejected_scan["findings"] = [{
            "category": "secret", "severity": "critical", "disposition": "reject",
            "relative_path": "tests/test_api.py", "detector": "secret_assignment", "fingerprint": "f" * 64,
        }]
        rejected_scan["counts"] = {
            **rejected_scan["counts"], "findings": 1,
            "by_category": {"secret": 1},
            "by_disposition": {"reject": 1},
        }
        with tempfile.TemporaryDirectory() as directory:
            arguments = argparse.Namespace(
                output_dir=Path(directory), finder_model="gpt-5.6-sol", finder_reasoning="max",
                writer_model="gpt-5.6-sol", writer_reasoning="max", max_output_tokens=14_000,
                validate_only=False,
            )
            finder_call = (json.dumps(finder), {"total_tokens": 100}, "finder-id", [], {})
            with patch(
                "repository_kickoff.repository_kickoff.call_structured_stage",
                side_effect=[finder_call, (json.dumps(writer), {"total_tokens": 75}, "writer-id", [], {})],
            ) as call, patch(
                "repository_kickoff.repository_kickoff.verify_github_selection", side_effect=verify,
            ), patch(
                "repository_kickoff.repository_kickoff.download_github_archive",
                return_value={"archive_size_bytes": 100, "original_archive_sha256": ARCHIVE_SHA},
            ), patch(
                "repository_kickoff.repository_kickoff.safely_extract_archive",
                return_value=(Path(directory), {"file_count": 1}),
            ), patch(
                "repository_kickoff.repository_kickoff.scan_tree", return_value=rejected_scan,
            ), patch(
                "repository_kickoff.repository_kickoff.prepare_repository",
            ) as prepare, patch("repository_kickoff.repository_kickoff.append_ledger") as append:
                result_path = run(arguments)
            self.assertEqual(call.call_count, 2)
            writer_payload = call.call_args_list[1].kwargs["payload"]
            self.assertNotIn("content_review", writer_payload)
            for field in ("source_scan_status", "risk_scan_status", "review_status", "prepared_repository"):
                self.assertNotIn(field, writer_payload["repository"])
            prepare.assert_not_called()
            append.assert_called_once()
            self.assertEqual(append.call_args.kwargs["status"], "potential_pii")
            run_directory = result_path.parent
            status = json.loads((run_directory / "status.json").read_text(encoding="utf-8"))
            self.assertEqual(status["status"], "completed")
            self.assertEqual(status["review_status"], "potential_pii")
            self.assertFalse(status["upload_ready"])
            handoff = Path(status["repository_handoff"])
            self.assertTrue(handoff.is_file())
            self.assertIn("## Risk files", handoff.read_text(encoding="utf-8"))
            self.assertTrue(result_path.is_file())
            self.assertFalse((run_directory / "upload_ready_repository.zip").exists())
            findings_markdown = (run_directory / "content_safety_findings.md").read_text(encoding="utf-8")
            self.assertIn(
                f"https://github.com/example/fresh-python-project/blob/{COMMIT}/tests/test_api.py",
                findings_markdown,
            )
            self.assertIn("critical", findings_markdown)
            self.assertIn("manual review required before upload", result_path.read_text(encoding="utf-8"))
            saved_writer = json.loads((run_directory / "writer_result.json").read_text(encoding="utf-8"))
            self.assertEqual(saved_writer["task"], writer["task"])
            for phrase in ("content-risk review", "upload-ready", "safety-reviewed", "content_safety_findings.md"):
                self.assertNotIn(phrase, saved_writer["turn_one_prompt"])

    def test_clean_source_with_flagged_prepared_rescan_still_gets_prompt(self) -> None:
        finder = finder_result()
        writer = writer_result(finder["selected_repository"])
        flagged = clean_scan()
        flagged["status"] = "manual_review_required"
        flagged["findings"] = [{
            "category": "uninspectable", "severity": "high", "disposition": "manual_review",
            "relative_path": "image.png", "detector": "opaque_file", "fingerprint": "f" * 64,
        }]
        flagged["counts"] = {
            **flagged["counts"], "findings": 1,
            "by_category": {"uninspectable": 1},
            "by_disposition": {"manual_review": 1},
        }

        def verify(result: dict, _used_ids: set[int], preflight_candidates=None) -> dict:
            result["selected_repository"].update({
                "github_repository_id": 101, "github_node_id": "R_101",
                "activity_status": "recent", "activity_age_days": 17,
            })
            return {"selected_repository": result["selected_repository"], "verified_candidates": result["candidates_considered"]}

        with tempfile.TemporaryDirectory() as directory:
            arguments = argparse.Namespace(
                output_dir=Path(directory), finder_model="gpt-5.6-sol", finder_reasoning="high",
                writer_model="gpt-5.6-sol", writer_reasoning="high", max_output_tokens=30_000,
                validate_only=False,
            )
            calls = [
                (json.dumps(finder), {"total_tokens": 10}, "finder-id", [], {}),
                (json.dumps(writer), {"total_tokens": 10}, "writer-id", [], {}),
            ]
            with patch(
                "repository_kickoff.repository_kickoff.call_structured_stage", side_effect=calls,
            ), patch(
                "repository_kickoff.repository_kickoff.verify_github_selection", side_effect=verify,
            ), patch(
                "repository_kickoff.repository_kickoff.download_github_archive",
                return_value={"archive_size_bytes": 100, "original_archive_sha256": ARCHIVE_SHA},
            ), patch(
                "repository_kickoff.repository_kickoff.safely_extract_archive",
                return_value=(Path(directory), {"file_count": 1}),
            ), patch(
                "repository_kickoff.repository_kickoff.scan_tree", return_value=clean_scan(),
            ), patch(
                "repository_kickoff.repository_kickoff.prepare_repository",
                return_value={"status": "manual_review_required", "final_report": flagged},
            ), patch("repository_kickoff.repository_kickoff.append_ledger") as append:
                result_path = run(arguments)
            self.assertIsNotNone(result_path)
            self.assertEqual(append.call_args.kwargs["status"], "potential_pii")
            status = json.loads((result_path.parent / "status.json").read_text(encoding="utf-8"))
            self.assertFalse(status["upload_ready"])
            self.assertFalse((result_path.parent / "upload_ready_repository.zip").exists())
            self.assertIn("image.png", (result_path.parent / "content_safety_findings.md").read_text(encoding="utf-8"))

    def test_successful_run_writes_both_receipts_and_result(self) -> None:
        finder = finder_result()
        writer = writer_result(finder["selected_repository"])

        def verify(result: dict, used_ids: set[int], preflight_candidates=None) -> dict:
            self.assertEqual(used_ids, set())
            selected = result["selected_repository"]
            selected.update({
                "github_repository_id": 101,
                "github_node_id": "R_101",
                "activity_status": "recent",
                "activity_age_days": 17,
            })
            return {
                "selected_repository": selected,
                "verified_candidates": result["candidates_considered"],
            }

        with tempfile.TemporaryDirectory() as directory:
            arguments = parse_args([
                "--output-dir", directory,
                "--repository-dir", str(Path(directory) / "handoffs"),
            ])
            calls = [
                (json.dumps(finder), {"total_tokens": 100}, "finder-id", ["https://example.com/finder"], {}),
                (json.dumps(writer), {"total_tokens": 200}, "writer-id", ["https://example.com/writer"], {}),
            ]
            with patch(
                "repository_kickoff.repository_kickoff.call_structured_stage", side_effect=calls,
            ) as model_call, patch(
                "repository_kickoff.repository_kickoff.verify_github_selection", side_effect=verify,
            ), patch(
                "repository_kickoff.repository_kickoff.download_github_archive",
                return_value={"archive_size_bytes": 100, "original_archive_sha256": ARCHIVE_SHA},
            ), patch(
                "repository_kickoff.repository_kickoff.safely_extract_archive",
                return_value=(Path(directory), {"file_count": 1}),
            ), patch(
                "repository_kickoff.repository_kickoff.scan_tree", return_value=clean_scan(),
            ), patch(
                "repository_kickoff.repository_kickoff.prepare_repository",
                side_effect=lambda _source, output, **_kwargs: preparation_result(Path(output)),
            ), patch("repository_kickoff.repository_kickoff.append_ledger") as append:
                result_path = run(arguments)
            self.assertIsNotNone(result_path)
            assert result_path is not None
            self.assertTrue(result_path.is_file())
            self.assertTrue((result_path.parent / "repository_finder_response.json").is_file())
            self.assertTrue((result_path.parent / "turn_one_writer_response.json").is_file())
            self.assertTrue((result_path.parent / "content_safety_findings.md").is_file())
            status = json.loads((result_path.parent / "status.json").read_text(encoding="utf-8"))
            self.assertEqual(status["status"], "completed")
            self.assertEqual(status["review_status"], "used_for_task")
            self.assertTrue(status["upload_ready"])
            handoff = Path(status["repository_handoff"])
            self.assertTrue(handoff.is_file())
            handoff_text = handoff.read_text(encoding="utf-8")
            self.assertIn("## Engineering task", handoff_text)
            self.assertIn("# Expected Outcome", handoff_text)
            self.assertNotIn("Why this opening works", handoff_text)
            self.assertNotIn("Opening approach", handoff_text)
            self.assertNotIn("Strongest alternative", handoff_text)
            self.assertNotIn("gpt-5.6-sol", handoff_text)
            writer_payload = model_call.call_args_list[1].kwargs["payload"]
            self.assertEqual(set(writer_payload), {"repository", "request"})
            self.assertNotIn("run_id", writer_payload)
            self.assertNotIn("selection_reason", writer_payload)
            self.assertNotIn("uncertainties", writer_payload)
            for hidden_field in (
                "opening_approach", "approach_reuse_reason", "long_horizon_fit",
                "screening_limitations", "source_scan_status", "risk_scan_status",
                "review_status", "prepared_repository", "sanitized_paths",
            ):
                self.assertNotIn(hidden_field, writer_payload["repository"])
            payload_text = json.dumps(writer_payload).casefold()
            for hidden_phrase in ("candidate comparison", "coding-model evaluation", "long-horizon", "grader", "token budget"):
                self.assertNotIn(hidden_phrase, payload_text)
            self.assertEqual(model_call.call_args_list[0].kwargs["model"], "gpt-5.6-sol")
            self.assertEqual(model_call.call_args_list[0].kwargs["reasoning_effort"], "xhigh")
            self.assertEqual(model_call.call_args_list[1].kwargs["model"], "gpt-5.6-sol")
            self.assertEqual(model_call.call_args_list[1].kwargs["reasoning_effort"], "high")
            self.assertEqual(model_call.call_args_list[0].kwargs["max_output_tokens"], 40_000)
            append.assert_called_once()
            self.assertEqual(append.call_args.kwargs["status"], "used_for_task")

    def test_saved_finder_receipt_can_be_reused_without_another_finder_call(self) -> None:
        finder = finder_result()
        writer = writer_result(finder["selected_repository"])

        def verify(result: dict, _used_ids: set[int], preflight_candidates=None) -> dict:
            selected = result["selected_repository"]
            selected.update({
                "github_repository_id": 101,
                "github_node_id": "R_101",
                "activity_status": "recent",
                "activity_age_days": 17,
            })
            return {"selected_repository": selected, "verified_candidates": result["candidates_considered"]}

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt_path = root / "saved_finder_response.json"
            receipt_path.write_text(json.dumps({
                "stage": "repository_finder",
                "model": "gpt-5.6-sol",
                "reasoning_effort": "high",
                "response_id": "saved-finder-id",
                "usage": {"total_tokens": 50},
                "web_sources": ["https://example.com/source"],
                "output_text": json.dumps(finder),
            }), encoding="utf-8")
            arguments = argparse.Namespace(
                output_dir=root / "runs", finder_model="gpt-5.6-sol", finder_reasoning="max",
                writer_model="gpt-5.6-sol", writer_reasoning="high", max_output_tokens=30_000,
                validate_only=False, reuse_finder_response=receipt_path,
            )
            writer_call = (json.dumps(writer), {"total_tokens": 75}, "writer-id", [], {})
            with patch(
                "repository_kickoff.repository_kickoff.call_structured_stage", return_value=writer_call,
            ) as call, patch(
                "repository_kickoff.repository_kickoff.verify_github_selection", side_effect=verify,
            ), patch(
                "repository_kickoff.repository_kickoff.download_github_archive",
                return_value={"archive_size_bytes": 100, "original_archive_sha256": ARCHIVE_SHA},
            ), patch(
                "repository_kickoff.repository_kickoff.safely_extract_archive",
                return_value=(root, {"file_count": 1}),
            ), patch(
                "repository_kickoff.repository_kickoff.scan_tree", return_value=clean_scan(),
            ), patch(
                "repository_kickoff.repository_kickoff.prepare_repository",
                side_effect=lambda _source, output, **_kwargs: preparation_result(Path(output)),
            ), patch("repository_kickoff.repository_kickoff.append_ledger"):
                result_path = run(arguments)
            self.assertIsNotNone(result_path)
            self.assertEqual(call.call_count, 1)
            self.assertEqual(call.call_args.kwargs["schema_name"], "turn_one_prompt_writer")
            copied = json.loads(
                (result_path.parent / "repository_finder_response.json").read_text(encoding="utf-8")
            )
            self.assertEqual(copied["response_id"], "saved-finder-id")
            self.assertEqual(copied["reused_from"], str(receipt_path.resolve()))

    def test_web_search_sources_are_extracted_and_deduplicated(self) -> None:
        response = SimpleNamespace(output=[
            SimpleNamespace(
                type="web_search_call",
                action=SimpleNamespace(sources=[
                    SimpleNamespace(url="https://example.com/b"),
                    SimpleNamespace(url="https://example.com/a"),
                    SimpleNamespace(url="https://example.com/a"),
                ]),
            ),
            SimpleNamespace(
                type="web_search_call",
                action=SimpleNamespace(url="https://example.com/opened"),
            ),
            SimpleNamespace(type="message"),
        ])
        self.assertEqual(
            response_web_sources(response),
            ["https://example.com/a", "https://example.com/b", "https://example.com/opened"],
        )

    def test_github_verification_covers_the_full_shortlist_and_stable_identity(self) -> None:
        result = finder_result()
        metadata = [
            {
                "private": False, "archived": False, "fork": False, "language": "Python",
                "stargazers_count": 510, "size": 10_100, "license": {"spdx_id": "MIT"},
                "topics": [], "full_name": "example/fresh-python-project",
                "html_url": "https://github.com/example/fresh-python-project", "description": "Useful",
                "default_branch": "main", "pushed_at": "2026-09-01T00:00:00Z", "id": 101, "node_id": "R_101",
            },
            {"sha": COMMIT},
            {
                "private": False, "archived": False, "fork": False, "language": "Python",
                "stargazers_count": 610, "size": 12_100, "license": {"spdx_id": "Apache-2.0"},
                "topics": [], "full_name": "example/alternative",
                "html_url": "https://github.com/example/alternative", "description": "Alternative",
                "default_branch": "main", "pushed_at": "2026-08-15T00:00:00Z", "id": 202, "node_id": "R_202",
            },
            {"sha": "c" * 40},
        ]
        with patch("repository_kickoff.repository_kickoff.fetch_json", side_effect=metadata):
            verification = verify_github_selection(result, set())
        self.assertEqual(result["selected_repository"]["github_repository_id"], 101)
        self.assertEqual(result["selected_repository"]["activity_status"], "recent")
        self.assertEqual([item["github_repository_id"] for item in result["candidates_considered"]], [101, 202])
        self.assertEqual(result["candidates_considered"][1]["commit_sha"], "c" * 40)
        self.assertEqual(result["candidates_considered"][1]["evidence_commit_sha"], "b" * 40)
        self.assertEqual(verification["verified_candidates"][1]["evidence_commit_sha"], "b" * 40)
        self.assertEqual(len(verification["verified_candidates"]), 2)
        self.assertIs(validate_finder_result(result, set()), result)

    def test_selected_evidence_commit_is_preserved_when_verified_head_moves(self) -> None:
        result = finder_result()
        metadata = [
            {
                "private": False, "archived": False, "fork": False, "language": "Python",
                "stargazers_count": 510, "size": 10_100, "license": {"spdx_id": "MIT"},
                "topics": [], "full_name": "example/fresh-python-project",
                "html_url": "https://github.com/example/fresh-python-project", "description": "Useful",
                "default_branch": "main", "pushed_at": "2026-09-01T00:00:00Z", "id": 101, "node_id": "R_101",
            },
            {"sha": "d" * 40},
            {
                "private": False, "archived": False, "fork": False, "language": "Python",
                "stargazers_count": 610, "size": 12_100, "license": {"spdx_id": "Apache-2.0"},
                "topics": [], "full_name": "example/alternative",
                "html_url": "https://github.com/example/alternative", "description": "Alternative",
                "default_branch": "main", "pushed_at": "2026-08-15T00:00:00Z", "id": 202, "node_id": "R_202",
            },
            {"sha": "b" * 40},
        ]
        with patch("repository_kickoff.repository_kickoff.fetch_json", side_effect=metadata):
            verify_github_selection(result, set())
        self.assertEqual(result["selected_repository"]["commit_sha"], "d" * 40)
        self.assertEqual(result["selected_repository"]["evidence_commit_sha"], COMMIT)
        self.assertIs(validate_finder_result(result, set()), result)

    def test_github_verification_rejects_a_used_repository_id(self) -> None:
        result = finder_result()
        metadata = {
            "private": False, "archived": False, "fork": False, "language": "Python",
            "stargazers_count": 501, "size": 10_000, "license": {"spdx_id": "MIT"},
            "topics": [], "full_name": "example/fresh-python-project",
            "html_url": "https://github.com/example/fresh-python-project", "description": "Useful",
            "default_branch": "main", "pushed_at": "2026-09-01T00:00:00Z", "id": 101, "node_id": "R_101",
        }
        with patch("repository_kickoff.repository_kickoff.fetch_json", side_effect=[metadata, {"sha": COMMIT}]):
            with self.assertRaisesRegex(KickoffError, "already used"):
                verify_github_selection(result, {101})

    def test_schemas_are_strict_at_every_object(self) -> None:
        def walk(node: object) -> None:
            if isinstance(node, dict):
                types = node.get("type")
                if types == "object" or isinstance(types, list) and "object" in types:
                    self.assertIs(node.get("additionalProperties"), False)
                    self.assertEqual(set(node.get("required", [])), set(node.get("properties", {})))
                for value in node.values():
                    walk(value)
            elif isinstance(node, list):
                for value in node:
                    walk(value)
        walk(finder_schema())
        walk(writer_schema())

    def test_distributed_registry_template_starts_empty(self) -> None:
        template = Path(__file__).resolve().parent / "data" / "used_repositories.example.json"
        ledger = load_ledger(template)
        self.assertEqual(ledger, {"schema_version": 1, "repositories": []})


if __name__ == "__main__":
    unittest.main()
