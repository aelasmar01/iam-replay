"""CLI behaviour and exit codes (spec §8, milestone 5).

Exit codes carry meaning in CI: 1 means the tool worked and found something,
2 means the tool did not work and nothing it printed should be believed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from iam_replay.cli import EXIT_GATE_TRIPPED, EXIT_OK, EXIT_TOOL_ERROR, main

FIXTURES = Path(__file__).parent / "fixtures" / "cloudtrail"
LIVE = FIXTURES / "live" / "workload_events.json"
BASELINE = FIXTURES / "live" / "policy-tight-baseline.json"
PRINCIPAL = "arn:aws:iam::123456789012:role/iam-replay-fixture-workload"

pytestmark = pytest.mark.skipif(
    not LIVE.exists() or not BASELINE.exists(),
    reason="no captured workload events; see scripts/capture_live_events.py",
)


@pytest.fixture
def runner():
    return CliRunner()


def run(runner, *extra, policy=None):
    return runner.invoke(
        main,
        [
            "--principal", PRINCIPAL,
            "--policy", str(policy or BASELINE),
            "--source", "files",
            "--path", str(LIVE),
            "--days", "3650",
            *extra,
        ],
    )


def write_policy(tmp_path: Path, document: dict) -> Path:
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(document))
    return path


def test_baseline_replay_reports_no_denies(runner):
    result = run(runner)
    assert result.exit_code == EXIT_OK
    assert "WOULD DENY  (0)" in result.output


def test_the_analyzed_window_is_always_printed(runner):
    """Not only when it differs from the request: a 90-day claim over twelve
    days of data is invisible unless stated unconditionally."""
    result = run(runner)
    assert "Window requested:" in result.output
    assert "Window analyzed:" in result.output


def test_caveats_are_printed_every_run(runner):
    result = run(runner)
    assert "Data events" in result.output
    assert "identity-based policies" in result.output


def test_a_denying_policy_trips_the_deny_gate(runner, tmp_path):
    policy = write_policy(tmp_path, {"Statement": [
        {"Effect": "Allow", "Action": "iam:ListRoles", "Resource": "*"}
    ]})

    assert run(runner, policy=policy).exit_code == EXIT_OK
    assert run(runner, "--fail-on-deny", policy=policy).exit_code == EXIT_GATE_TRIPPED


def test_the_indeterminate_gate_is_independent_of_the_deny_gate(runner, tmp_path):
    policy = write_policy(tmp_path, {"Statement": [
        {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*",
            "Condition": {"StringEquals": {"aws:ResourceTag/Project": "iam-replay"}},
        }
    ]})

    result = run(runner, "--fail-on-indeterminate", policy=policy)
    assert result.exit_code == EXIT_GATE_TRIPPED
    assert "INDETERMINATE" in result.output


def test_a_clean_run_passes_both_gates(runner):
    assert run(runner, "--fail-on-deny", "--fail-on-indeterminate").exit_code == EXIT_OK


def test_missing_policy_file_is_a_tool_error(runner):
    result = run(runner, policy=Path("/nonexistent/policy.json"))
    assert result.exit_code == EXIT_TOOL_ERROR
    assert "not found" in result.output


def test_malformed_policy_is_a_tool_error(runner, tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json")
    result = run(runner, policy=path)
    assert result.exit_code == EXIT_TOOL_ERROR
    assert "not valid JSON" in result.output


def test_a_json_document_that_is_not_a_policy_is_rejected(runner, tmp_path):
    """Better than replaying against an empty statement list and reporting that
    everything would break."""
    path = tmp_path / "notapolicy.json"
    path.write_text(json.dumps({"hello": "world"}))
    result = run(runner, policy=path)
    assert result.exit_code == EXIT_TOOL_ERROR
    assert "does not look like an IAM policy" in result.output


def test_missing_source_path_is_a_tool_error(runner):
    result = runner.invoke(main, [
        "--principal", PRINCIPAL, "--policy", str(BASELINE),
        "--source", "files", "--path", "/nonexistent/dir",
    ])
    assert result.exit_code == EXIT_TOOL_ERROR


def test_files_source_without_a_path_is_a_tool_error(runner):
    result = runner.invoke(main, [
        "--principal", PRINCIPAL, "--policy", str(BASELINE), "--source", "files",
    ])
    assert result.exit_code == EXIT_TOOL_ERROR
    assert "requires --path" in result.output


def test_lookup_beyond_ninety_days_is_a_tool_error_naming_the_way_out(runner):
    result = runner.invoke(main, [
        "--principal", PRINCIPAL, "--policy", str(BASELINE),
        "--source", "lookup", "--days", "120",
    ])
    assert result.exit_code == EXIT_TOOL_ERROR
    assert "--source files" in result.output


def test_days_below_one_is_a_tool_error(runner):
    assert run(runner, "--days", "0").exit_code == EXIT_TOOL_ERROR


def test_json_output_carries_the_stable_schema(runner):
    result = run(runner, "--format", "json")
    assert result.exit_code == EXIT_OK

    document = json.loads(result.output)
    assert document["schema_version"]
    assert document["window"]["analyzed_days"] >= 0
    assert "analyzed_start" in document["window"]
    assert set(document["summary"]) == {"DENY", "INDETERMINATE", "ALLOW", "new_access"}
    assert document["counts"]["succeeded"] > 0
    assert document["caveats"]


def test_json_output_lists_allows_rather_than_collapsing_them(runner):
    """The JSON is the audit artifact, so it does not summarise the way the
    table does."""
    document = json.loads(run(runner, "--format", "json").output)
    assert document["would_allow"]
    assert document["would_allow"][0]["action"]
    assert document["would_allow"][0]["count"] >= 1


def test_a_session_arn_is_accepted_as_the_principal(runner):
    result = runner.invoke(main, [
        "--principal", "arn:aws:sts::123456789012:assumed-role/iam-replay-fixture-workload/x",
        "--policy", str(BASELINE), "--source", "files", "--path", str(LIVE), "--days", "3650",
    ])
    assert result.exit_code == EXIT_OK
    assert "WOULD DENY  (0)" in result.output


def test_an_unrelated_principal_matches_nothing(runner):
    result = runner.invoke(main, [
        "--principal", "arn:aws:iam::123456789012:role/SomeOtherRole",
        "--policy", str(BASELINE), "--source", "files", "--path", str(LIVE), "--days", "3650",
        "--format", "json",
    ])
    assert result.exit_code == EXIT_OK
    document = json.loads(result.output)
    assert document["counts"]["events_for_principal"] == 0
    assert document["counts"]["events_scanned"] > 0


def test_verbose_lists_the_allows(runner):
    assert "Use --verbose" in run(runner).output
    assert "Use --verbose" not in run(runner, "--verbose").output


def test_a_boundary_intersects_the_candidate(runner, tmp_path):
    boundary = write_policy(tmp_path, {"Statement": [
        {"Effect": "Allow", "Action": "iam:ListRoles", "Resource": "*"}
    ]})
    result = run(runner, "--boundary", str(boundary), "--fail-on-deny")
    assert result.exit_code == EXIT_GATE_TRIPPED


# --- mapping provenance ------------------------------------------------------


def test_mapping_provenance_is_printed_on_every_run(runner):
    """Same move as the analyzed window: a caveat someone might skip becomes a
    number in the header they cannot avoid."""
    result = run(runner)
    assert "Mapping provenance:" in result.output
    assert "oracle-backed" in result.output


def test_provenance_names_the_untested_mappings_in_json(runner):
    document = json.loads(run(runner, "--format", "json").output)
    provenance = document["mapping_provenance"]

    assert provenance["mappings_used"] > 0
    assert provenance["oracle_backed"] + provenance["asserted"] == provenance["mappings_used"]
    assert len(provenance["asserted_mappings"]) == provenance["asserted"]


def test_a_run_leaning_on_untested_mappings_says_so(runner, tmp_path, monkeypatch):
    """The case that matters: a production role touching mappings the oracle has
    never covered must surface both the count and a caveat."""
    from iam_replay.normalize import validation

    monkeypatch.setattr(validation, "MANIFEST_PATH", tmp_path / "absent.json")
    validation._manifest.cache_clear()
    validation.validated_pairs.cache_clear()

    # rich hard-wraps the header, so compare against whitespace-collapsed output
    flat = " ".join(run(runner).output.split())
    assert "asserted, never tested against AWS" in flat
    assert "never been checked against real AWS traffic" in flat

    validation._manifest.cache_clear()
    validation.validated_pairs.cache_clear()


def test_the_json_schema_declares_every_reason_value(runner):
    """A consumer switching on `reason` should be able to validate against the
    contract rather than infer it from whatever a sample run happened to emit."""
    from iam_replay.models import Reason

    document = json.loads(run(runner, "--format", "json").output)

    assert document["schema_version"] == "1.1.0"
    assert set(document["reason_values"]) == {r.value for r in Reason}
    assert "resource_policy_unevaluable" in document["reason_values"]


def test_gates_under_the_resource_policy_distribution(runner, tmp_path):
    """Calls that used to be a confident DENY on s3 are now INDETERMINATE, so
    --fail-on-deny alone would let them through. --fail-on-indeterminate is what
    catches them, and both must still work."""
    policy = write_policy(tmp_path, {"Statement": [
        {"Effect": "Allow", "Action": "iam:ListRoles", "Resource": "*"}
    ]})

    output = run(runner, "--format", "json", policy=policy).output
    document = json.loads(output)
    reasons = {entry["reason"] for entry in document["indeterminate"]}
    assert "resource_policy_unevaluable" in reasons

    # s3/kms/lambda calls land in INDETERMINATE; iam/ec2 calls still in DENY.
    assert document["summary"]["DENY"] > 0
    assert run(runner, "--fail-on-deny", policy=policy).exit_code == EXIT_GATE_TRIPPED
    assert run(runner, "--fail-on-indeterminate", policy=policy).exit_code == EXIT_GATE_TRIPPED


# --- unmapped events (item 2) ------------------------------------------------

EDGE = FIXTURES / "edge_cases.json"
EDGE_PRINCIPAL = "arn:aws:iam::123456789012:role/service-role/DeployRole"


def run_edge(runner, *extra, fmt=None):
    """The edge-case fixture holds an unmapped event from a supported service
    (s3 GetBucketInventoryConfiguration) alongside an unsupported-service event
    (dynamodb), which is exactly the pair that must not be conflated."""
    args = [
        "--principal", EDGE_PRINCIPAL,
        "--policy", str(BASELINE),
        "--source", "files", "--path", str(EDGE),
        "--days", "3650",
        *extra,
    ]
    if fmt:
        args += ["--format", fmt]
    return runner.invoke(main, args)


def test_unmapped_events_are_reported_in_the_header(runner):
    """A user can otherwise see WOULD DENY (0) on a role whose most interesting
    calls never reached the evaluator at all."""
    flat = " ".join(run_edge(runner).output.split())
    assert "unmapped events:" in flat
    assert "distinct event name" in flat


def test_the_unmapped_line_prints_even_when_zero(runner):
    """Same reasoning as the analyzed window: a number that only appears when
    it is bad is a number nobody learns to look for."""
    flat = " ".join(run(runner).output.split())
    assert "unmapped events: 0" in flat


def test_unmapped_and_unsupported_are_counted_separately(runner):
    """Two different statements. 'I have no mapping for this call' and 'this
    service is out of scope' must not be merged into one number."""
    document = json.loads(run_edge(runner, fmt="json").output)

    unmapped = document["unmapped"]
    assert unmapped["total_events"] >= 1
    names = {entry["event"] for entry in unmapped["events"]}
    assert "GetBucketInventoryConfiguration" in names
    # dynamodb is out of scope, not unmapped -- it must not appear here.
    assert not any(entry["service"] == "dynamodb" for entry in unmapped["events"])
    assert document["counts"]["not_evaluated"]["unsupported_service"] >= 1


def test_json_lists_each_unmapped_event_with_its_count(runner):
    document = json.loads(run_edge(runner, fmt="json").output)
    entry = next(
        e for e in document["unmapped"]["events"]
        if e["event"] == "GetBucketInventoryConfiguration"
    )
    assert entry["service"] == "s3"
    assert entry["count"] >= 1


def test_unmapped_events_raise_a_caveat(runner):
    document = json.loads(run_edge(runner, fmt="json").output)
    assert any("no mapping" in caveat for caveat in document["caveats"])


def test_no_unmapped_caveat_when_there_are_none(runner):
    document = json.loads(run(runner, "--format", "json").output)
    assert document["unmapped"]["total_events"] == 0
    assert not any("no mapping" in caveat for caveat in document["caveats"])


def test_verbose_lists_the_distinct_unmapped_event_names(runner):
    """The caveat names them either way -- that is the point of a caveat. What
    --verbose adds is the per-event breakdown in its own section."""
    plain = run_edge(runner).output
    verbose = run_edge(runner, "--verbose").output

    assert "GetBucketInventoryConfiguration" in plain  # named in the caveat
    assert "UNMAPPED EVENTS" not in plain
    assert "UNMAPPED EVENTS" in verbose
    assert "s3:GetBucketInventoryConfiguration" in verbose
