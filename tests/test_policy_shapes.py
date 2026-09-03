"""What common policy shapes actually produce, measured on real traffic.

A user who points this tool at a tag-scoped policy gets a wall of
INDETERMINATE and no actionable output at all. That is a designed boundary, not
a broken tool -- but only if the README says so, and it can only say so
honestly if the claim is measured rather than assumed.

These tests characterise the behaviour so the README's numbers stay true. They
also correct a plausible misreading of the design: the tool is deliberately
stricter than AWS about `Null`, `...IfExists` and `ForAllValues:`, and it would
be easy to conclude that strictness is what floods the output with unknowns. It
is not. Those operators resolve confidently whenever CloudTrail records the key
they test. The wall is caused by *tag* keys, which CloudTrail never records
under any operator.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest

from iam_replay.evaluate.engine import evaluate_mapped_request
from iam_replay.models import Verdict
from iam_replay.normalize.mapper import Mapper
from iam_replay.sources.files import FileEventSource

EVENTS_FILE = Path(__file__).parent / "fixtures" / "cloudtrail" / "live" / "workload_events.json"

pytestmark = pytest.mark.skipif(
    not EVENTS_FILE.exists(),
    reason="no captured workload events; see scripts/capture_live_events.py",
)


def allow_all(**condition) -> dict:
    statement = {"Effect": "Allow", "Action": "*", "Resource": "*"}
    if condition:
        statement["Condition"] = condition
    return {"Version": "2012-10-17", "Statement": [statement]}


def allow_all_with_deny_guard(**condition) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*"},
            {"Sid": "Guard", "Effect": "Deny", "Action": "*", "Resource": "*",
             "Condition": condition},
        ],
    }


@pytest.fixture(scope="module")
def requests():
    mapper = Mapper()
    return [
        request
        for record in FileEventSource(EVENTS_FILE).events()
        for request in mapper.map_event(record).requests
    ]


def verdicts(policy, requests) -> Counter:
    return Counter(evaluate_mapped_request(r, policy).verdict for r in requests)


def share(counts: Counter, verdict: Verdict) -> float:
    total = sum(counts.values())
    return counts[verdict] / total if total else 0.0


# --- the wall ----------------------------------------------------------------


def test_a_tag_scoped_policy_is_entirely_indeterminate(requests):
    """The headline finding, and the one the README has to state.

    ABAC policies conditioned on aws:ResourceTag are idiomatic and common. On
    real traffic, this tool can resolve exactly none of it -- CloudTrail records
    no tag on any event, so every call reaching such a statement is unknown.
    """
    counts = verdicts(allow_all(StringEquals={"aws:ResourceTag/Project": "acme"}), requests)

    assert share(counts, Verdict.INDETERMINATE) == 1.0
    assert counts[Verdict.ALLOW] == 0
    assert counts[Verdict.DENY] == 0


def test_the_lenient_if_exists_variant_is_no_better(requests):
    """Reaching for IfExists is the natural response to the wall above, and it
    does not help: the key is missing from the log, not from the request, and
    only the second would justify skipping the check."""
    counts = verdicts(
        allow_all(StringEqualsIfExists={"aws:ResourceTag/Project": "acme"}), requests
    )
    assert share(counts, Verdict.INDETERMINATE) == 1.0


def test_principal_and_request_tags_are_equally_unavailable(requests):
    for condition in (
        {"StringEquals": {"aws:PrincipalTag/team": "platform"}},
        {"StringEquals": {"aws:RequestTag/Project": "acme"}},
        {"ForAllValues:StringEquals": {"aws:TagKeys": "Project"}},
    ):
        counts = verdicts(allow_all(**condition), requests)
        assert share(counts, Verdict.INDETERMINATE) == 1.0, condition


# --- and where the strictness costs nothing ----------------------------------


def test_a_policy_with_no_conditions_resolves_completely(requests):
    counts = verdicts(allow_all(), requests)
    assert share(counts, Verdict.ALLOW) == 1.0


def test_the_tls_deny_guard_resolves_confidently(requests):
    """The S3 boilerplate. CloudTrail records tlsDetails, so aws:SecureTransport
    is known and the guard correctly does not fire -- no unknowns."""
    counts = verdicts(allow_all_with_deny_guard(Bool={"aws:SecureTransport": "false"}), requests)

    assert counts[Verdict.INDETERMINATE] == 0
    assert share(counts, Verdict.ALLOW) == 1.0


def test_the_mfa_deny_guard_resolves_confidently(requests):
    """IfExists against a key CloudTrail *does* record resolves normally. The
    workload runs without MFA, so the guard fires on everything -- a confident
    DENY, not an unknown."""
    counts = verdicts(
        allow_all_with_deny_guard(BoolIfExists={"aws:MultiFactorAuthPresent": "false"}),
        requests,
    )

    assert counts[Verdict.INDETERMINATE] == 0
    assert share(counts, Verdict.DENY) == 1.0


def test_region_scoping_resolves_completely(requests):
    """aws:RequestedRegion comes straight off the event."""
    counts = verdicts(allow_all(StringEquals={"aws:RequestedRegion": "us-east-1"}), requests)
    assert share(counts, Verdict.ALLOW) == 1.0


def test_the_strict_operators_are_not_what_causes_the_wall(requests):
    """The claim the README makes, pinned.

    If strictness about Null/IfExists were the cause, the MFA and TLS guards
    above would also be unknown. They are not. Tag unavailability is the whole
    of the effect.
    """
    tag_scoped = verdicts(allow_all(StringEquals={"aws:ResourceTag/Project": "acme"}), requests)
    if_exists_on_a_recorded_key = verdicts(
        allow_all_with_deny_guard(BoolIfExists={"aws:MultiFactorAuthPresent": "false"}), requests
    )

    assert share(tag_scoped, Verdict.INDETERMINATE) == 1.0
    assert share(if_exists_on_a_recorded_key, Verdict.INDETERMINATE) == 0.0


def test_report_policy_shape_outcomes(requests, capsys):
    """Prints the table the README quotes. Run with `pytest -s`."""
    shapes = {
        "no conditions": allow_all(),
        "tag-scoped (ABAC)": allow_all(StringEquals={"aws:ResourceTag/Project": "acme"}),
        "tag-scoped, IfExists": allow_all(
            StringEqualsIfExists={"aws:ResourceTag/Project": "acme"}
        ),
        "MFA deny guard": allow_all_with_deny_guard(
            BoolIfExists={"aws:MultiFactorAuthPresent": "false"}
        ),
        "TLS deny guard": allow_all_with_deny_guard(Bool={"aws:SecureTransport": "false"}),
        "region-scoped": allow_all(StringEquals={"aws:RequestedRegion": "us-east-1"}),
    }
    with capsys.disabled():
        print(f"\n  {'policy shape':<24} {'ALLOW':>6} {'DENY':>6} {'INDET':>6}")
        for name, policy in shapes.items():
            c = verdicts(policy, requests)
            print(
                f"  {name:<24} {c[Verdict.ALLOW]:>6} {c[Verdict.DENY]:>6} "
                f"{c[Verdict.INDETERMINATE]:>6}"
            )
