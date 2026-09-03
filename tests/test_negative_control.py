"""Negative controls -- the other half of the ground-truth oracle.

`test_ground_truth.py` proves the absence of false *denies*: every successful
call must be ALLOWed by the policy that authorized it. It structurally cannot
prove the absence of false *allows*, because a mapping that lands on the wrong
action still gets allowed whenever the baseline happens to grant that action
too.

The concrete miss: if `GetRole` were mapped to `iam:ListRoles` instead of
`iam:GetRole`, the baseline grants `iam:ListRoles` on `*`, so the positive
oracle returns ALLOW and passes silently.

A negative control catches it. For each (action, resource) pair **written
literally in the tight baseline**, replay the same captured traffic against a
policy that allows everything except that one pair:

    Allow  *        on *
    Deny   <action> on <resource>      <- the policy's own strings, not the mapper's

Every such pair must then deny at least one real request. If the mapper emits
the wrong action, or a bucket ARN where an object ARN belongs, or widens a
resource to `*`, the deny stops matching and the pair pins nothing.

Two properties fall out of one test:

* the mapper's output lands on the same (action, resource) a human wrote by
  hand, rather than merely on *something* the baseline happens to allow, and
* the baseline is minimal -- no permission in it is dead weight. That is the
  property the positive oracle needs in order to have any teeth at all, and
  until now it was assumed rather than demonstrated.

The denies are built from the policy, and the requests come from real AWS
traffic. Neither side is derived from the mapper, so the test is not circular.
No new AWS calls and no new spend: this is the same captured fixture the
positive oracle replays.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from iam_replay.evaluate.engine import evaluate_mapped_request
from iam_replay.models import Outcome, Verdict
from iam_replay.normalize.mapper import SERVICE_ALLOWLIST, Mapper
from iam_replay.sources.files import FileEventSource

LIVE = Path(__file__).parent / "fixtures" / "cloudtrail" / "live"
EVENTS_FILE = LIVE / "workload_events.json"
BASELINE_POLICY = LIVE / "policy-tight-baseline.json"

pytestmark = pytest.mark.skipif(
    not EVENTS_FILE.exists() or not BASELINE_POLICY.exists(),
    reason="no captured workload events; see scripts/capture_live_events.py",
)

#: Baseline permissions the workload genuinely uses but that CloudTrail does not
#: record, so no request can ever pin them.
#:
#: This is NOT an allowlist of known mapper failures -- the positive oracle
#: forbids those and so does this file. It is a documented property of
#: CloudTrail with exactly one member, and
#: `test_the_unrecorded_set_has_not_grown` fails if it ever gains another, so a
#: real mapper bug cannot be quietly parked here.
NOT_RECORDED_BY_CLOUDTRAIL = {
    "s3:ListBucket": (
        "ListObjectsV2 is a CloudTrail data event. The fixture workload calls it "
        "successfully on every run and it never reaches the trail, while every "
        "other bucket-level s3 call it makes does."
    ),
}


def _as_list(value):
    return value if isinstance(value, list) else [value]


def baseline_pairs(policy: dict) -> list[tuple[str, str, str]]:
    """Every (sid, action, resource) triple written literally in the policy.

    Restricted to the service allowlist: a `logs:` permission can never produce
    a request, so a control targeting it would pin nothing for reasons that say
    nothing about the mapper.
    """
    pairs: list[tuple[str, str, str]] = []
    for statement in policy["Statement"]:
        if statement.get("Effect") != "Allow":
            continue
        for action in _as_list(statement.get("Action", [])):
            if action.split(":", 1)[0] not in SERVICE_ALLOWLIST:
                continue
            for resource in _as_list(statement.get("Resource", [])):
                pairs.append((statement.get("Sid", "?"), action, resource))
    return pairs


def negative_control_policy(action: str, resource: str) -> dict:
    """Allow everything, then deny exactly the pair under test."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "AllowEverything", "Effect": "Allow", "Action": "*", "Resource": "*"},
            {
                "Sid": "NegativeControl",
                "Effect": "Deny",
                "Action": action,
                "Resource": resource,
            },
        ],
    }


@pytest.fixture(scope="module")
def policy() -> dict:
    return json.loads(BASELINE_POLICY.read_text())


@pytest.fixture(scope="module")
def requests_from_successful_calls():
    """Every request the captured successful traffic produces."""
    mapper = Mapper()
    out = []
    for record in FileEventSource(EVENTS_FILE).events():
        mapped = mapper.map_event(record)
        if mapped.meta.outcome is not Outcome.SUCCEEDED:
            continue
        for request in mapped.requests:
            out.append((mapped.meta.event_name, request))
    return out


def pinned_by(control: dict, requests) -> list[tuple[str, str, str | None]]:
    """Requests the control denies, via its NegativeControl statement."""
    hits = []
    for event_name, request in requests:
        decision = evaluate_mapped_request(request, control)
        if decision.verdict is Verdict.DENY and decision.matched_sid == "NegativeControl":
            hits.append((event_name, request.action, request.resource_arn))
    return hits


# --- the instrument ----------------------------------------------------------


def test_every_baseline_permission_pins_a_real_request(policy, requests_from_successful_calls):
    """THE negative control. Each hand-written permission must deny something.

    A pair that pins nothing means one of two things, and both are bugs worth
    failing on: the mapper is not producing the (action, resource) the human
    wrote for those calls, or the baseline carries a permission the workload
    does not need -- which would mean the positive oracle is running against a
    policy looser than it claims.
    """
    unpinned = []
    for sid, action, resource in baseline_pairs(policy):
        if action in NOT_RECORDED_BY_CLOUDTRAIL:
            continue
        control = negative_control_policy(action, resource)
        if not pinned_by(control, requests_from_successful_calls):
            unpinned.append(f"  {sid}: {action} on {resource}")

    assert not unpinned, (
        "baseline permissions that denied no real request:\n"
        + "\n".join(unpinned)
        + "\n\nEither the mapper emits a different action or resource for these "
        "calls than the baseline names, or the baseline grants something the "
        "workload never uses."
    )


def test_every_request_is_pinned_by_some_baseline_permission(
    policy, requests_from_successful_calls
):
    """The converse direction: no request floats free of the policy.

    A request that no baseline pair can deny is one the positive oracle allowed
    for some reason other than the permission that was written for it.
    """
    pinned: set[tuple[str, str | None]] = set()
    for _sid, action, resource in baseline_pairs(policy):
        control = negative_control_policy(action, resource)
        for _event, act, res in pinned_by(control, requests_from_successful_calls):
            pinned.add((act, res))

    everything = {(request.action, request.resource_arn) for _, request in requests_from_successful_calls}
    floating = sorted(everything - pinned)

    assert not floating, f"requests no baseline permission accounts for: {floating}"


def test_a_deliberately_wrong_action_is_caught(policy, requests_from_successful_calls):
    """Proves the instrument itself works, using the exact bug the positive
    oracle misses: iam:GetRole mapped to iam:ListRoles.

    The baseline grants iam:ListRoles on `*`, so that mapping sails through the
    positive oracle. Here the iam:GetRole control pins nothing, and the test
    above would fail -- which is the whole point.
    """
    from dataclasses import replace

    sabotaged = [
        (name, replace(request, action="iam:ListRoles", resource_arn="*"))
        if request.action == "iam:GetRole"
        else (name, request)
        for name, request in requests_from_successful_calls
    ]

    get_role_pair = next(
        (a, r) for _s, a, r in baseline_pairs(policy) if a == "iam:GetRole"
    )
    control = negative_control_policy(*get_role_pair)

    assert pinned_by(control, requests_from_successful_calls), "control should pin the real mapping"
    assert not pinned_by(control, sabotaged), "control failed to notice a wrong action"


def test_a_deliberately_widened_resource_is_caught(policy, requests_from_successful_calls):
    """The other family the positive oracle misses: a resource widened to `*`.

    A statement scoped to one bucket cannot deny a request whose resource is
    `*`, so the control stops firing.
    """
    from dataclasses import replace

    widened = [
        (name, replace(request, resource_arn="*"))
        if request.action == "s3:GetBucketVersioning"
        else (name, request)
        for name, request in requests_from_successful_calls
    ]

    pair = next(
        (a, r) for _s, a, r in baseline_pairs(policy) if a == "s3:GetBucketVersioning"
    )
    control = negative_control_policy(*pair)

    assert pinned_by(control, requests_from_successful_calls)
    assert not pinned_by(control, widened), "control failed to notice a widened resource"


def test_the_unrecorded_set_has_not_grown():
    """Guards the one exemption.

    NOT_RECORDED_BY_CLOUDTRAIL exists for a documented CloudTrail behaviour, not
    for mapper bugs. If it ever gains a member, that is a decision someone has
    to make deliberately rather than by adding a line to get a test green.
    """
    assert set(NOT_RECORDED_BY_CLOUDTRAIL) == {"s3:ListBucket"}


def test_report_negative_control_coverage(policy, requests_from_successful_calls, capsys):
    """Prints what each control pinned. Run with `pytest -s`."""
    with capsys.disabled():
        print("\n  negative control — each baseline permission vs. real traffic:")
        for sid, action, resource in baseline_pairs(policy):
            if action in NOT_RECORDED_BY_CLOUDTRAIL:
                print(f"    {action:<30} — not recorded by CloudTrail (data event)")
                continue
            hits = pinned_by(negative_control_policy(action, resource), requests_from_successful_calls)
            events = sorted({event for event, _, _ in hits})
            print(f"    {action:<30} pins {len(hits):>2} requests  {', '.join(events)}")
