"""The ground-truth oracle -- the primary validation of the mapper (spec §9.1).

Every successful CloudTrail event was, by definition, authorized under the
policy in force at the time. So replaying the fixture workload's SUCCEEDED
events against that same policy must return ALLOW for every one of them. Any
DENY is a mapper bug: wrong action, wrong resource ARN, or a missing context
key. No exceptions, and no allowlist of known failures.

This is a stronger instrument than test_mapper.py, which can only check the
mapper against its author's beliefs about the mapping. Here the ground truth
comes from AWS having actually authorized the call.

**What it does not catch.** A mapping that is too *broad* still resolves to
ALLOW and passes silently, as does a missing context key the in-force policy
does not reference. The oracle proves the absence of false denies, not the
absence of false allows. The README must state this next to the number.

The events are a committed snapshot produced by scripts/capture_live_events.py,
so this runs offline and deterministically in CI. Regenerate it whenever the
fixture workload changes.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest

from iam_replay.evaluate.engine import evaluate_mapped_request
from iam_replay.models import Outcome, Reason, Verdict
from iam_replay.normalize.mapper import Mapper
from iam_replay.sources.files import FileEventSource

LIVE_DIR = Path(__file__).parent / "fixtures" / "cloudtrail" / "live"
EVENTS_FILE = LIVE_DIR / "workload_events.json"
BASELINE_POLICY = LIVE_DIR / "policy-tight-baseline.json"

pytestmark = pytest.mark.skipif(
    not EVENTS_FILE.exists() or not BASELINE_POLICY.exists(),
    reason=(
        "No captured workload events yet. Deploy terraform/, let the workload "
        "run, then: python scripts/capture_live_events.py --principal <role-arn>"
    ),
)


@pytest.fixture(scope="module")
def baseline_policy() -> dict:
    return json.loads(BASELINE_POLICY.read_text())


@pytest.fixture(scope="module")
def mapped_events():
    """Every captured event, mapped -- including the ones that produced no request."""
    mapper = Mapper()
    return [mapper.map_event(record) for record in FileEventSource(EVENTS_FILE).events()]


@pytest.fixture(scope="module")
def replayed(baseline_policy):
    """Map and evaluate every captured event once."""
    mapper = Mapper()
    results = []
    for record in FileEventSource(EVENTS_FILE).events():
        mapped = mapper.map_event(record)
        for request in mapped.requests:
            results.append((mapped, request, evaluate_mapped_request(request, baseline_policy)))
    return results


def test_the_snapshot_actually_contains_events(replayed):
    """A silently empty fixture would make every assertion below vacuous."""
    assert replayed, "captured snapshot produced no evaluable requests"


def test_no_successful_call_is_denied_by_the_policy_that_authorized_it(replayed):
    """THE oracle. Zero denies. No exception list, ever.

    A failure here is a mapper bug to fix, never a baseline to widen: widening
    policy-tight-baseline.json to make this pass is how the instrument silently
    loses its teeth.
    """
    failures = [
        (mapped.meta.event_name, request.action, request.resource_arn, decision.notes)
        for mapped, request, decision in replayed
        if mapped.meta.outcome is Outcome.SUCCEEDED and decision.verdict is Verdict.DENY
    ]

    assert not failures, "\n".join(
        f"  {event_name}: {action} on {resource} -- {notes}"
        for event_name, action, resource, notes in failures
    )


def test_the_baseline_is_tight_enough_to_have_teeth(replayed, baseline_policy):
    """The oracle's strength is proportional to how narrow the in-force policy is.

    Replayed against `s3:*` on `*`, everything allows and the test above proves
    nothing. This guards the instrument itself: no statement may pair a
    service-wide action wildcard with a `*` resource.
    """
    offenders = []
    for statement in baseline_policy.get("Statement", []):
        actions = statement.get("Action", [])
        actions = actions if isinstance(actions, list) else [actions]
        resources = statement.get("Resource", [])
        resources = resources if isinstance(resources, list) else [resources]

        if "*" not in resources:
            continue
        for action in actions:
            # `service:*` on `*` is the shape that makes the oracle toothless.
            # A named action on `*` is fine: many APIs have no resource-level
            # permissions at all.
            if action == "*" or action.endswith(":*"):
                offenders.append((statement.get("Sid"), action))

    assert not offenders, f"baseline is too broad to catch a mapper bug: {offenders}"


def test_every_allowlisted_service_the_workload_exercises_is_actually_mapped(replayed):
    """Catches a service silently falling out of the mappings: without this,
    deleting a mapping file would make the oracle pass by evaluating nothing."""
    from iam_replay.normalize.mapper import SERVICE_ALLOWLIST

    seen = {request.service for _, request, _ in replayed}
    assert seen, "no requests were produced at all"
    assert seen <= SERVICE_ALLOWLIST


def test_report_the_verdict_distribution(replayed, capsys):
    """Not an assertion -- prints the numbers the README quotes.

    Run with `pytest -s` to see it.
    """
    distribution = Counter(decision.verdict for _, _, decision in replayed)
    shapes = {(r.action, r.resource_arn) for _, r, _ in replayed}

    with capsys.disabled():
        print(f"\n  distinct authorization shapes: {len(shapes)}")
        for verdict, count in sorted(distribution.items(), key=lambda kv: kv[0].value):
            print(f"  {verdict.value:<15} {count}")


def test_indeterminates_name_the_key_that_defeated_them(replayed):
    """An INDETERMINATE with no explanation is not a useful answer."""
    for _, _, decision in replayed:
        if decision.verdict is not Verdict.INDETERMINATE:
            continue
        assert decision.reason is not None
        if decision.reason in (
            Reason.MISSING_CONDITION_KEY,
            Reason.NEVER_AVAILABLE_CONDITION_KEY,
        ):
            assert decision.unevaluable_keys


def test_no_allowlisted_service_event_is_left_unmapped(mapped_events):
    """The oracle alone cannot catch a missing mapping.

    An unmapped event produces no request, so it is silently skipped rather
    than denied -- it passes the oracle by not being evaluated at all. That is
    how a wrong event name hides: CloudTrail records Lambda calls under
    API-versioned names (GetFunction20150331v2), and a mapping written for
    "GetFunction" would look clean while covering nothing.

    Every event the fixture workload produces in an allowlisted service must
    therefore be mapped, with no silent skips.
    """
    from iam_replay.normalize.mapper import SERVICE_ALLOWLIST, service_from_event_source

    unmapped = sorted(
        {
            f"{mapped.meta.event_source} {mapped.meta.event_name}"
            for mapped in mapped_events
            if mapped.reason is Reason.UNMAPPED_EVENT
            and service_from_event_source(mapped.meta.event_source) in SERVICE_ALLOWLIST
        }
    )
    assert not unmapped, f"allowlisted-service events with no mapping: {unmapped}"


def test_the_workload_exercises_every_allowlisted_service(mapped_events):
    """Guards the instrument: if the workload stopped calling a service, that
    service's mappings would no longer be covered by the oracle at all, and the
    number in the README would quietly mean less than it says."""
    from iam_replay.normalize.mapper import SERVICE_ALLOWLIST, service_from_event_source

    exercised = {
        service_from_event_source(mapped.meta.event_source) for mapped in mapped_events
    }
    missing = SERVICE_ALLOWLIST - exercised
    assert not missing, f"workload no longer exercises: {sorted(missing)}"
