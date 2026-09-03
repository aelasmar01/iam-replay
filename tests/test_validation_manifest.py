"""The oracle-backed mapping manifest, and its runtime reporting.

The manifest is the claim "these mappings have met real AWS traffic". It is
shipped in the wheel and printed on every run, so it has to be kept honest by
tests rather than by whoever last remembered to regenerate it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from iam_replay.normalize import validation

LIVE = Path(__file__).parent / "fixtures" / "cloudtrail" / "live"
EVENTS_FILE = LIVE / "workload_events.json"
BASELINE_POLICY = LIVE / "policy-tight-baseline.json"


def test_the_manifest_ships_with_the_package():
    assert validation.MANIFEST_PATH.exists()
    assert validation.validated_total() > 0


def test_declared_totals_match_the_actual_mapping_files(mapper):
    """A stale total would misstate the denominator in every report."""
    manifest = json.loads(validation.MANIFEST_PATH.read_text())
    actual = {service: len(events) for service, events in mapper._mappings.items()}
    assert manifest["declared_totals"] == actual


def test_every_validated_pair_is_a_real_mapping(mapper):
    """A manifest entry naming an event that no longer exists would credit the
    run with validation it does not have."""
    for service, event_name in validation.validated_pairs():
        assert service in mapper._mappings, service
        assert event_name in mapper._mappings[service], f"{service}:{event_name}"


def test_sts_assume_role_is_now_validated():
    """It was the most-relied-on mapping with nothing behind it. The fixture
    workload now assumes a real second role, so it has real coverage."""
    assert validation.is_validated("sts", "AssumeRole")


def test_unvalidated_mappings_are_reported_as_such():
    """ec2:RunInstances remains asserted rather than tested: validating it means
    launching a real instance, which is deliberately out of scope."""
    assert not validation.is_validated("ec2", "RunInstances")
    assert not validation.is_validated("iam", "CreateRole")
    assert not validation.is_validated(None, "GetRole")


@pytest.mark.skipif(
    not EVENTS_FILE.exists() or not BASELINE_POLICY.exists(),
    reason="no captured workload events; see scripts/capture_live_events.py",
)
def test_the_manifest_matches_what_the_fixture_actually_validates():
    """Regenerating must be a no-op. If this fails, the fixture changed and
    `python scripts/refresh_validation_manifest.py` needs rerunning -- the
    manifest must never claim more than the oracle currently proves.
    """
    from iam_replay.evaluate.engine import evaluate_mapped_request
    from iam_replay.models import Outcome, Verdict
    from iam_replay.normalize.mapper import Mapper
    from iam_replay.sources.files import FileEventSource

    from .test_negative_control import baseline_pairs, negative_control_policy

    baseline = json.loads(BASELINE_POLICY.read_text())
    mapper = Mapper()

    successful = []
    for record in FileEventSource(EVENTS_FILE).events():
        mapped = mapper.map_event(record)
        if mapped.meta.outcome is not Outcome.SUCCEEDED:
            continue
        service = mapped.meta.event_source.split(".", 1)[0]
        for request in mapped.requests:
            successful.append((service, mapped.meta.event_name, request))

    allowed = {
        (s, e)
        for s, e, r in successful
        if evaluate_mapped_request(r, baseline).verdict is Verdict.ALLOW
    }
    pinned = set()
    for _sid, action, resource in baseline_pairs(baseline):
        control = negative_control_policy(action, resource)
        for s, e, r in successful:
            decision = evaluate_mapped_request(r, control)
            if decision.verdict is Verdict.DENY and decision.matched_sid == "NegativeControl":
                pinned.add((s, e))

    assert validation.validated_pairs() == frozenset(allowed & pinned)


def test_a_missing_manifest_does_not_break_a_replay(monkeypatch, tmp_path):
    """Nothing is known to be validated, which is the cautious answer -- but the
    tool must still run."""
    monkeypatch.setattr(validation, "MANIFEST_PATH", tmp_path / "absent.json")
    validation._manifest.cache_clear()
    validation.validated_pairs.cache_clear()

    assert validation.validated_pairs() == frozenset()
    assert validation.validated_total() == 0
    assert not validation.is_validated("iam", "GetRole")

    validation._manifest.cache_clear()
    validation.validated_pairs.cache_clear()


def test_a_corrupt_manifest_does_not_break_a_replay(monkeypatch, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    monkeypatch.setattr(validation, "MANIFEST_PATH", bad)
    validation._manifest.cache_clear()
    validation.validated_pairs.cache_clear()

    assert validation.validated_pairs() == frozenset()

    validation._manifest.cache_clear()
    validation.validated_pairs.cache_clear()
