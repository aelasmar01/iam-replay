"""Deduplication into distinct authorization shapes (spec §8, milestone 5)."""

from __future__ import annotations

from datetime import datetime, timezone

from iam_replay.dedupe import SAMPLE_LIMIT, deduplicate, split_by_outcome
from iam_replay.models import (
    AuthorizationRequest,
    Confidence,
    EventMeta,
    MappedEvent,
    Outcome,
    freeze_context,
)

ROLE = "arn:aws:iam::123456789012:role/DeployRole"


def event(
    action: str = "s3:ListBucket",
    resource: str = "arn:aws:s3:::b",
    day: int = 1,
    event_id: str = "e1",
    outcome: Outcome = Outcome.SUCCEEDED,
    confidence: Confidence = Confidence.EXACT,
    notes: tuple[str, ...] = (),
    **context: str,
) -> MappedEvent:
    meta = EventMeta(
        event_id=event_id,
        event_time=datetime(2026, 9, day, tzinfo=timezone.utc),
        event_name="ListObjectsV2",
        event_source="s3.amazonaws.com",
        aws_region="us-east-1",
        outcome=outcome,
    )
    request = AuthorizationRequest(
        principal_arn=ROLE,
        action=action,
        resource_arn=resource,
        context=freeze_context({"aws:PrincipalArn": ROLE, **context}),
        confidence=confidence,
        notes=notes,
    )
    return MappedEvent(meta, requests=(request,), principal_arn=ROLE)


def test_identical_shapes_collapse_with_a_count():
    groups = deduplicate([event(event_id=f"e{i}") for i in range(5)])
    assert len(groups) == 1
    assert groups[0].count == 5


def test_different_resources_stay_separate():
    groups = deduplicate([event(resource="arn:aws:s3:::a"), event(resource="arn:aws:s3:::b")])
    assert len(groups) == 2


def test_first_and_last_seen_span_the_group():
    groups = deduplicate([event(day=5), event(day=1), event(day=9)])
    assert groups[0].first_seen.day == 1
    assert groups[0].last_seen.day == 9


def test_sample_event_ids_are_capped():
    groups = deduplicate([event(event_id=f"e{i}") for i in range(20)])
    assert len(groups[0].sample_event_ids) == SAMPLE_LIMIT


def test_groups_are_ordered_by_call_count_descending():
    events = [event(resource="arn:aws:s3:::rare")]
    events += [event(resource="arn:aws:s3:::common") for _ in range(10)]
    groups = deduplicate(events)
    assert groups[0].request.resource_arn.endswith("common")
    assert groups[0].count == 10


def test_context_the_policy_never_reads_does_not_split_a_group():
    """The readability fix that matters in practice: two Lambda containers make
    the same call from different source IPs with different user agents. Those
    are the same authorization shape, and evaluation reads neither key."""
    events = [
        event(**{"aws:SourceIp": "203.0.113.1", "aws:UserAgent": "boto3/1.0"}),
        event(**{"aws:SourceIp": "203.0.113.2", "aws:UserAgent": "aws-sdk-java/2.0"}),
    ]

    relevant = frozenset({"aws:PrincipalArn"})
    assert len(deduplicate(events, relevant)) == 1

    # With no key set supplied, every key counts -- the conservative default.
    assert len(deduplicate(events)) == 2


def test_context_the_policy_does_read_still_splits_a_group():
    """Collapsing these would merge requests that can evaluate differently."""
    events = [
        event(**{"aws:RequestedRegion": "us-east-1"}),
        event(**{"aws:RequestedRegion": "eu-west-1"}),
    ]
    assert len(deduplicate(events, frozenset({"aws:RequestedRegion"}))) == 2


def test_group_records_how_many_raw_contexts_collapsed():
    events = [
        event(**{"aws:SourceIp": "203.0.113.1"}),
        event(**{"aws:SourceIp": "203.0.113.2"}),
    ]
    groups = deduplicate(events, frozenset({"aws:PrincipalArn"}))
    assert len(groups[0].context_variants) == 2


def test_merging_keeps_the_most_cautious_confidence():
    """A group must never claim more certainty than its least certain member."""
    events = [
        event(confidence=Confidence.EXACT),
        event(confidence=Confidence.INFERRED, notes=("principal was parsed",)),
    ]
    groups = deduplicate(events)
    assert len(groups) == 1
    assert groups[0].request.confidence is Confidence.INFERRED
    assert "principal was parsed" in groups[0].request.notes


def test_merging_unions_the_notes():
    events = [event(notes=("note a",)), event(notes=("note b",))]
    groups = deduplicate(events)
    assert set(groups[0].request.notes) == {"note a", "note b"}


def test_already_denied_events_are_split_out_of_the_regression_set():
    """Replaying an already-denied call and reporting WOULD DENY fabricates a
    regression (spec §4.1)."""
    events = [
        event(outcome=Outcome.SUCCEEDED),
        event(outcome=Outcome.FAILED_POST_AUTHZ),
        event(outcome=Outcome.AUTHZ_DENIED),
    ]
    regression, already_denied = split_by_outcome(events)

    assert len(regression) == 2
    assert len(already_denied) == 1


def test_failed_post_authz_stays_in_the_regression_set():
    """Authorization passed, so the call is evidence about the candidate policy."""
    regression, _ = split_by_outcome([event(outcome=Outcome.FAILED_POST_AUTHZ)])
    assert len(regression) == 1


def test_outcome_mix_is_recorded_on_the_group():
    events = [event(outcome=Outcome.SUCCEEDED), event(outcome=Outcome.FAILED_POST_AUTHZ)]
    groups = deduplicate(events)
    assert groups[0].outcomes[Outcome.SUCCEEDED] == 1
    assert groups[0].outcomes[Outcome.FAILED_POST_AUTHZ] == 1


def test_events_that_produced_no_requests_contribute_nothing():
    meta = EventMeta("e", datetime.now(timezone.utc), "X", "s3.amazonaws.com", "us-east-1", Outcome.SUCCEEDED)
    assert deduplicate([MappedEvent(meta)]) == []
