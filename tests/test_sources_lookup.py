"""The lookup event source (spec §5).

This is the *default* source, so it is the one most users will ever exercise --
and until these tests existed it was the only module in the package with no
coverage at all, because it had only ever been run against live AWS. A
regression here would have shipped silently.

The AWS client is faked rather than mocked at the boto3 level: the source's
whole job is to page the API and unwrap its envelope, and a fake paginator
tests exactly that without pretending to test boto3 itself.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from iam_replay.sources.lookup import LookupEventSource
from iam_replay.window import LOOKUP_MAX_DAYS

START = datetime(2026, 9, 1, tzinfo=timezone.utc)
END = datetime(2026, 9, 2, tzinfo=timezone.utc)


def envelope(record: dict | str, event_id: str = "e1") -> dict:
    """One LookupEvents entry: the record arrives as a JSON *string*."""
    return {
        "EventId": event_id,
        "EventName": record.get("eventName") if isinstance(record, dict) else "?",
        "CloudTrailEvent": record if isinstance(record, str) else json.dumps(record),
    }


def record(event_name: str = "ListBuckets", **extra) -> dict:
    return {
        "eventID": f"id-{event_name}",
        "eventName": event_name,
        "eventSource": "s3.amazonaws.com",
        "eventTime": "2026-09-01T12:00:00Z",
        "awsRegion": "us-east-1",
        **extra,
    }


class FakePaginator:
    def __init__(self, pages):
        self.pages = pages
        self.calls: list[dict] = []

    def paginate(self, **kwargs):
        self.calls.append(kwargs)
        return iter(self.pages)


class FakeClient:
    """Stands in for boto3's cloudtrail client."""

    def __init__(self, pages):
        self.paginator = FakePaginator(pages)
        self.requested_paginators: list[str] = []

    def get_paginator(self, name):
        self.requested_paginators.append(name)
        return self.paginator


def source(pages, **kwargs) -> tuple[LookupEventSource, FakeClient]:
    client = FakeClient(pages)
    return LookupEventSource(start=START, end=END, client=client, **kwargs), client


# --- unwrapping the envelope -------------------------------------------------


def test_the_json_string_envelope_is_unwrapped_into_a_record():
    """The single most important behaviour here. LookupEvents nests the real
    record as a JSON string inside CloudTrailEvent; every other source yields
    plain dicts, and nothing downstream branches on which source it read."""
    src, _ = source([{"Events": [envelope(record("ListBuckets"))]}])

    events = list(src.events())

    assert len(events) == 1
    assert isinstance(events[0], dict)
    assert events[0]["eventName"] == "ListBuckets"
    assert events[0]["eventSource"] == "s3.amazonaws.com"


def test_the_outer_wrapper_fields_are_not_leaked_downstream():
    """EventId/EventName on the wrapper duplicate the record's own fields in a
    different shape. Yielding the wrapper would break every consumer."""
    src, _ = source([{"Events": [envelope(record())]}])

    event = next(iter(src.events()))
    assert "CloudTrailEvent" not in event
    assert "EventId" not in event


def test_every_page_is_consumed():
    pages = [
        {"Events": [envelope(record("ListBuckets"), "e1")]},
        {"Events": [envelope(record("GetBucketLocation"), "e2")]},
        {"Events": [envelope(record("ListRoles"), "e3")]},
    ]
    src, _ = source(pages)

    assert [e["eventName"] for e in src.events()] == [
        "ListBuckets",
        "GetBucketLocation",
        "ListRoles",
    ]


def test_several_events_within_one_page():
    page = {"Events": [envelope(record(f"Event{i}"), f"e{i}") for i in range(5)]}
    src, _ = source([page])

    assert len(list(src.events())) == 5


# --- the window is handed to the API ----------------------------------------


def test_the_requested_window_is_passed_to_the_api():
    """If StartTime/EndTime were dropped, the source would silently return the
    API's own default window instead of the one the report claims."""
    src, client = source([{"Events": []}])
    list(src.events())

    assert client.requested_paginators == ["lookup_events"]
    assert client.paginator.calls == [{"StartTime": START, "EndTime": END}]


def test_end_defaults_to_now_when_not_given():
    before = datetime.now(timezone.utc)
    src = LookupEventSource(start=START, client=FakeClient([{"Events": []}]))
    after = datetime.now(timezone.utc)

    assert before <= src.end <= after


# --- malformed input is dropped, never guessed at ----------------------------


def test_an_entry_with_no_cloudtrail_event_is_skipped():
    src, _ = source([{"Events": [{"EventId": "e1"}, envelope(record())]}])

    events = list(src.events())
    assert len(events) == 1


def test_an_unparsable_record_is_dropped_rather_than_crashing_the_replay():
    """One malformed record must not take down a replay of millions. The count
    difference stays visible in the report's header."""
    src, _ = source([{"Events": [envelope("{not json"), envelope(record())]}])

    events = list(src.events())
    assert len(events) == 1
    assert events[0]["eventName"] == "ListBuckets"


def test_an_empty_cloudtrail_event_string_is_skipped():
    src, _ = source([{"Events": [envelope(""), envelope(record())]}])
    assert len(list(src.events())) == 1


def test_a_page_with_no_events_key_is_tolerated():
    src, _ = source([{}, {"Events": [envelope(record())]}])
    assert len(list(src.events())) == 1


def test_no_events_at_all_yields_nothing():
    src, _ = source([{"Events": []}])
    assert list(src.events()) == []


# --- window reporting --------------------------------------------------------


def test_earliest_available_is_the_apis_ninety_day_floor():
    """Reported as a property of the service rather than discovered from the
    data: a quiet account with no old events is indistinguishable from a source
    that cannot serve them, and the floor is the honest answer either way."""
    src, _ = source([{"Events": []}])

    earliest = src.earliest_available()
    age = datetime.now(timezone.utc) - earliest

    assert abs(age - timedelta(days=LOOKUP_MAX_DAYS)) < timedelta(seconds=5)


def test_earliest_available_does_not_call_the_api():
    """Window resolution runs before any events are fetched; making it hit the
    API would cost a round trip on every run for a constant."""
    src, client = source([{"Events": []}])

    src.earliest_available()
    assert client.requested_paginators == []


# --- construction ------------------------------------------------------------


def test_the_source_names_itself_for_the_report_and_the_ceiling_check():
    """window.check_source_ceiling keys off this exact string to enforce the
    90-day limit, so a rename here silently disables that check."""
    src, _ = source([{"Events": []}])
    assert src.name == "lookup"


def test_an_injected_client_is_used_without_touching_boto3(monkeypatch):
    """Guards the lazy-construction path: importing boto3 at __init__ would make
    the source unusable in tests and slow to import in the CLI."""
    import iam_replay.sources.lookup as module

    def explode(*args, **kwargs):  # pragma: no cover - must never run
        raise AssertionError("boto3 was constructed despite an injected client")

    monkeypatch.setattr("boto3.client", explode)

    src, _ = source([{"Events": [envelope(record())]}])
    assert len(list(src.events())) == 1


def test_the_real_client_is_built_lazily_and_honours_the_region(monkeypatch):
    built: list[dict] = []

    def fake_client(service, **kwargs):
        built.append({"service": service, **kwargs})
        return FakeClient([{"Events": []}])

    monkeypatch.setattr("boto3.client", fake_client)

    src = LookupEventSource(start=START, end=END, region="eu-west-1")
    assert built == []  # nothing constructed at __init__

    list(src.events())
    assert built == [{"service": "cloudtrail", "region_name": "eu-west-1"}]


def test_no_region_means_the_default_from_the_environment(monkeypatch):
    built: list[dict] = []

    def fake_client(service, **kwargs):
        built.append({"service": service, **kwargs})
        return FakeClient([{"Events": []}])

    monkeypatch.setattr("boto3.client", fake_client)

    list(LookupEventSource(start=START, end=END).events())
    assert built == [{"service": "cloudtrail"}]


def test_the_client_is_built_once_and_reused():
    src, client = source([{"Events": []}])
    assert src.client is client
    assert src.client is client


# --- integration with the rest of the pipeline -------------------------------


def test_records_from_this_source_map_like_any_other(mapper):
    """The point of unwrapping here: the mapper cannot tell where a record came
    from."""
    src, _ = source([{"Events": [envelope(record("ListBuckets", **{
        "userIdentity": {
            "type": "AssumedRole",
            "accountId": "123456789012",
            "sessionContext": {
                "sessionIssuer": {"arn": "arn:aws:iam::123456789012:role/DeployRole"}
            },
        },
        "recipientAccountId": "123456789012",
    }))]}])

    mapped = [mapper.map_event(r) for r in src.events()]

    assert len(mapped) == 1
    assert mapped[0].requests[0].action == "s3:ListAllMyBuckets"
    assert mapped[0].principal_arn == "arn:aws:iam::123456789012:role/DeployRole"
