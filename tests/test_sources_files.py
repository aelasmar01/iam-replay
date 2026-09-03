"""The files event source (spec §5, milestone 3/5)."""

from __future__ import annotations

import gzip
import json
from datetime import datetime, timezone

import pytest

from iam_replay.sources.files import FileEventSource

from .conftest import FIXTURES


HAND_BUILT = ["s3_events.json", "iam_events.json", "sts_events.json", "edge_cases.json"]


def test_reads_every_record_in_a_directory_tree():
    """Recurses, so the captured live/ snapshot is included alongside the
    hand-built files. Counted as a floor rather than an exact number: the live
    snapshot grows whenever it is regenerated."""
    events = list(FileEventSource(FIXTURES).events())
    hand_built = sum(len(list(FileEventSource(FIXTURES / name).events())) for name in HAND_BUILT)

    assert hand_built == 26
    assert len(events) >= hand_built
    assert all("eventName" in event for event in events)


def test_reads_a_single_file():
    events = list(FileEventSource(FIXTURES / "s3_events.json").events())
    assert len(events) == 7


def test_reads_the_gzipped_json_cloudtrail_actually_writes(tmp_path):
    """Trail objects in S3 are gzipped; reading only plain JSON would make the
    long-window path silently return nothing."""
    payload = {"Records": [{"eventName": "ListBuckets", "eventTime": "2026-08-01T00:00:00Z"}]}
    target = tmp_path / "123_CloudTrail_us-east-1_20260801T0000Z_abc.json.gz"
    with gzip.open(target, "wt", encoding="utf-8") as handle:
        json.dump(payload, handle)

    events = list(FileEventSource(tmp_path).events())
    assert [event["eventName"] for event in events] == ["ListBuckets"]


def test_skips_digest_files():
    """Digest files sit alongside the logs and contain no events. Parsing them
    as logs would add noise to every count in the report."""
    from iam_replay.sources.files import FileEventSource as Source

    source = Source(FIXTURES)
    assert all("_CloudTrail-Digest_" not in p.name for p in source._log_files())


def test_reads_newline_delimited_json(tmp_path):
    target = tmp_path / "export.json"
    target.write_text(
        '{"eventName": "GetRole", "eventTime": "2026-08-01T00:00:00Z"}\n'
        '{"eventName": "ListRoles", "eventTime": "2026-08-02T00:00:00Z"}\n'
    )
    events = list(FileEventSource(target).events())
    assert [event["eventName"] for event in events] == ["GetRole", "ListRoles"]


def test_earliest_available_is_discovered_from_the_data():
    """Window resolution (§5) reports the window actually analyzed, which for
    this source means whatever the files happen to hold."""
    source = FileEventSource(FIXTURES)
    assert source.earliest_available() == datetime(2026, 8, 20, 14, 3, 11, tzinfo=timezone.utc)


def test_earliest_available_works_without_iterating_first():
    source = FileEventSource(FIXTURES)
    assert source.earliest_available() is not None


def test_missing_path_fails_immediately():
    """Better than yielding zero events and letting the report claim a clean
    result over an empty window."""
    with pytest.raises(FileNotFoundError):
        FileEventSource("/nonexistent/trail-data")
