"""Time-window resolution (spec §5, milestone 5)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from iam_replay.window import DEFAULT_DAYS, LOOKUP_MAX_DAYS, WindowError, resolve

NOW = datetime(2026, 9, 2, 12, 0, tzinfo=timezone.utc)


def test_default_window_is_ninety_days():
    window = resolve("files", None, now=NOW)
    assert window.requested_days == DEFAULT_DAYS
    assert window.analyzed_days == DEFAULT_DAYS
    assert not window.truncated


def test_days_below_one_is_rejected_before_any_work():
    for bad in (0, -1, -90):
        with pytest.raises(WindowError, match="at least 1"):
            resolve("files", None, days=bad, now=NOW)


def test_lookup_beyond_ninety_days_errors_rather_than_clamping():
    """Silently clamping would produce a report whose header says one thing and
    whose evidence covers another."""
    with pytest.raises(WindowError) as exc:
        resolve("lookup", None, days=LOOKUP_MAX_DAYS + 1, now=NOW)

    message = str(exc.value)
    assert "90-day limit" in message
    assert "cloudtrail:LookupEvents" in message
    # Must tell the user the way around it, not just refuse.
    assert "--source files" in message


def test_lookup_at_exactly_ninety_days_is_allowed():
    assert resolve("lookup", None, days=LOOKUP_MAX_DAYS, now=NOW).analyzed_days == 90


def test_files_source_has_no_ceiling():
    window = resolve("files", None, days=3650, now=NOW)
    assert window.requested_days == 3650


def test_a_short_source_truncates_and_says_so():
    """The case the analyzed-window reporting exists for: 90 days requested
    over a trail holding twelve."""
    window = resolve("files", NOW - timedelta(days=12), days=90, now=NOW)

    assert window.requested_days == 90
    assert window.analyzed_days == 12
    assert window.truncated


def test_a_source_with_more_history_than_requested_does_not_extend_the_window():
    window = resolve("files", NOW - timedelta(days=400), days=30, now=NOW)
    assert window.analyzed_days == 30
    assert not window.truncated


def test_since_and_until():
    window = resolve(
        "files",
        None,
        since=datetime(2026, 8, 1, tzinfo=timezone.utc),
        until=datetime(2026, 8, 31, tzinfo=timezone.utc),
        now=NOW,
    )
    assert window.analyzed_days == 30


def test_days_cannot_be_combined_with_since():
    with pytest.raises(WindowError, match="cannot be combined"):
        resolve("files", None, days=7, since=datetime(2026, 8, 1, tzinfo=timezone.utc), now=NOW)


def test_until_without_since_is_rejected():
    with pytest.raises(WindowError, match="requires --since"):
        resolve("files", None, until=datetime(2026, 8, 1, tzinfo=timezone.utc), now=NOW)


def test_since_after_until_is_rejected():
    with pytest.raises(WindowError, match="not before"):
        resolve(
            "files",
            None,
            since=datetime(2026, 8, 31, tzinfo=timezone.utc),
            until=datetime(2026, 8, 1, tzinfo=timezone.utc),
            now=NOW,
        )


def test_covers_bounds_the_analyzed_window_not_the_requested_one():
    window = resolve("files", NOW - timedelta(days=12), days=90, now=NOW)

    assert window.covers(NOW - timedelta(days=1))
    assert not window.covers(NOW - timedelta(days=30))


def test_describe_always_states_the_analyzed_window():
    """Printed unconditionally, so a truncated window can never pass unnoticed."""
    assert "12 days" in resolve("files", NOW - timedelta(days=12), days=90, now=NOW).describe()
    assert "90 days" in resolve("files", None, days=90, now=NOW).describe()


def test_sub_day_windows_are_described_in_hours_not_zero_days():
    """"0 days" reads as "nothing was analyzed", which is the opposite of what
    this field exists to communicate."""
    window = resolve("files", NOW - timedelta(hours=20), days=90, now=NOW)

    assert window.analyzed_days == 0
    assert "hours" in window.describe()
    assert "0 days" not in window.describe()


def test_very_short_windows_fall_back_to_minutes():
    window = resolve("files", NOW - timedelta(minutes=30), days=90, now=NOW)
    assert "minutes" in window.describe()


def test_analyzed_seconds_is_exact_where_days_truncates():
    window = resolve("files", NOW - timedelta(hours=20), days=90, now=NOW)
    assert window.analyzed_seconds == 20 * 3600
