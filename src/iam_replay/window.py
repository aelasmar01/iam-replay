"""Time-window resolution (spec §5).

The number that matters here is ``analyzed_days``, and it appears in the report
header and the JSON output **always** -- not only when it differs from what was
requested. "I analyzed 90 days" against a trail holding twelve days of data is
the exact false comfort this tool exists to prevent, and it is invisible unless
the analyzed window is stated unconditionally.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

#: cloudtrail:LookupEvents serves at most 90 days of management events. This is
#: an API limit, not a policy choice, so it is enforced rather than clamped.
LOOKUP_MAX_DAYS = 90

DEFAULT_DAYS = 90


class WindowError(ValueError):
    """A window that cannot be honoured, with an actionable message."""


@dataclass(frozen=True)
class Window:
    """What was asked for, and what could actually be analyzed."""

    requested_days: int
    requested_start: datetime
    analyzed_start: datetime
    analyzed_end: datetime
    #: True when the source held less history than was requested. Drives the
    #: warning at the top of the report.
    truncated: bool
    source_name: str

    @property
    def analyzed_days(self) -> int:
        return max(0, (self.analyzed_end - self.analyzed_start).days)

    def covers(self, moment: datetime) -> bool:
        return self.analyzed_start <= moment <= self.analyzed_end

    def describe(self) -> str:
        start = self.analyzed_start.date().isoformat()
        end = self.analyzed_end.date().isoformat()
        return f"{self.analyzed_days} days ({start} → {end})"


def resolve_requested_days(
    days: int | None,
    since: datetime | None,
    until: datetime | None,
    now: datetime | None = None,
) -> tuple[int, datetime, datetime]:
    """Turn the CLI's mutually exclusive window flags into (days, start, end)."""
    now = now or datetime.now(timezone.utc)

    if days is not None and (since is not None or until is not None):
        raise WindowError("--days cannot be combined with --since/--until")

    if since is not None:
        end = until or now
        if since >= end:
            raise WindowError(f"--since ({since.isoformat()}) is not before --until ({end.isoformat()})")
        return max(1, (end - since).days), since, end

    if until is not None:
        raise WindowError("--until requires --since")

    requested = DEFAULT_DAYS if days is None else days
    if requested < 1:
        # Rejected before any work is done, per spec §5.
        raise WindowError(f"--days must be at least 1 (got {requested})")

    return requested, now - timedelta(days=requested), now


def check_source_ceiling(source_name: str, requested_days: int) -> None:
    """Fail loudly when a source cannot serve the requested window.

    ``lookup`` above 90 days errors out naming the API limit and the way
    around it. Silently clamping would hand back a report whose header says one
    thing and whose evidence covers another.
    """
    if source_name == "lookup" and requested_days > LOOKUP_MAX_DAYS:
        raise WindowError(
            f"--days {requested_days} exceeds the {LOOKUP_MAX_DAYS}-day limit of "
            "cloudtrail:LookupEvents, which is imposed by the API and cannot be "
            "raised.\n"
            "For a longer window, sync the trail bucket and read it directly:\n"
            "    aws s3 sync s3://<your-trail-bucket>/AWSLogs/ ./trail-data/\n"
            "    iam-replay --source files --path ./trail-data ..."
        )


def resolve(
    source_name: str,
    source_earliest: datetime | None,
    days: int | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    now: datetime | None = None,
) -> Window:
    """Resolve the window actually analyzed, given what the source can serve."""
    now = now or datetime.now(timezone.utc)
    requested_days, requested_start, end = resolve_requested_days(days, since, until, now)
    check_source_ceiling(source_name, requested_days)

    analyzed_start = requested_start
    truncated = False
    if source_earliest is not None and source_earliest > requested_start:
        analyzed_start = source_earliest
        truncated = True

    return Window(
        requested_days=requested_days,
        requested_start=requested_start,
        analyzed_start=analyzed_start,
        analyzed_end=end,
        truncated=truncated,
        source_name=source_name,
    )
