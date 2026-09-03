"""Read CloudTrail records via ``cloudtrail:LookupEvents`` (spec §5).

Needs no trail: CloudTrail Event history is on by default and retains
**management events for 90 days**. That makes this the zero-setup path -- point
it at an account and it works -- and also the limited one:

* 90 days, hard. The ceiling is enforced in :mod:`iam_replay.window`, which
  errors rather than clamping.
* **Management events only.** Data events never appear here at all, so a clean
  result for a data-plane role means nothing.

The API is also slow: it returns at most 50 events per call and is aggressively
rate-limited. For a busy principal over a long window, sync the trail bucket and
use the ``files`` source instead.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator

from ..window import LOOKUP_MAX_DAYS
from .base import EventSource


class LookupEventSource(EventSource):
    """CloudTrail records from the LookupEvents API."""

    name = "lookup"

    def __init__(
        self,
        start: datetime,
        end: datetime | None = None,
        region: str | None = None,
        client: Any = None,
    ) -> None:
        self.start = start
        self.end = end or datetime.now(timezone.utc)
        self._region = region
        self._client = client

    @property
    def client(self) -> Any:
        if self._client is None:
            import boto3

            self._client = (
                boto3.client("cloudtrail", region_name=self._region)
                if self._region
                else boto3.client("cloudtrail")
            )
        return self._client

    def events(self) -> Iterator[dict[str, Any]]:
        """Yield parsed CloudTrail records.

        LookupEvents returns a wrapper whose ``CloudTrailEvent`` field is a JSON
        *string* holding the actual record. Unwrapping happens here so nothing
        downstream has to know which source it is reading (see sources/base.py).
        """
        paginator = self.client.get_paginator("lookup_events")
        for page in paginator.paginate(StartTime=self.start, EndTime=self.end):
            for entry in page.get("Events", []):
                raw = entry.get("CloudTrailEvent")
                if not raw:
                    continue
                try:
                    yield json.loads(raw)
                except json.JSONDecodeError:
                    # A record we cannot parse is dropped rather than guessed
                    # at, and the count difference is visible in the report.
                    continue

    def earliest_available(self) -> datetime | None:
        """The API's 90-day floor, which is a property of the service.

        Returned unconditionally rather than discovered, because a quiet account
        with no old events is indistinguishable from a source that cannot serve
        them -- and reporting the floor is the honest answer either way.
        """
        return datetime.now(timezone.utc) - timedelta(days=LOOKUP_MAX_DAYS)
