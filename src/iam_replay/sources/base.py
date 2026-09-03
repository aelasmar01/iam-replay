"""The event source interface (spec §3).

Every source yields **parsed CloudTrail record dicts** -- the same shape found
inside a trail file's ``Records`` array. That uniformity is load-bearing: the
``lookup`` source returns a wrapper whose ``CloudTrailEvent`` field is a JSON
*string* holding the real record, while trail files hold the records directly.
Unwrapping happens inside each source, so nothing downstream ever branches on
where an event came from.

The interface is deliberately small so CloudTrail Lake can be added later
without disturbing anything (spec §2 -- design for it, do not build it).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Iterator


class EventSource(ABC):
    """A stream of CloudTrail records, plus what window it can actually cover."""

    #: Short name used in reports and error messages.
    name: str = "source"

    @abstractmethod
    def events(self) -> Iterator[dict[str, Any]]:
        """Yield parsed CloudTrail records, in no guaranteed order."""

    @abstractmethod
    def earliest_available(self) -> datetime | None:
        """The oldest event time this source can serve, or None if unknown.

        Window resolution (spec §5) uses this to report the window it *actually*
        analyzed rather than the one that was requested. Claiming 90 days of
        coverage over a trail holding 12 is the exact false comfort this tool
        exists to prevent.
        """
