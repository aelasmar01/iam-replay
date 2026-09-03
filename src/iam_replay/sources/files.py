"""Read CloudTrail records from local or synced trail files (spec §5).

This is the long-window path: ``aws s3 sync`` the trail prefix, point at the
directory. It has no API ceiling, so it covers windows the 90-day
``LookupEvents`` limit cannot.

Accepts the gzipped JSON CloudTrail writes to S3, plain JSON, and the
newline-delimited form some exports use.
"""

from __future__ import annotations

import gzip
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .base import EventSource

#: Suffixes worth opening. CloudTrail also writes digest files alongside the
#: log files; those contain no events and are skipped by name.
_LOG_SUFFIXES = (".json.gz", ".json")


class FileEventSource(EventSource):
    """CloudTrail records read from a directory tree or a single file."""

    name = "files"

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if not self.path.exists():
            raise FileNotFoundError(f"no such path: {self.path}")
        self._earliest: datetime | None = None
        self._scanned = False

    def _log_files(self) -> list[Path]:
        if self.path.is_file():
            return [self.path]
        files = [
            candidate
            for candidate in sorted(self.path.rglob("*"))
            if candidate.is_file()
            and candidate.name.endswith(_LOG_SUFFIXES)
            and "_CloudTrail-Digest_" not in candidate.name
        ]
        return files

    @staticmethod
    def _read(path: Path) -> Any:
        opener = gzip.open if path.name.endswith(".gz") else open
        with opener(path, "rt", encoding="utf-8") as handle:  # type: ignore[operator]
            text = handle.read()

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # Newline-delimited JSON, as some exports produce.
            return [json.loads(line) for line in text.splitlines() if line.strip()]

    def events(self) -> Iterator[dict[str, Any]]:
        earliest: datetime | None = None

        for path in self._log_files():
            document = self._read(path)
            if isinstance(document, dict):
                records = document.get("Records", [])
            else:
                records = document

            for record in records:
                if not isinstance(record, dict):
                    continue
                event_time = _parse_time(record.get("eventTime"))
                if event_time and (earliest is None or event_time < earliest):
                    earliest = event_time
                yield record

        self._earliest = earliest
        self._scanned = True

    def earliest_available(self) -> datetime | None:
        """Discovered from the files themselves, by scanning if needed."""
        if not self._scanned:
            for _ in self.events():
                pass
        return self._earliest


def _parse_time(raw: Any) -> datetime | None:
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed
