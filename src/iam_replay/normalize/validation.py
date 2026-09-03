"""Which event mappings have been validated against real AWS traffic.

Most of this package's mappings are *asserted*: written by hand, covered by
hand-written fixtures, never checked against AWS. A smaller set is
*oracle-backed* -- replayed against the policy that actually authorized the call
and pinned by a negative control (see tests/test_ground_truth.py and
tests/test_negative_control.py).

The distinction is surfaced at runtime rather than left in the README, for the
same reason the analyzed window is printed on every run: a caveat someone might
not read becomes a number they cannot avoid. Someone replaying a production role
deserves to know whether their particular replay touched validated ground.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

MANIFEST_PATH = Path(__file__).parent / "validated_mappings.json"


@lru_cache(maxsize=1)
def _manifest() -> dict:
    try:
        return json.loads(MANIFEST_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        # A missing or unreadable manifest must not break a replay. It means
        # nothing is known to be validated, which is the cautious answer.
        return {"validated": {}, "declared_totals": {}}


@lru_cache(maxsize=1)
def validated_pairs() -> frozenset[tuple[str, str]]:
    """(service, eventName) pairs backed by both halves of the oracle."""
    manifest = _manifest()
    return frozenset(
        (service, event_name)
        for service, events in manifest.get("validated", {}).items()
        for event_name in events
    )


def is_validated(service: str | None, event_name: str) -> bool:
    if service is None:
        return False
    return (service, event_name) in validated_pairs()


def declared_total() -> int:
    return sum(_manifest().get("declared_totals", {}).values())


def validated_total() -> int:
    return len(validated_pairs())
