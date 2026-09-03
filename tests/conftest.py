from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from iam_replay.normalize.mapper import Mapper

FIXTURES = Path(__file__).parent / "fixtures" / "cloudtrail"


def load_records(name: str) -> list[dict[str, Any]]:
    """Read one fixture file's Records array."""
    return json.loads((FIXTURES / name).read_text())["Records"]


def record_by_id(name: str, event_id: str) -> dict[str, Any]:
    for record in load_records(name):
        if record["eventID"] == event_id:
            return record
    raise KeyError(f"{event_id} not in {name}")


@pytest.fixture(scope="session")
def mapper() -> Mapper:
    return Mapper()
