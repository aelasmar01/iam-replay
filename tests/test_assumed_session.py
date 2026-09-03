"""Attribution of calls made under an assumed role session, on real traffic.

`normalize/principal.py` exists because CloudTrail reports a role session as
``arn:aws:sts::…:assumed-role/RoleName/session`` -- the session, not the role --
and because string-parsing that ARN silently loses the role's *path*. Until now
that reasoning was only exercised by hand-built fixtures, where the author
controls both the input and the expectation.

The fixture workload now assumes a second role that deliberately lives under a
path, and makes a call under that session. These tests replay the resulting real
events, so the path-preservation claim is checked against traffic AWS actually
produced rather than against a fixture written to agree with the code.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from iam_replay.normalize.mapper import Mapper
from iam_replay.normalize.principal import normalize_principal_filter, resolve
from iam_replay.sources.files import FileEventSource

LIVE = Path(__file__).parent / "fixtures" / "cloudtrail" / "live"
SESSION_EVENTS = LIVE / "assumed_session_events.json"

#: The account ID is scrubbed to the documentation account by the capture script.
TARGET_ROLE_ARN = (
    "arn:aws:iam::123456789012:role/iam-replay-fixture-roles/iam-replay-fixture-target"
)

pytestmark = pytest.mark.skipif(
    not SESSION_EVENTS.exists(),
    reason=(
        "no captured assumed-session events; run scripts/capture_live_events.py "
        "with --principal <target role arn> --name assumed_session_events"
    ),
)


@pytest.fixture(scope="module")
def session_events():
    return list(FileEventSource(SESSION_EVENTS).events())


def test_the_snapshot_contains_events(session_events):
    assert session_events


def test_a_real_session_arn_resolves_to_the_role_arn(session_events):
    """The whole point of principal.py, on traffic AWS produced."""
    for record in session_events:
        resolved = resolve(record["userIdentity"])
        assert resolved.arn == TARGET_ROLE_ARN, record.get("eventName")


def test_the_role_path_survives_on_real_traffic(session_events):
    """The failure mode that motivated preferring sessionIssuer.

    The session ARN carries no path, so parsing it yields
    ``role/iam-replay-fixture-target`` -- an ARN no correctly-written policy
    matches. Only sessionIssuer has the real answer.
    """
    record = session_events[0]
    session_arn = record["userIdentity"]["arn"]

    assert "/iam-replay-fixture-roles/" not in session_arn  # the path is absent here
    assert "assumed-role/" in session_arn

    resolved = resolve(record["userIdentity"])
    assert "/iam-replay-fixture-roles/" in resolved.arn
    assert resolved.inferred is False

    # And what the fallback would have produced, had sessionIssuer been missing.
    without_issuer = dict(record["userIdentity"])
    without_issuer.pop("sessionContext", None)
    fallback = resolve(without_issuer)

    assert fallback.arn != resolved.arn
    assert fallback.inferred is True
    assert any("path" in note for note in fallback.notes)


def test_events_under_the_session_are_attributed_to_the_target_role(session_events):
    """Mapped events carry the role ARN, so --principal filtering works against
    a session the workload opened at runtime."""
    mapper = Mapper()
    for record in session_events:
        assert mapper.map_event(record).principal_arn == TARGET_ROLE_ARN


def test_the_principal_filter_accepts_the_session_arn_form(session_events):
    """A user pasting the session ARN out of a CloudTrail console row should
    still match. Normalizing it cannot recover the path, so it will not equal
    the resolved ARN -- which is exactly why --principal is documented as taking
    the role ARN."""
    session_arn = session_events[0]["userIdentity"]["arn"]
    normalized = normalize_principal_filter(session_arn)

    assert normalized.startswith("arn:aws:iam::")
    assert ":role/" in normalized
    assert normalized != TARGET_ROLE_ARN  # the path cannot be recovered


def test_the_assume_role_call_itself_is_attributed_to_the_caller():
    """The other half: sts:AssumeRole is attributed to the *workload* role, not
    the role being assumed, which is what gives sts:AssumeRole its first real
    oracle coverage."""
    workload_events = LIVE / "workload_events.json"
    if not workload_events.exists():
        pytest.skip("no captured workload events")

    mapper = Mapper()
    assume_roles = [
        mapper.map_event(record)
        for record in FileEventSource(workload_events).events()
        if record.get("eventName") == "AssumeRole"
    ]
    assert assume_roles, "workload produced no AssumeRole events"

    for mapped in assume_roles:
        assert mapped.principal_arn.endswith("role/iam-replay-fixture-workload")
        actions = [request.action for request in mapped.requests]
        assert actions == ["sts:AssumeRole"]
        assert mapped.requests[0].resource_arn == TARGET_ROLE_ARN
