"""Condition-key extraction (spec §6, milestone 1).

The rule under test throughout: a key is present because the event carried it,
or it is absent. There is no default and no inference.
"""

from __future__ import annotations

from iam_replay.normalize.context import extract, is_never_available
from iam_replay.normalize.principal import resolve

from .conftest import record_by_id


def context_for(fixture: str, event_id: str) -> dict:
    record = record_by_id(fixture, event_id)
    return extract(record, resolve(record.get("userIdentity")))


def test_secure_transport_is_set_only_when_tls_details_are_present():
    """Hardcoding aws:SecureTransport=true is almost always right, which is
    exactly why it is forbidden: it would evaluate away a
    `Deny ... Bool: {aws:SecureTransport: false}` on an assumption."""
    with_tls = context_for("s3_events.json", "s3-0001-listobjectsv2-success")
    assert with_tls["aws:SecureTransport"] == ("true",)

    without_tls = context_for("s3_events.json", "s3-0007-getbucketacl-no-tls-details")
    assert "aws:SecureTransport" not in without_tls


def test_source_ip_is_omitted_for_service_principal_strings():
    """sourceIPAddress holds 'cloudtrail.amazonaws.com' when the call did not
    come from a client IP. Setting aws:SourceIp from that would make an
    IpAddress condition evaluate against nonsense."""
    service_call = context_for("s3_events.json", "s3-0007-getbucketacl-no-tls-details")
    assert "aws:SourceIp" not in service_call

    client_call = context_for("s3_events.json", "s3-0001-listobjectsv2-success")
    assert client_call["aws:SourceIp"] == ("203.0.113.42",)


def test_principal_arn_comes_from_the_role_not_the_session():
    context = context_for("s3_events.json", "s3-0001-listobjectsv2-success")
    assert context["aws:PrincipalArn"] == (
        "arn:aws:iam::123456789012:role/service-role/DeployRole",
    )


def test_straightforward_keys_are_taken_verbatim():
    context = context_for("s3_events.json", "s3-0001-listobjectsv2-success")
    assert context["aws:PrincipalAccount"] == ("123456789012",)
    assert context["aws:RequestedRegion"] == ("us-east-1",)
    assert context["aws:UserAgent"][0].startswith("aws-cli/")


def test_mfa_flag_is_carried_through_in_both_states():
    no_mfa = context_for("s3_events.json", "s3-0001-listobjectsv2-success")
    assert no_mfa["aws:MultiFactorAuthPresent"] == ("false",)

    with_mfa = context_for("sts_events.json", "sts-0006-decodeauthorizationmessage")
    assert with_mfa["aws:MultiFactorAuthPresent"] == ("true",)


def test_mfa_key_is_absent_when_the_event_does_not_say():
    context = context_for("iam_events.json", "iam-0003-listroles-star-resource")
    assert "aws:MultiFactorAuthPresent" not in context


def test_invoked_by_populates_the_via_service_keys():
    context = context_for("s3_events.json", "s3-0007-getbucketacl-no-tls-details")
    assert context["aws:ViaAWSService"] == ("true",)
    assert context["aws:CalledVia"] == ("cloudtrail.amazonaws.com",)


def test_via_service_keys_absent_for_a_direct_call():
    context = context_for("s3_events.json", "s3-0001-listobjectsv2-success")
    assert "aws:ViaAWSService" not in context
    assert "aws:CalledVia" not in context


def test_tag_keys_are_recognised_as_never_available():
    for key in ("aws:ResourceTag/env", "aws:PrincipalTag/team",
                "aws:RequestTag/owner", "aws:TagKeys"):
        assert is_never_available(key), key


def test_ordinary_keys_are_not_flagged_as_never_available():
    for key in ("aws:SourceIp", "aws:PrincipalArn", "s3:prefix"):
        assert not is_never_available(key), key
