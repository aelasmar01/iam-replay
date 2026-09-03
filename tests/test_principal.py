"""Assumed-role normalization (spec §4.2, milestone 1)."""

from __future__ import annotations

from iam_replay.normalize.principal import (
    matches,
    normalize_principal_filter,
    resolve,
)

from .conftest import record_by_id


def test_session_issuer_preserves_the_role_path():
    """The whole point of preferring sessionIssuer: string-parsing the session
    ARN cannot recover /service-role/, and would produce a role ARN that no
    correctly-written policy matches."""
    record = record_by_id("s3_events.json", "s3-0001-listobjectsv2-success")
    resolved = resolve(record["userIdentity"])

    assert resolved.arn == "arn:aws:iam::123456789012:role/service-role/DeployRole"
    assert resolved.inferred is False
    assert resolved.notes == ()


def test_missing_session_issuer_falls_back_and_is_marked_inferred():
    record = record_by_id("sts_events.json", "sts-0004-assumerole-no-session-issuer")
    resolved = resolve(record["userIdentity"])

    assert resolved.arn == "arn:aws:iam::123456789012:role/DeployRole"
    assert resolved.inferred is True
    # The note has to name the path hazard: this ARN is wrong whenever the real
    # role lives under a path, and a reviewer must be able to see why.
    assert any("path" in note for note in resolved.notes)


def test_aws_service_identity_has_no_principal():
    record = record_by_id("sts_events.json", "sts-0005-assumerole-by-aws-service")
    resolved = resolve(record["userIdentity"])

    assert resolved.arn is None
    assert any("lambda.amazonaws.com" in note for note in resolved.notes)


def test_iam_user_arn_is_used_as_is_including_its_path():
    record = record_by_id("edge_cases.json", "edge-0006-iam-user-principal")
    resolved = resolve(record["userIdentity"])

    assert resolved.arn == "arn:aws:iam::123456789012:user/ops/alice"
    assert resolved.inferred is False


def test_govcloud_partition_is_preserved():
    record = record_by_id("edge_cases.json", "edge-0005-govcloud-partition")
    assert resolve(record["userIdentity"]).arn.startswith("arn:aws-us-gov:iam::")


def test_missing_user_identity_is_not_a_crash():
    assert resolve(None).arn is None
    assert resolve({}).arn is None


def test_principal_filter_accepts_either_arn_form():
    role_arn = "arn:aws:iam::123456789012:role/DeployRole"
    session_arn = "arn:aws:sts::123456789012:assumed-role/DeployRole/deploy-1"

    assert normalize_principal_filter(session_arn) == role_arn
    assert normalize_principal_filter(role_arn) == role_arn
    assert normalize_principal_filter(f"  {role_arn}  ") == role_arn


def test_principal_filter_leaves_other_principal_types_alone():
    user_arn = "arn:aws:iam::123456789012:user/ops/alice"
    assert normalize_principal_filter(user_arn) == user_arn


def test_matching_is_case_insensitive_but_not_loose():
    role_arn = "arn:aws:iam::123456789012:role/DeployRole"
    assert matches(role_arn, "arn:aws:iam::123456789012:role/deployrole")
    assert not matches(role_arn, "arn:aws:iam::123456789012:role/DeployRole2")
    assert not matches(None, role_arn)


def test_partition_is_not_normalized_away_when_filtering():
    """A GovCloud session ARN must not resolve to a commercial-partition role."""
    gov_session = "arn:aws-us-gov:sts::123456789012:assumed-role/DeployRole/s"
    assert normalize_principal_filter(gov_session) == (
        "arn:aws-us-gov:iam::123456789012:role/DeployRole"
    )
