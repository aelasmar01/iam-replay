"""Event -> authorization request mapping (spec §6, milestone 1).

These tests check the mapper against its author's beliefs about the mapping,
which is a weaker instrument than the ground-truth oracle in
test_ground_truth.py. They catch mechanical faults -- a template that silently
widens, a missing field that becomes a guess -- not a mapping that is simply
wrong about which action an API authorizes.
"""

from __future__ import annotations

import pytest

from iam_replay.models import Confidence, Reason
from iam_replay.normalize.mapper import Mapper, partition_for_region, service_from_event_source

from .conftest import load_records, record_by_id

ROLE = "arn:aws:iam::123456789012:role/service-role/DeployRole"


def map_one(mapper: Mapper, fixture: str, event_id: str):
    return mapper.map_event(record_by_id(fixture, event_id))


# --- event name is not the action -------------------------------------------

def test_list_objects_v2_authorizes_list_bucket(mapper):
    """The canonical case: eventName ListObjectsV2, IAM action s3:ListBucket."""
    result = map_one(mapper, "s3_events.json", "s3-0001-listobjectsv2-success")

    assert len(result.requests) == 1
    request = result.requests[0]
    assert request.action == "s3:ListBucket"
    assert request.resource_arn == "arn:aws:s3:::acme-artifacts-prod"
    assert request.principal_arn == ROLE
    assert request.confidence is Confidence.EXACT


def test_head_bucket_also_authorizes_list_bucket(mapper):
    record = dict(record_by_id("s3_events.json", "s3-0001-listobjectsv2-success"))
    record["eventName"] = "HeadBucket"
    assert mapper.map_event(record).requests[0].action == "s3:ListBucket"


# --- missing fields never become a guess ------------------------------------

def test_missing_resource_field_yields_unknown_resource_not_a_wildcard(mapper):
    """A template that cannot be filled must produce None, never '*'. Widening
    to '*' would make a tightened policy look like it still matches."""
    result = map_one(mapper, "s3_events.json", "s3-0004-listobjectsv2-no-bucket-field")

    request = result.requests[0]
    assert request.resource_arn is None
    assert request.confidence is Confidence.UNKNOWN_RESOURCE
    assert any("bucketName" in note for note in request.notes)


def test_unknown_resource_is_reported_even_when_the_principal_was_inferred(mapper):
    """UNKNOWN_RESOURCE outranks INFERRED: a missing resource has the larger
    effect on the verdict, so it is the confidence the report must show."""
    record = dict(record_by_id("s3_events.json", "s3-0004-listobjectsv2-no-bucket-field"))
    record["userIdentity"] = {
        "type": "AssumedRole",
        "arn": "arn:aws:sts::123456789012:assumed-role/DeployRole/deploy-1",
        "accountId": "123456789012",
    }
    request = mapper.map_event(record).requests[0]

    assert request.confidence is Confidence.UNKNOWN_RESOURCE
    assert any("sessionIssuer" in note for note in request.notes)


def test_star_resource_is_declared_by_the_mapping_not_inferred(mapper):
    """s3:ListAllMyBuckets genuinely has no bucket-scoped resource. That is a
    documented fact recorded in the mapping, not a fallback for a missing field."""
    result = map_one(mapper, "s3_events.json", "s3-0003-listbuckets-success")
    request = result.requests[0]

    assert request.action == "s3:ListAllMyBuckets"
    assert request.resource_arn == "*"
    assert request.confidence is Confidence.EXACT


# --- resources[] preference --------------------------------------------------

def test_resources_array_supplies_the_role_path_the_template_cannot(mapper):
    """requestParameters only carries 'AppRole'; the correct ARN includes
    /service-role/. CloudTrail's resources[] annotation has it, so it wins."""
    result = map_one(mapper, "iam_events.json", "iam-0001-getrole-with-resources-array")
    request = result.requests[0]

    assert request.action == "iam:GetRole"
    assert request.resource_arn == "arn:aws:iam::123456789012:role/service-role/AppRole"


def test_template_is_used_when_no_resources_array_is_present(mapper):
    result = map_one(mapper, "iam_events.json", "iam-0002-getrole-template-fallback")
    assert result.requests[0].resource_arn == "arn:aws:iam::123456789012:role/FlatRole"


def test_ambiguous_resources_array_falls_back_rather_than_guessing(mapper):
    """Two roles of the same type are listed. Picking either would be a
    confidently wrong ARN, so the mapper falls back to the template."""
    result = map_one(mapper, "iam_events.json", "iam-0007-getrole-ambiguous-resources-array")
    assert result.requests[0].resource_arn == "arn:aws:iam::123456789012:role/AppRole"


def test_full_arn_in_request_parameters_is_used_verbatim(mapper):
    result = map_one(mapper, "iam_events.json", "iam-0004-getpolicy-full-arn-in-request")
    assert result.requests[0].resource_arn == (
        "arn:aws:iam::123456789012:policy/team/ReadOnlyish"
    )


# --- APIs that require no authorization -------------------------------------

def test_get_caller_identity_produces_no_request_at_all(mapper):
    """sts:GetCallerIdentity requires no IAM permission. Mapping it to an action
    would make a tight baseline produce a DENY on a call that was never
    authorized in the first place -- a regression manufactured by the mapper,
    and the fastest way to poison the ground-truth oracle."""
    result = map_one(mapper, "sts_events.json", "sts-0001-getcalleridentity-no-authz-needed")

    assert result.requests == ()
    assert result.reason is Reason.NO_AUTHORIZATION_REQUIRED


# --- triage of events the mapper declines to handle --------------------------

def test_unsupported_service_is_an_answer_not_a_failure(mapper):
    result = map_one(mapper, "edge_cases.json", "edge-0001-unsupported-service")
    assert result.reason is Reason.UNSUPPORTED_SERVICE
    assert result.requests == ()


def test_unmapped_event_in_a_supported_service_is_reported_as_such(mapper):
    result = map_one(mapper, "edge_cases.json", "edge-0002-unmapped-event-in-supported-service")
    assert result.reason is Reason.UNMAPPED_EVENT


def test_event_without_a_principal_is_not_evaluated(mapper):
    result = map_one(mapper, "sts_events.json", "sts-0005-assumerole-by-aws-service")
    assert result.reason is Reason.UNKNOWN_PRINCIPAL
    assert result.requests == ()


# --- partitions --------------------------------------------------------------

def test_govcloud_arns_are_built_in_the_right_partition(mapper):
    """Hardcoding arn:aws: would build an ARN no GovCloud policy matches."""
    result = map_one(mapper, "edge_cases.json", "edge-0005-govcloud-partition")
    assert result.requests[0].resource_arn == "arn:aws-us-gov:s3:::gov-bucket"


@pytest.mark.parametrize(
    "region,partition",
    [
        ("us-east-1", "aws"),
        ("eu-west-2", "aws"),
        ("us-gov-west-1", "aws-us-gov"),
        ("cn-north-1", "aws-cn"),
        ("", "aws"),
    ],
)
def test_partition_derivation(region, partition):
    assert partition_for_region(region) == partition


def test_service_extraction_from_event_source():
    assert service_from_event_source("s3.amazonaws.com") == "s3"
    assert service_from_event_source("monitoring.amazonaws.com") == "monitoring"
    assert service_from_event_source("") is None


# --- provenance --------------------------------------------------------------

def test_event_metadata_survives_mapping(mapper):
    result = map_one(mapper, "s3_events.json", "s3-0005-putbucketpolicy-denied")
    assert result.meta.event_id == "s3-0005-putbucketpolicy-denied"
    assert result.meta.event_name == "PutBucketPolicy"
    assert result.meta.error_code == "AccessDenied"
    assert result.meta.event_time.year == 2026


def test_every_fixture_event_maps_without_raising(mapper):
    """The mapper must never crash on a real event shape. Declining to map is
    an answer; an exception halts the whole replay."""
    for name in ("s3_events.json", "iam_events.json", "sts_events.json", "edge_cases.json"):
        for record in load_records(name):
            mapper.map_event(record)


def test_requests_are_hashable_for_deduplication(mapper):
    """Dedupe (§8) keys on the whole request, so every field must be hashable."""
    result = map_one(mapper, "s3_events.json", "s3-0001-listobjectsv2-success")
    assert len(set(result.requests)) == 1
