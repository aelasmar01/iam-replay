"""Triage must place every event in exactly one bucket (spec §4.1, milestone 1)."""

from __future__ import annotations

import pytest

from iam_replay.models import Outcome
from iam_replay.normalize.outcome import AUTHZ_DENIED_ERROR_CODES, classify

from .conftest import load_records

#: The bucket each fixture event must land in. Written out by event ID rather
#: than derived, so that a change to the classifier cannot quietly change what
#: the test asserts.
EXPECTED = {
    "s3-0001-listobjectsv2-success": Outcome.SUCCEEDED,
    "s3-0002-getbucketlocation-success": Outcome.SUCCEEDED,
    "s3-0003-listbuckets-success": Outcome.SUCCEEDED,
    "s3-0004-listobjectsv2-no-bucket-field": Outcome.SUCCEEDED,
    "s3-0005-putbucketpolicy-denied": Outcome.AUTHZ_DENIED,
    "s3-0006-getbuckettagging-throttled": Outcome.FAILED_POST_AUTHZ,
    "s3-0007-getbucketacl-no-tls-details": Outcome.SUCCEEDED,
    "iam-0001-getrole-with-resources-array": Outcome.SUCCEEDED,
    "iam-0002-getrole-template-fallback": Outcome.SUCCEEDED,
    "iam-0003-listroles-star-resource": Outcome.SUCCEEDED,
    "iam-0004-getpolicy-full-arn-in-request": Outcome.SUCCEEDED,
    "iam-0005-attachrolepolicy-denied": Outcome.AUTHZ_DENIED,
    "iam-0006-getrole-no-rolename-no-resources": Outcome.FAILED_POST_AUTHZ,
    "iam-0007-getrole-ambiguous-resources-array": Outcome.SUCCEEDED,
    "sts-0001-getcalleridentity-no-authz-needed": Outcome.SUCCEEDED,
    "sts-0002-assumerole-success": Outcome.SUCCEEDED,
    "sts-0003-assumerole-denied": Outcome.AUTHZ_DENIED,
    "sts-0004-assumerole-no-session-issuer": Outcome.SUCCEEDED,
    "sts-0005-assumerole-by-aws-service": Outcome.SUCCEEDED,
    "sts-0006-decodeauthorizationmessage": Outcome.SUCCEEDED,
    "edge-0001-unsupported-service": Outcome.SUCCEEDED,
    "edge-0002-unmapped-event-in-supported-service": Outcome.SUCCEEDED,
    "edge-0003-blank-error-code-is-success": Outcome.SUCCEEDED,
    "edge-0004-ec2-unauthorized-operation": Outcome.AUTHZ_DENIED,
    "edge-0005-govcloud-partition": Outcome.SUCCEEDED,
    "edge-0006-iam-user-principal": Outcome.SUCCEEDED,
}

ALL_FIXTURE_FILES = ["s3_events.json", "iam_events.json", "sts_events.json", "edge_cases.json"]


def all_records():
    for name in ALL_FIXTURE_FILES:
        yield from load_records(name)


@pytest.mark.parametrize("record", list(all_records()), ids=lambda r: r["eventID"])
def test_every_fixture_event_lands_in_the_expected_bucket(record):
    assert classify(record) is EXPECTED[record["eventID"]]


def test_every_fixture_event_has_an_expectation():
    """Guards against a fixture being added without deciding what it means."""
    seen = {record["eventID"] for record in all_records()}
    assert seen == set(EXPECTED)


def test_blank_error_code_is_not_read_as_a_failure():
    """A blank errorCode would otherwise push a success out of the oracle set."""
    assert classify({"errorCode": ""}) is Outcome.SUCCEEDED
    assert classify({"errorCode": "   "}) is Outcome.SUCCEEDED
    assert classify({}) is Outcome.SUCCEEDED


def test_non_authz_errors_stay_in_the_regression_set():
    """Dropping every errorCode would silently shrink the evidence base."""
    for code in ("ThrottlingException", "RequestLimitExceeded", "ValidationException",
                 "ResourceNotFoundException", "NoSuchBucket", "SlowDown"):
        assert classify({"errorCode": code}) is Outcome.FAILED_POST_AUTHZ


def test_dry_run_is_not_mistaken_for_a_denial():
    """ec2 --dry-run reports success via an errorCode; reading it as a denial
    would drop a legitimately authorized call from the regression set."""
    assert "DryRunOperation" not in AUTHZ_DENIED_ERROR_CODES
    assert classify({"errorCode": "DryRunOperation"}) is Outcome.FAILED_POST_AUTHZ


def test_authentication_failures_are_not_authorization_denials():
    """AuthFailure means credentials never resolved to a principal, so no
    authorization decision was reached and the event says nothing about what a
    candidate policy would do."""
    assert "AuthFailure" not in AUTHZ_DENIED_ERROR_CODES
