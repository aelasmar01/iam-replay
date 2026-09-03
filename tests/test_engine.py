"""Policy evaluation (spec §7, milestone 2).

Derived from AWS's documented policy evaluation logic for identity-based
policies: explicit Deny > explicit Allow > implicit deny.
"""

from __future__ import annotations

import pytest

from iam_replay.models import (
    AuthorizationRequest,
    Confidence,
    Reason,
    Verdict,
    freeze_context,
)
from iam_replay.evaluate.engine import (
    evaluate_mapped_request,
    evaluate_policy,
    evaluate_request,
)

ROLE = "arn:aws:iam::123456789012:role/DeployRole"
BUCKET = "arn:aws:s3:::acme-artifacts-prod"


def request(
    action: str = "s3:ListBucket",
    resource: str | None = BUCKET,
    confidence: Confidence = Confidence.EXACT,
    **context: str,
) -> AuthorizationRequest:
    base = {"aws:PrincipalArn": ROLE, "aws:RequestedRegion": "us-east-1"}
    base.update(context)
    return AuthorizationRequest(
        principal_arn=ROLE,
        action=action,
        resource_arn=resource,
        context=freeze_context(base),
        confidence=confidence,
    )


def policy(*statements) -> dict:
    return {"Version": "2012-10-17", "Statement": list(statements)}


def allow(**kwargs) -> dict:
    return {"Effect": "Allow", **kwargs}


def deny(**kwargs) -> dict:
    return {"Effect": "Deny", **kwargs}


# --- THE safety-critical rule ------------------------------------------------


def test_unevaluable_condition_never_allows():
    """The rule most likely to be quietly broken in a refactor (spec §7).

    Every shape below has a matching Allow whose condition depends on a key the
    event did not record. None of them may return ALLOW. An unevaluable
    condition is an admission of ignorance, and ignorance is not permission.
    """
    unevaluable_conditions = [
        # Key absent from the context entirely.
        {"Bool": {"aws:SecureTransport": "true"}},
        {"StringEquals": {"aws:PrincipalTag/team": "platform"}},
        {"StringLike": {"aws:ResourceTag/env": "prod*"}},
        {"ForAllValues:StringEquals": {"aws:TagKeys": "env"}},
        # IfExists does not get a free pass here: absent from the log is not
        # the same claim as absent from the request.
        {"StringEqualsIfExists": {"aws:SourceVpc": "vpc-123"}},
        # Null likewise, when the key is missing from the context.
        {"Null": {"aws:MultiFactorAuthPresent": "false"}},
        # An operator the engine does not implement must not pass silently.
        {"NotAnOperator": {"aws:PrincipalArn": ROLE}},
    ]

    for condition in unevaluable_conditions:
        decision = evaluate_request(
            request(),
            policy(allow(Action="s3:ListBucket", Resource=BUCKET, Condition=condition)),
        )
        assert decision.verdict is Verdict.INDETERMINATE, condition
        assert decision.verdict is not Verdict.ALLOW
        assert decision.unevaluable_keys, condition


def test_unevaluable_deny_blocks_an_otherwise_clean_allow():
    """A Deny nobody could evaluate might still fire. Reporting ALLOW because
    the Allow matched cleanly would manufacture a confident verdict out of a
    condition the event never recorded."""
    decision = evaluate_request(
        request(),
        policy(
            allow(Action="s3:*", Resource="*"),
            deny(
                Sid="BlockInsecure",
                Action="s3:*",
                Resource="*",
                Condition={"Bool": {"aws:SecureTransport": "false"}},
            ),
        ),
    )

    assert decision.verdict is Verdict.INDETERMINATE
    assert decision.matched_sid == "BlockInsecure"
    assert "aws:SecureTransport" in decision.unevaluable_keys
    assert any("Deny" in note for note in decision.notes)


def test_unevaluable_allow_still_denies_when_no_allow_could_apply():
    """Absence of an Allow needs no context, so an implicit deny stays
    confident even when some other statement was unevaluable."""
    decision = evaluate_request(
        request(action="s3:DeleteBucket"),
        policy(
            allow(
                Action="s3:ListBucket",
                Resource=BUCKET,
                Condition={"Bool": {"aws:SecureTransport": "true"}},
            )
        ),
    )
    assert decision.verdict is Verdict.DENY


# --- precedence --------------------------------------------------------------


def test_explicit_deny_beats_explicit_allow():
    decision = evaluate_request(
        request(),
        policy(
            allow(Sid="Broad", Action="s3:*", Resource="*"),
            deny(Sid="NoListing", Action="s3:ListBucket", Resource=BUCKET),
        ),
    )
    assert decision.verdict is Verdict.DENY
    assert decision.matched_sid == "NoListing"


def test_implicit_deny_when_nothing_matches():
    decision = evaluate_request(request(), policy(allow(Action="ec2:*", Resource="*")))
    assert decision.verdict is Verdict.DENY
    assert any("implicit deny" in note for note in decision.notes)


def test_empty_policy_denies():
    assert evaluate_request(request(), policy()).verdict is Verdict.DENY


def test_matching_allow_with_a_false_condition_is_a_confident_deny():
    """The key is present and the condition simply does not hold, so no Allow
    applies. That is an ordinary implicit deny, not an unknown."""
    decision = evaluate_request(
        request(**{"aws:RequestedRegion": "us-east-1"}),
        policy(
            allow(
                Action="s3:ListBucket",
                Resource=BUCKET,
                Condition={"StringEquals": {"aws:RequestedRegion": "eu-west-1"}},
            )
        ),
    )
    assert decision.verdict is Verdict.DENY


# --- Action / NotAction / Resource / NotResource -----------------------------


def test_action_wildcards():
    for pattern in ("s3:*", "s3:List*", "*", ["ec2:*", "s3:ListBucket"]):
        decision = evaluate_request(request(), policy(allow(Action=pattern, Resource="*")))
        assert decision.verdict is Verdict.ALLOW, pattern


def test_not_action_excludes_the_named_actions():
    excluded = evaluate_request(
        request(action="iam:DeleteRole"),
        policy(allow(NotAction="iam:*", Resource="*")),
    )
    assert excluded.verdict is Verdict.DENY

    included = evaluate_request(
        request(action="s3:ListBucket"),
        policy(allow(NotAction="iam:*", Resource="*")),
    )
    assert included.verdict is Verdict.ALLOW


def test_not_resource_excludes_the_named_resources():
    excluded = evaluate_request(
        request(),
        policy(allow(Action="s3:*", NotResource=BUCKET)),
    )
    assert excluded.verdict is Verdict.DENY

    included = evaluate_request(
        request(resource="arn:aws:s3:::other-bucket"),
        policy(allow(Action="s3:*", NotResource=BUCKET)),
    )
    assert included.verdict is Verdict.ALLOW


def test_statement_without_a_resource_element_grants_nothing():
    assert evaluate_request(request(), policy(allow(Action="s3:*"))).verdict is Verdict.DENY


def test_a_single_statement_object_is_accepted():
    """The Statement element may be one object rather than a list."""
    decision = evaluate_request(
        request(), {"Statement": allow(Action="s3:*", Resource="*")}
    )
    assert decision.verdict is Verdict.ALLOW


# --- unknown resource --------------------------------------------------------


def test_unknown_resource_resolves_against_a_wildcard_statement():
    """A statement scoped to '*' covers whatever the resource turns out to be,
    so a missing ARN does not prevent a sound verdict."""
    decision = evaluate_mapped_request(
        request(resource=None, confidence=Confidence.UNKNOWN_RESOURCE),
        policy(allow(Action="s3:ListBucket", Resource="*")),
    )
    assert decision.verdict is Verdict.ALLOW
    assert any("scoped to '*'" in note for note in decision.notes)


def test_unknown_resource_against_a_narrow_statement_is_indeterminate():
    decision = evaluate_mapped_request(
        request(resource=None, confidence=Confidence.UNKNOWN_RESOURCE),
        policy(allow(Action="s3:ListBucket", Resource=BUCKET)),
    )
    assert decision.verdict is Verdict.INDETERMINATE
    assert decision.reason is Reason.UNKNOWN_RESOURCE


def test_unknown_resource_still_denies_when_the_action_is_not_granted():
    """The action is absent from the policy entirely, so the missing resource
    changes nothing."""
    decision = evaluate_mapped_request(
        request(action="s3:DeleteBucket", resource=None, confidence=Confidence.UNKNOWN_RESOURCE),
        policy(allow(Action="s3:ListBucket", Resource="*")),
    )
    assert decision.verdict is Verdict.DENY


# --- conditions that can be evaluated ----------------------------------------


def test_condition_operators_that_hold():
    cases = [
        ({"StringEquals": {"aws:PrincipalArn": ROLE}}, {}),
        ({"StringNotEquals": {"aws:PrincipalArn": "arn:aws:iam::1:role/Other"}}, {}),
        ({"StringLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/Deploy*"}}, {}),
        ({"ArnLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/*"}}, {}),
        ({"StringEqualsIgnoreCase": {"aws:RequestedRegion": "US-EAST-1"}}, {}),
        ({"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}}, {"aws:SourceIp": "203.0.113.9"}),
        ({"NotIpAddress": {"aws:SourceIp": "10.0.0.0/8"}}, {"aws:SourceIp": "203.0.113.9"}),
        ({"Bool": {"aws:SecureTransport": "true"}}, {"aws:SecureTransport": "true"}),
        ({"Null": {"aws:SourceIp": "false"}}, {"aws:SourceIp": "203.0.113.9"}),
        ({"NumericLessThan": {"aws:MultiFactorAuthAge": "3600"}}, {"aws:MultiFactorAuthAge": "60"}),
        (
            {"DateGreaterThan": {"aws:CurrentTime": "2020-01-01T00:00:00Z"}},
            {"aws:CurrentTime": "2026-08-20T14:00:00Z"},
        ),
    ]
    for condition, extra in cases:
        decision = evaluate_request(
            request(**extra),
            policy(allow(Action="s3:*", Resource="*", Condition=condition)),
        )
        assert decision.verdict is Verdict.ALLOW, condition


def test_condition_operators_that_do_not_hold():
    cases = [
        ({"StringEquals": {"aws:PrincipalArn": "arn:aws:iam::1:role/Other"}}, {}),
        ({"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}, {"aws:SourceIp": "203.0.113.9"}),
        ({"Bool": {"aws:SecureTransport": "false"}}, {"aws:SecureTransport": "true"}),
        ({"Null": {"aws:SourceIp": "true"}}, {"aws:SourceIp": "203.0.113.9"}),
    ]
    for condition, extra in cases:
        decision = evaluate_request(
            request(**extra),
            policy(allow(Action="s3:*", Resource="*", Condition=condition)),
        )
        assert decision.verdict is Verdict.DENY, condition


def test_all_operators_in_a_condition_block_must_hold():
    decision = evaluate_request(
        request(),
        policy(
            allow(
                Action="s3:*",
                Resource="*",
                Condition={
                    "StringEquals": {"aws:PrincipalArn": ROLE},
                    "StringEqualsIgnoreCase": {"aws:RequestedRegion": "eu-west-1"},
                },
            )
        ),
    )
    assert decision.verdict is Verdict.DENY


def test_values_under_one_key_are_ored():
    decision = evaluate_request(
        request(),
        policy(
            allow(
                Action="s3:*",
                Resource="*",
                Condition={"StringEquals": {"aws:RequestedRegion": ["eu-west-1", "us-east-1"]}},
            )
        ),
    )
    assert decision.verdict is Verdict.ALLOW


def test_set_operators_over_a_multi_valued_key():
    multi = AuthorizationRequest(
        principal_arn=ROLE,
        action="s3:ListBucket",
        resource_arn=BUCKET,
        context=freeze_context({"aws:CalledVia": ("cloudformation.amazonaws.com", "lambda.amazonaws.com")}),
    )

    for_all_holds = evaluate_request(
        multi,
        policy(
            allow(
                Action="s3:*",
                Resource="*",
                Condition={
                    "ForAllValues:StringEquals": {
                        "aws:CalledVia": ["cloudformation.amazonaws.com", "lambda.amazonaws.com"]
                    }
                },
            )
        ),
    )
    assert for_all_holds.verdict is Verdict.ALLOW

    for_all_fails = evaluate_request(
        multi,
        policy(
            allow(
                Action="s3:*",
                Resource="*",
                Condition={"ForAllValues:StringEquals": {"aws:CalledVia": "lambda.amazonaws.com"}},
            )
        ),
    )
    assert for_all_fails.verdict is Verdict.DENY

    for_any = evaluate_request(
        multi,
        policy(
            allow(
                Action="s3:*",
                Resource="*",
                Condition={"ForAnyValue:StringEquals": {"aws:CalledVia": "lambda.amazonaws.com"}},
            )
        ),
    )
    assert for_any.verdict is Verdict.ALLOW


def test_condition_keys_are_matched_case_insensitively():
    decision = evaluate_request(
        request(),
        policy(allow(Action="s3:*", Resource="*",
                     Condition={"StringEquals": {"AWS:PrincipalArn": ROLE}})),
    )
    assert decision.verdict is Verdict.ALLOW


def test_never_available_keys_get_their_own_reason():
    """The user needs to know the key can never be evaluated, not merely that
    it was missing this time."""
    decision = evaluate_request(
        request(),
        policy(
            allow(
                Action="s3:*",
                Resource="*",
                Condition={"StringEquals": {"aws:ResourceTag/env": "prod"}},
            )
        ),
    )
    assert decision.reason is Reason.NEVER_AVAILABLE_CONDITION_KEY
    assert "aws:ResourceTag/env" in decision.unevaluable_keys


def test_malformed_comparison_values_are_unevaluable_not_false():
    """A non-numeric value under a Numeric operator is a broken comparison. It
    must not silently become False, which would evaluate a Deny away."""
    decision = evaluate_request(
        request(**{"aws:MultiFactorAuthAge": "not-a-number"}),
        policy(
            allow(
                Action="s3:*",
                Resource="*",
                Condition={"NumericLessThan": {"aws:MultiFactorAuthAge": "3600"}},
            )
        ),
    )
    assert decision.verdict is Verdict.INDETERMINATE


# --- permission boundary -----------------------------------------------------


def test_boundary_intersects_rather_than_grants():
    identity = policy(allow(Action="s3:*", Resource="*"))

    within = evaluate_request(request(), identity, policy(allow(Action="s3:ListBucket", Resource="*")))
    assert within.verdict is Verdict.ALLOW

    outside = evaluate_request(request(), identity, policy(allow(Action="ec2:*", Resource="*")))
    assert outside.verdict is Verdict.DENY


def test_boundary_alone_grants_nothing():
    decision = evaluate_request(
        request(),
        policy(allow(Action="ec2:*", Resource="*")),
        policy(allow(Action="s3:*", Resource="*")),
    )
    assert decision.verdict is Verdict.DENY


def test_explicit_deny_in_the_boundary_wins():
    decision = evaluate_request(
        request(),
        policy(allow(Action="s3:*", Resource="*")),
        policy(
            allow(Action="s3:*", Resource="*"),
            deny(Sid="BoundaryDeny", Action="s3:ListBucket", Resource="*"),
        ),
    )
    assert decision.verdict is Verdict.DENY
    assert any("boundary" in note for note in decision.notes)


def test_an_unresolved_boundary_makes_the_whole_result_unresolved():
    decision = evaluate_request(
        request(),
        policy(allow(Action="s3:*", Resource="*")),
        policy(
            allow(
                Action="s3:*",
                Resource="*",
                Condition={"Bool": {"aws:SecureTransport": "true"}},
            )
        ),
    )
    assert decision.verdict is Verdict.INDETERMINATE
    assert any("boundary" in note for note in decision.notes)


def test_a_confident_deny_outranks_an_unresolved_boundary():
    decision = evaluate_request(
        request(action="s3:DeleteBucket"),
        policy(allow(Action="s3:ListBucket", Resource="*")),
        policy(
            allow(
                Action="s3:*",
                Resource="*",
                Condition={"Bool": {"aws:SecureTransport": "true"}},
            )
        ),
    )
    assert decision.verdict is Verdict.DENY


# --- reporting ---------------------------------------------------------------


def test_the_deciding_statement_is_named():
    decision = evaluate_policy(
        policy(allow(Sid="AllowArtifactListing", Action="s3:ListBucket", Resource=BUCKET)),
        request(),
    )
    assert decision.matched_sid == "AllowArtifactListing"


def test_statements_without_a_sid_get_a_positional_label():
    decision = evaluate_policy(
        policy(allow(Action="s3:ListBucket", Resource=BUCKET)), request()
    )
    assert decision.matched_sid == "statement[0]"
