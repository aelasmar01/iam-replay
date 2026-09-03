"""Condition operator coverage (spec §7, milestone 2).

test_engine.py checks conditions through whole-policy verdicts. This file
checks the three-valued evaluator directly, where FALSE and UNEVALUABLE are
distinguishable -- a distinction the verdict alone can hide.
"""

from __future__ import annotations

import pytest

from iam_replay.evaluate.conditions import Tri, evaluate, parse_operator, referenced_keys

CONTEXT = {
    "aws:PrincipalArn": ("arn:aws:iam::123456789012:role/DeployRole",),
    "aws:RequestedRegion": ("us-east-1",),
    "aws:SourceIp": ("203.0.113.9",),
    "aws:SecureTransport": ("true",),
    "aws:MultiFactorAuthPresent": ("false",),
    "aws:CalledVia": ("cloudformation.amazonaws.com", "lambda.amazonaws.com"),
}


@pytest.mark.parametrize(
    "operator,key,value,expected",
    [
        ("StringEquals", "aws:RequestedRegion", "us-east-1", Tri.TRUE),
        ("StringEquals", "aws:RequestedRegion", "eu-west-1", Tri.FALSE),
        ("StringNotEquals", "aws:RequestedRegion", "eu-west-1", Tri.TRUE),
        ("StringNotEquals", "aws:RequestedRegion", "us-east-1", Tri.FALSE),
        ("StringEqualsIgnoreCase", "aws:RequestedRegion", "US-EAST-1", Tri.TRUE),
        ("StringNotEqualsIgnoreCase", "aws:RequestedRegion", "US-EAST-1", Tri.FALSE),
        ("StringLike", "aws:RequestedRegion", "us-*", Tri.TRUE),
        ("StringLike", "aws:RequestedRegion", "eu-*", Tri.FALSE),
        ("StringNotLike", "aws:RequestedRegion", "eu-*", Tri.TRUE),
        ("ArnLike", "aws:PrincipalArn", "arn:aws:iam::*:role/*", Tri.TRUE),
        ("ArnEquals", "aws:PrincipalArn", "arn:aws:iam::123456789012:role/DeployRole", Tri.TRUE),
        ("ArnNotLike", "aws:PrincipalArn", "arn:aws:iam::*:user/*", Tri.TRUE),
        ("IpAddress", "aws:SourceIp", "203.0.113.0/24", Tri.TRUE),
        ("IpAddress", "aws:SourceIp", "10.0.0.0/8", Tri.FALSE),
        ("NotIpAddress", "aws:SourceIp", "10.0.0.0/8", Tri.TRUE),
        ("Bool", "aws:SecureTransport", "true", Tri.TRUE),
        ("Bool", "aws:SecureTransport", "false", Tri.FALSE),
        ("Bool", "aws:MultiFactorAuthPresent", "false", Tri.TRUE),
    ],
)
def test_operator_truth_table(operator, key, value, expected):
    assert evaluate({operator: {key: value}}, CONTEXT).value is expected


@pytest.mark.parametrize(
    "operator,value,expected",
    [
        ("NumericEquals", "60", Tri.TRUE),
        ("NumericNotEquals", "60", Tri.FALSE),
        ("NumericLessThan", "61", Tri.TRUE),
        ("NumericLessThan", "60", Tri.FALSE),
        ("NumericLessThanEquals", "60", Tri.TRUE),
        ("NumericGreaterThan", "59", Tri.TRUE),
        ("NumericGreaterThanEquals", "60", Tri.TRUE),
    ],
)
def test_numeric_operators(operator, value, expected):
    context = {"aws:MultiFactorAuthAge": ("60",)}
    assert evaluate({operator: {"aws:MultiFactorAuthAge": value}}, context).value is expected


@pytest.mark.parametrize(
    "operator,value,expected",
    [
        ("DateEquals", "2026-08-20T14:00:00Z", Tri.TRUE),
        ("DateNotEquals", "2026-08-20T14:00:00Z", Tri.FALSE),
        ("DateLessThan", "2026-08-21T00:00:00Z", Tri.TRUE),
        ("DateLessThanEquals", "2026-08-20T14:00:00Z", Tri.TRUE),
        ("DateGreaterThan", "2020-01-01T00:00:00Z", Tri.TRUE),
        ("DateGreaterThanEquals", "2026-08-20T14:00:00Z", Tri.TRUE),
    ],
)
def test_date_operators(operator, value, expected):
    context = {"aws:CurrentTime": ("2026-08-20T14:00:00Z",)}
    assert evaluate({operator: {"aws:CurrentTime": value}}, context).value is expected


def test_naive_and_epoch_timestamps_are_accepted():
    """CloudTrail-adjacent sources emit both forms; failing to parse either
    would turn a working Date condition into a spurious INDETERMINATE."""
    assert evaluate(
        {"DateGreaterThan": {"aws:CurrentTime": "2020-01-01T00:00:00"}},
        {"aws:CurrentTime": ("2026-08-20T14:00:00Z",)},
    ).value is Tri.TRUE
    assert evaluate(
        {"DateLessThan": {"aws:CurrentTime": "4102444800"}},
        {"aws:CurrentTime": ("2026-08-20T14:00:00Z",)},
    ).value is Tri.TRUE


# --- the three-valued part ---------------------------------------------------


def test_missing_key_is_unevaluable_not_false():
    result = evaluate({"StringEquals": {"aws:SourceVpc": "vpc-1"}}, CONTEXT)
    assert result.value is Tri.UNEVALUABLE
    assert result.unevaluable_keys == ("aws:SourceVpc",)


def test_if_exists_does_not_get_a_free_pass_on_a_missing_key():
    """Real IAM skips the check when the key is absent. Here absence means the
    log did not record it, which is a different claim and cannot justify
    skipping anything."""
    result = evaluate({"StringEqualsIfExists": {"aws:SourceVpc": "vpc-1"}}, CONTEXT)
    assert result.value is Tri.UNEVALUABLE


def test_if_exists_evaluates_normally_when_the_key_is_present():
    assert evaluate(
        {"StringEqualsIfExists": {"aws:RequestedRegion": "us-east-1"}}, CONTEXT
    ).value is Tri.TRUE


def test_for_all_values_on_a_missing_key_is_not_vacuously_true():
    """In IAM this passes over the empty set -- a documented gotcha. Here the
    set is not known to be empty, only unrecorded."""
    result = evaluate({"ForAllValues:StringEquals": {"aws:TagKeys": "env"}}, CONTEXT)
    assert result.value is Tri.UNEVALUABLE


def test_null_resolves_confidently_when_the_key_is_present():
    """Presence is a fact the event proves, so both directions are answerable."""
    assert evaluate({"Null": {"aws:SourceIp": "false"}}, CONTEXT).value is Tri.TRUE
    assert evaluate({"Null": {"aws:SourceIp": "true"}}, CONTEXT).value is Tri.FALSE


def test_null_is_unevaluable_when_the_key_is_absent():
    result = evaluate({"Null": {"aws:SourceVpc": "true"}}, CONTEXT)
    assert result.value is Tri.UNEVALUABLE
    assert result.unevaluable_keys == ("aws:SourceVpc",)


def test_unsupported_operator_is_unevaluable_and_says_so():
    result = evaluate({"Frobnicate": {"aws:SourceIp": "x"}}, CONTEXT)
    assert result.value is Tri.UNEVALUABLE
    assert any("Frobnicate" in note for note in result.notes)


def test_unknown_quantifier_prefix_is_not_silently_dropped():
    result = evaluate({"ForSomeValues:StringEquals": {"aws:CalledVia": "x"}}, CONTEXT)
    assert result.value is Tri.UNEVALUABLE


def test_a_definite_false_outranks_an_unevaluable_sibling():
    """The block cannot apply regardless of the unknown, and a confident FALSE
    is more useful to the reader than an unknown."""
    result = evaluate(
        {
            "StringEquals": {"aws:RequestedRegion": "eu-west-1"},
            "Bool": {"aws:SecureTransportt": "true"},
        },
        CONTEXT,
    )
    assert result.value is Tri.FALSE


def test_empty_condition_block_is_true():
    assert evaluate(None, CONTEXT).value is Tri.TRUE
    assert evaluate({}, CONTEXT).value is Tri.TRUE


# --- parsing -----------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,base,negated,quantifier,if_exists",
    [
        ("StringEquals", "StringEquals", False, None, False),
        ("StringNotEquals", "StringEquals", True, None, False),
        ("StringEqualsIfExists", "StringEquals", False, None, True),
        ("ForAnyValue:StringLike", "StringLike", False, "ForAnyValue", False),
        ("ForAllValues:StringNotLikeIfExists", "StringLike", True, "ForAllValues", True),
    ],
)
def test_operator_parsing(raw, base, negated, quantifier, if_exists):
    operator = parse_operator(raw)
    assert operator is not None
    assert (operator.base, operator.negated, operator.quantifier, operator.if_exists) == (
        base,
        negated,
        quantifier,
        if_exists,
    )


def test_unknown_operators_do_not_parse():
    assert parse_operator("Frobnicate") is None
    assert parse_operator("ForSomeValues:StringEquals") is None


def test_referenced_keys_are_reported_for_the_report():
    keys = referenced_keys(
        {
            "StringEquals": {"aws:PrincipalArn": "x", "aws:RequestedRegion": "y"},
            "Bool": {"aws:SecureTransport": "true"},
        }
    )
    assert keys == ("aws:PrincipalArn", "aws:RequestedRegion", "aws:SecureTransport")
