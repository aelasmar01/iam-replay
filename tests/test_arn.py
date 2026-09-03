"""Wildcard matching primitives (spec §7, milestone 2)."""

from __future__ import annotations

import pytest

from iam_replay.evaluate.arn import (
    action_matches,
    glob_match,
    is_full_wildcard,
    resource_matches,
)


@pytest.mark.parametrize(
    "pattern,action,expected",
    [
        ("s3:ListBucket", "s3:ListBucket", True),
        ("s3:ListBucket", "s3:GetObject", False),
        ("s3:*", "s3:ListBucket", True),
        ("s3:Get*", "s3:GetObject", True),
        ("s3:Get*", "s3:PutObject", False),
        ("*", "iam:PassRole", True),
        ("s3:List?ucket", "s3:ListBucket", True),
        ("s3:List?ucket", "s3:ListBBucket", False),
        # Actions are case-insensitive: a case-sensitive compare here would
        # miss a real Allow and report a false DENY.
        ("s3:listbucket", "s3:ListBucket", True),
        ("S3:ListBucket", "s3:listbucket", True),
    ],
)
def test_action_matching(pattern, action, expected):
    assert action_matches(pattern, action) is expected


@pytest.mark.parametrize(
    "pattern,arn,expected",
    [
        ("arn:aws:s3:::bucket", "arn:aws:s3:::bucket", True),
        ("arn:aws:s3:::bucket", "arn:aws:s3:::other", False),
        ("arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket/key.txt", True),
        ("arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket", False),
        ("arn:aws:s3:::*", "arn:aws:s3:::anything", True),
        ("*", "arn:aws:iam::123456789012:role/R", True),
        # Resource ARNs are case-sensitive: matching loosely here would cover a
        # resource the policy does not, and report a false ALLOW.
        ("arn:aws:s3:::MyBucket", "arn:aws:s3:::mybucket", False),
        ("arn:aws:iam::123456789012:role/Deploy", "arn:aws:iam::123456789012:role/deploy", False),
    ],
)
def test_resource_matching(pattern, arn, expected):
    assert resource_matches(pattern, arn) is expected


def test_regex_metacharacters_in_patterns_are_literal():
    """IAM gives no meaning to '.', '+', '[' or '('. Treating them as regex
    would change which resources a policy covers."""
    assert resource_matches("arn:aws:s3:::my.bucket", "arn:aws:s3:::my.bucket")
    assert not resource_matches("arn:aws:s3:::my.bucket", "arn:aws:s3:::myXbucket")
    assert resource_matches("arn:aws:s3:::a+b", "arn:aws:s3:::a+b")
    assert resource_matches("arn:aws:s3:::a[b]", "arn:aws:s3:::a[b]")
    assert not resource_matches("arn:aws:s3:::a[bc]", "arn:aws:s3:::ab")


def test_pattern_must_match_the_whole_value():
    """A prefix match would let 'arn:aws:s3:::bucket' cover
    'arn:aws:s3:::bucket-evil'."""
    assert not resource_matches("arn:aws:s3:::bucket", "arn:aws:s3:::bucket-evil")
    assert not action_matches("s3:List", "s3:ListBucket")


def test_wildcards_span_separators():
    assert glob_match("arn:aws:s3:::*", "arn:aws:s3:::a/b/c", case_sensitive=True)


def test_full_wildcard_detection():
    assert is_full_wildcard("*")
    assert not is_full_wildcard("arn:aws:s3:::*")
    assert not is_full_wildcard("s3:*")
