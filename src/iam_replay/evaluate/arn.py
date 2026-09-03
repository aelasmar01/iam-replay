"""Wildcard matching for IAM actions and resource ARNs (spec §7).

IAM policy elements support two wildcards: ``*`` for any sequence of characters
and ``?`` for exactly one. Everything else is literal, which is why patterns are
regex-escaped rather than handed to :mod:`fnmatch` -- fnmatch would give ``[``
and ``]`` character-class meaning that IAM does not, silently changing which
resources a policy matches.

Case sensitivity differs between the two elements and getting it backwards
produces wrong verdicts in both directions:

* **Actions are case-insensitive.** ``s3:listbucket`` and ``s3:ListBucket`` are
  the same action, so a case-sensitive compare would miss a real Allow and
  report a false DENY.
* **Resource ARNs are case-sensitive.** Bucket names, key paths and role names
  are distinct when they differ only in case, so a case-insensitive compare
  would match a resource the policy does not cover and report a false ALLOW.
"""

from __future__ import annotations

import re
from functools import lru_cache


@lru_cache(maxsize=4096)
def _compile(pattern: str, case_sensitive: bool) -> re.Pattern[str]:
    parts: list[str] = []
    for char in pattern:
        if char == "*":
            parts.append(".*")
        elif char == "?":
            parts.append(".")
        else:
            parts.append(re.escape(char))
    flags = 0 if case_sensitive else re.IGNORECASE
    return re.compile("".join(parts) + r"\Z", flags | re.DOTALL)


def glob_match(pattern: str, value: str, *, case_sensitive: bool) -> bool:
    """Match ``value`` against an IAM pattern using only ``*`` and ``?``."""
    return _compile(pattern, case_sensitive).match(value) is not None


def action_matches(pattern: str, action: str) -> bool:
    """Whether a policy Action element matches a requested action."""
    return glob_match(pattern, action, case_sensitive=False)


def resource_matches(pattern: str, resource_arn: str) -> bool:
    """Whether a policy Resource element matches a resource ARN."""
    return glob_match(pattern, resource_arn, case_sensitive=True)


def is_full_wildcard(pattern: str) -> bool:
    """Whether a pattern matches every possible value.

    Used to decide whether a request whose resource ARN could not be determined
    (Confidence.UNKNOWN_RESOURCE) can still be resolved: a statement scoped to
    ``*`` matches regardless of what the resource turns out to be, while any
    narrower pattern cannot be evaluated at all.
    """
    return pattern == "*"
