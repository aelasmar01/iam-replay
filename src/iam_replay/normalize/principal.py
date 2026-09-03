"""Resolve a CloudTrail ``userIdentity`` to the principal a policy applies to (§4.2).

For a role session, ``userIdentity.arn`` is the *session* ARN --
``arn:aws:sts::123456789012:assumed-role/AppRole/session-name`` -- not the role
ARN. That is the common case for exactly the CI/CD, automation, and agent roles
this tool targets, so matching it against a candidate policy written for the
role requires explicit normalization rather than an incidental string compare.

Prefer ``sessionContext.sessionIssuer.arn``, which is the role ARN directly.
Parsing the session ARN is a fallback only, and is marked INFERRED, because the
session ARN omits the role's path: a role at ``/service-role/AppRole`` produces
``assumed-role/AppRole/session``, from which the correct role ARN
``arn:aws:iam::123456789012:role/service-role/AppRole`` cannot be recovered.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

_ASSUMED_ROLE_ARN = re.compile(
    r"^arn:(?P<partition>[^:]+):sts::(?P<account>\d+):assumed-role/(?P<role>[^/]+)/(?P<session>.+)$"
)
_ROLE_ARN = re.compile(
    r"^arn:(?P<partition>[^:]+):iam::(?P<account>\d+):role/(?P<path_and_name>.+)$"
)


@dataclass(frozen=True)
class ResolvedPrincipal:
    """The principal ARN a candidate policy should be evaluated for.

    ``arn`` is None when the event has no IAM principal to speak of -- an
    AWS service calling on its own behalf, for instance. That is a legitimate
    outcome, not an error, and it must not be papered over with a guess.
    """

    arn: str | None
    inferred: bool = False
    notes: tuple[str, ...] = field(default_factory=tuple)


def _role_arn_from_session(session_arn: str) -> str | None:
    """Rebuild a role ARN from an assumed-role session ARN. Lossy: see module docstring."""
    match = _ASSUMED_ROLE_ARN.match(session_arn)
    if match is None:
        return None
    return "arn:{partition}:iam::{account}:role/{role}".format(**match.groupdict())


def resolve(user_identity: dict[str, Any] | None) -> ResolvedPrincipal:
    """Normalize a CloudTrail ``userIdentity`` block to a principal ARN."""
    if not user_identity:
        return ResolvedPrincipal(None, notes=("event has no userIdentity block",))

    identity_type = user_identity.get("type")
    arn = (user_identity.get("arn") or "").strip() or None

    if identity_type == "AssumedRole":
        session_context = user_identity.get("sessionContext") or {}
        issuer_arn = ((session_context.get("sessionIssuer") or {}).get("arn") or "").strip()
        if issuer_arn:
            return ResolvedPrincipal(issuer_arn)

        # sessionIssuer absent. Fall back to parsing, and say so: the result is
        # wrong for any role that lives under a path.
        if arn and (parsed := _role_arn_from_session(arn)):
            return ResolvedPrincipal(
                parsed,
                inferred=True,
                notes=(
                    "role ARN parsed from the session ARN because "
                    "sessionContext.sessionIssuer was absent; incorrect if the "
                    "role has a path such as /service-role/",
                ),
            )
        return ResolvedPrincipal(
            None,
            notes=("assumed-role identity with neither sessionIssuer nor a parsable ARN",),
        )

    if identity_type == "AWSService":
        invoked_by = user_identity.get("invokedBy") or "an AWS service"
        return ResolvedPrincipal(
            None,
            notes=(f"call made by {invoked_by} on its own behalf; no IAM principal",),
        )

    if arn:
        return ResolvedPrincipal(arn)

    return ResolvedPrincipal(
        None,
        notes=(f"userIdentity of type {identity_type!r} carries no ARN",),
    )


def normalize_principal_filter(arn: str) -> str:
    """Normalize a user-supplied ``--principal`` to a role ARN for filtering.

    Accepts either a role ARN or an assumed-role session ARN. A session ARN is
    normalized to the role ARN so that ``--principal`` matches what ``resolve``
    produces; anything else is returned unchanged so IAM users and other
    principal types still work.
    """
    arn = arn.strip()
    if (role_arn := _role_arn_from_session(arn)) is not None:
        return role_arn
    return arn


def matches(resolved: str | None, wanted: str) -> bool:
    """Whether a resolved principal ARN is the one the user asked about.

    Compared case-insensitively: IAM enforces case-insensitive uniqueness on
    role names, so two roles differing only in case cannot coexist, and a
    case-sensitive compare would silently drop every event for a principal the
    user typed with different capitalization.
    """
    if resolved is None:
        return False
    return resolved.casefold() == wanted.casefold()
