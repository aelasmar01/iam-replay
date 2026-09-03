"""Extract the IAM condition-key context a CloudTrail event genuinely carries (§6).

The governing rule: extract only what is actually present. A candidate policy
containing ``Deny ... Condition: {Bool: {aws:SecureTransport: false}}`` must not
have that deny evaluated away on an assumption. Hardcoding
``aws:SecureTransport = true`` is empirically almost always right, which is
precisely the reasoning the three-state output exists to reject -- when the key
is absent the honest answer is INDETERMINATE.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from ..models import ContextValue
from .principal import ResolvedPrincipal

#: Condition keys CloudTrail never carries, for any event. When a candidate
#: policy depends on one of these, the request is INDETERMINATE and the key is
#: named in the reason -- the user needs to know *which* key defeated the
#: evaluation, not merely that something did.
NEVER_AVAILABLE_KEY_PREFIXES = (
    "aws:ResourceTag/",
    "aws:PrincipalTag/",
    "aws:RequestTag/",
)
NEVER_AVAILABLE_KEYS = frozenset({"aws:TagKeys"})


def is_never_available(key: str) -> bool:
    """Whether a condition key can never be sourced from a CloudTrail event."""
    folded = key.casefold()
    if folded in {k.casefold() for k in NEVER_AVAILABLE_KEYS}:
        return True
    return any(folded.startswith(p.casefold()) for p in NEVER_AVAILABLE_KEY_PREFIXES)


def _is_ip_address(value: str) -> bool:
    """Whether ``sourceIPAddress`` holds a real IP rather than a service string.

    CloudTrail puts a service principal (``ec2.amazonaws.com``) or a literal
    like ``AWS Internal`` in this field when the call did not come from a
    client IP. Setting aws:SourceIp from those would make an IpAddress condition
    evaluate against nonsense, so parse rather than pattern-match.
    """
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def extract(event: dict[str, Any], principal: ResolvedPrincipal) -> dict[str, ContextValue]:
    """Build the condition-key context for one event.

    Every key is either present with a value taken from the event, or absent.
    There is no third state and no default.
    """
    context: dict[str, ContextValue] = {}
    user_identity: dict[str, Any] = event.get("userIdentity") or {}

    # Set from the *normalized role* ARN, not the session ARN: a policy
    # condition on aws:PrincipalArn is written against the role.
    if principal.arn:
        context["aws:PrincipalArn"] = (principal.arn,)

    if account_id := (user_identity.get("accountId") or "").strip():
        context["aws:PrincipalAccount"] = (account_id,)

    source_ip = (event.get("sourceIPAddress") or "").strip()
    if source_ip and _is_ip_address(source_ip):
        context["aws:SourceIp"] = (source_ip,)

    if user_agent := (event.get("userAgent") or "").strip():
        context["aws:UserAgent"] = (user_agent,)

    session_attributes = (user_identity.get("sessionContext") or {}).get("attributes") or {}
    mfa = session_attributes.get("mfaAuthenticated")
    if mfa is not None and str(mfa).strip():
        context["aws:MultiFactorAuthPresent"] = (str(mfa).strip().lower(),)

    if region := (event.get("awsRegion") or "").strip():
        context["aws:RequestedRegion"] = (region,)

    # Only when the event proves TLS was used. Absent tlsDetails, the key is
    # omitted entirely -- see the module docstring.
    if event.get("tlsDetails"):
        context["aws:SecureTransport"] = ("true",)

    # invokedBy means an AWS service made the call. aws:CalledVia is populated
    # from it rather than from a separate field, which is an approximation:
    # CalledVia is defined only for a specific set of forwarding services.
    if invoked_by := (user_identity.get("invokedBy") or "").strip():
        context["aws:ViaAWSService"] = ("true",)
        context["aws:CalledVia"] = (invoked_by,)

    return context
