"""Partition CloudTrail events by authorization outcome (spec §4.1).

CloudTrail records calls that already failed. Replaying an already-denied call
and reporting WOULD DENY is a fabricated regression, and it is the fastest way
to make the whole report untrustworthy. But the opposite shortcut -- dropping
every event that carries an ``errorCode`` -- silently shrinks the evidence base
and inflates confidence in a clean result. So every event lands in exactly one
of three buckets.

Which way to err when extending ``AUTHZ_DENIED_ERROR_CODES``: misclassifying a
genuine denial as FAILED_POST_AUTHZ puts an already-denied call into the
regression set, where a candidate policy that also denies it produces a
*fabricated* WOULD DENY. Misclassifying a post-authz failure as AUTHZ_DENIED
merely drops one call from the regression set. The first error is worse, so
prefer adding a code over omitting it -- but only codes that genuinely mean
"authorization did not pass".
"""

from __future__ import annotations

from typing import Any

from ..models import Outcome

#: Curated list of errorCodes that mean the request was rejected at
#: authorization time. Reviewed against the services in the v1 allowlist:
#:
#:   AccessDenied              -- s3 and most REST services
#:   AccessDeniedException     -- the JSON-protocol services (kms, lambda, sts)
#:   UnauthorizedOperation     -- ec2
#:   Client.UnauthorizedOperation -- ec2, when the SDK prefixes the fault type
#:   Forbidden                 -- returned by some endpoints ahead of the body
#:
#: Deliberately NOT included: ``AuthFailure`` and ``InvalidClientTokenId`` are
#: authentication failures -- the credentials never resolved to a principal, so
#: no authorization decision was reached and the event says nothing about what a
#: candidate policy would do. ``DryRunOperation`` is a *success* signal from
#: ec2's --dry-run and must not be read as a denial.
AUTHZ_DENIED_ERROR_CODES = frozenset(
    {
        "AccessDenied",
        "AccessDeniedException",
        "UnauthorizedOperation",
        "Client.UnauthorizedOperation",
        "Forbidden",
    }
)

#: Printed with every report. The AUTHZ_DENIED bucket is known-incomplete:
#: CloudTrail does not log all denied requests -- denied cross-account
#: sts:AssumeRole in the target account is one documented case -- so the absence
#: of denials in a trail proves nothing.
INCOMPLETE_DENIAL_LOGGING_CAVEAT = (
    "CloudTrail does not log every denied request (denied cross-account "
    "sts:AssumeRole in the target account is one documented case), so the set "
    "of already-denied calls is incomplete and its emptiness proves nothing."
)


def error_code_of(event: dict[str, Any]) -> str | None:
    """Return the event's errorCode, treating blank strings as absent.

    Some producers emit ``"errorCode": ""`` rather than omitting the field.
    Reading that as an error would push a successful call out of the oracle set.
    """
    code = event.get("errorCode")
    if code is None:
        return None
    code = str(code).strip()
    return code or None


def classify(event: dict[str, Any]) -> Outcome:
    """Assign one CloudTrail event to exactly one outcome bucket."""
    code = error_code_of(event)
    if code is None:
        return Outcome.SUCCEEDED
    if code in AUTHZ_DENIED_ERROR_CODES:
        return Outcome.AUTHZ_DENIED
    return Outcome.FAILED_POST_AUTHZ
