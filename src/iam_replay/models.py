"""Core data types shared across triage, mapping, and evaluation.

The types here are deliberately immutable and hashable: deduplication (§8) keys
on an entire ``AuthorizationRequest``, so every field it carries must be usable
inside a set.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Outcome(str, Enum):
    """Which triage bucket a CloudTrail event falls into (spec §4.1)."""

    #: Already denied under the policy in force. Excluded from the regression
    #: set -- replaying these and reporting WOULD DENY fabricates a regression.
    #: Evaluated separately for *new access* (spec §8).
    AUTHZ_DENIED = "AUTHZ_DENIED"

    #: No errorCode. The regression set, and the ground-truth oracle set (§9).
    SUCCEEDED = "SUCCEEDED"

    #: Authorization passed but the call failed afterwards (throttles,
    #: validation errors, missing resources). In the regression set, but *not*
    #: the oracle set: a front-door throttle can precede authorization, so it is
    #: not proof that the call was authorized.
    FAILED_POST_AUTHZ = "FAILED_POST_AUTHZ"


class Confidence(str, Enum):
    """How much the mapper had to assume to produce a request."""

    #: Every field came straight from the event.
    EXACT = "EXACT"

    #: The mapper supplied something the event did not state outright -- a
    #: multi-permission expansion, an implied iam:PassRole, or a principal
    #: parsed out of an ARN because sessionIssuer was absent.
    INFERRED = "INFERRED"

    #: A resource ARN could not be built because the event lacked the fields the
    #: template needs. resource_arn is None. Never guessed, never widened to "*".
    UNKNOWN_RESOURCE = "UNKNOWN_RESOURCE"


class Verdict(str, Enum):
    """The result of evaluating one request against a candidate policy (§7)."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    INDETERMINATE = "INDETERMINATE"


class Reason(str, Enum):
    """Why an event produced no confident ALLOW or DENY.

    These strings surface in the report and the JSON schema, so treat them as
    part of the public interface.
    """

    UNSUPPORTED_SERVICE = "unsupported_service"
    UNMAPPED_EVENT = "unmapped_event"
    UNKNOWN_RESOURCE = "unknown_resource"
    UNKNOWN_PRINCIPAL = "unknown_principal"

    #: A matching Allow statement referenced a condition key that CloudTrail did
    #: not record. The unevaluable keys are named alongside this reason.
    MISSING_CONDITION_KEY = "missing_condition_key"

    #: The policy referenced a key CloudTrail never carries at all (§6).
    NEVER_AVAILABLE_CONDITION_KEY = "never_available_condition_key"

    #: Not an indeterminate result: the API requires no IAM permission at all
    #: (sts:GetCallerIdentity is the canonical case), so there is nothing to
    #: authorize. These events are excluded from every verdict bucket. Mapping
    #: them to an action would make a tight policy produce a false DENY and
    #: poison the ground-truth oracle.
    NO_AUTHORIZATION_REQUIRED = "no_authorization_required"


#: Condition-key values are modelled as tuples because IAM keys can be
#: multi-valued (``aws:CalledVia``), and ``ForAllValues:``/``ForAnyValue:``
#: quantifiers in the engine (§7) need the full set rather than a joined string.
ContextValue = tuple[str, ...]


@dataclass(frozen=True)
class EventMeta:
    """Provenance for a single CloudTrail event.

    Kept separate from ``AuthorizationRequest`` so that provenance -- which is
    unique per event -- never leaks into the dedupe key, which must collapse
    millions of events into hundreds of distinct authorization shapes.
    """

    event_id: str
    event_time: datetime
    event_name: str
    event_source: str
    aws_region: str
    outcome: Outcome
    error_code: str | None = None


@dataclass(frozen=True)
class AuthorizationRequest:
    """One (principal, action, resource, context) tuple to evaluate.

    A single CloudTrail event can produce several of these: multi-permission
    events such as ``ec2:RunInstances`` expand to a list (spec §6).
    """

    principal_arn: str | None
    action: str
    resource_arn: str | None
    context: tuple[tuple[str, ContextValue], ...]
    confidence: Confidence = Confidence.EXACT

    #: Human-readable explanations for anything the mapper inferred or could not
    #: determine. Carried into the report so a reviewer can audit the mapping.
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def context_dict(self) -> dict[str, ContextValue]:
        return dict(self.context)

    @property
    def service(self) -> str:
        """The IAM service prefix, e.g. ``s3`` for ``s3:ListBucket``."""
        return self.action.split(":", 1)[0]


@dataclass(frozen=True)
class MappedEvent:
    """A triaged CloudTrail event and the requests it maps to.

    ``requests`` is empty when the event could not be mapped at all; ``reason``
    then says why. An unmappable event is an honest INDETERMINATE, not a
    failure, and it must still be counted in the report.
    """

    meta: EventMeta
    requests: tuple[AuthorizationRequest, ...] = field(default_factory=tuple)
    reason: Reason | None = None

    #: The principal the event is attributed to, resolved whether or not the
    #: event produced any request. Filtering by --principal depends on this:
    #: an unmapped or unsupported-service event still belongs to someone, and
    #: without this field every such event in the account looks like a match.
    principal_arn: str | None = None


def freeze_context(context: dict[str, ContextValue | str]) -> tuple[tuple[str, ContextValue], ...]:
    """Normalize a context dict into the hashable, sorted form requests carry.

    Single string values are wrapped into 1-tuples so that every key is
    uniformly multi-valued downstream.
    """
    frozen: list[tuple[str, ContextValue]] = []
    for key, value in context.items():
        frozen.append((key, (value,) if isinstance(value, str) else tuple(value)))
    return tuple(sorted(frozen))
