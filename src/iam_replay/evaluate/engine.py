"""IAM policy evaluation for identity-based policies (spec §7).

Standard precedence: explicit Deny beats explicit Allow beats implicit deny.
What makes this engine different from a textbook implementation is that its
input context is a *lossy record* of the request rather than the request itself,
so every rule has a third outcome for "the log does not say".

Out of scope by design (spec §2): service control policies, session policies,
and resource-based policies. A call this tool reports as allowed can still be
denied by any of them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

from ..models import AuthorizationRequest, Confidence, Reason, Verdict
from . import conditions as conditions_module
from .arn import action_matches, is_full_wildcard, resource_matches
from .conditions import Tri


#: Allowlisted services whose resources can carry a resource-based policy that
#: grants access in the same account, independently of any identity policy.
#:
#: AWS's own documentation makes the case plainly: in its worked example, a
#: principal "has no identity-based policies, but the resource-based policy
#: allows him full access". Within a single account it does not matter whether
#: the Allow comes from the identity policy or the resource policy. So for these
#: services the absence of an Allow in the candidate policy is *not* decisive,
#: and reporting a confident deny would be a confident wrong answer -- the
#: fixture demonstrated exactly that with kms:Decrypt against the aws/lambda key.
#:
#: sts is here because a role *trust* policy is a resource-based policy. AWS
#: documents that for one role to assume another within the same account, the
#: trust policy's grant is both necessary and sufficient, and the assuming
#: role's identity policy is not sufficient on its own. An implicit deny on
#: sts:AssumeRole therefore says nothing about whether the call would succeed.
#:
#: Verified against AWS documentation. Deliberately excluded:
#:
#:   iam   -- Settled, not pending review. IAM's only resource-based policy is
#:            the role trust policy, and a trust policy governs sts:AssumeRole,
#:            which is handled by the sts entry above. It does not govern
#:            iam:GetRole, iam:ListRoles or any other iam:* action -- those are
#:            authorized by identity policies alone, so an implicit deny on them
#:            is a confident answer. Adding iam here would soften correct denies
#:            into unknowns for no reason.
#:   ec2   -- no resource-based policy mechanism.
#:
#: secretsmanager, sqs and sns are named here for correctness but sit outside
#: the frozen v1 service allowlist, so no request can currently reach them.
RESOURCE_POLICY_CAPABLE_SERVICES = frozenset(
    {"s3", "kms", "lambda", "sts", "secretsmanager", "sqs", "sns"}
)


@dataclass(frozen=True)
class Decision:
    """The result of evaluating one request against one or more policies."""

    verdict: Verdict
    reason: Reason | None = None
    #: Sid (or index) of the statement that decided the outcome, when one did.
    matched_sid: str | None = None
    #: Condition keys that prevented a confident answer, named for the report.
    unevaluable_keys: tuple[str, ...] = field(default_factory=tuple)
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def is_deny(self) -> bool:
        return self.verdict is Verdict.DENY


@dataclass(frozen=True)
class _StatementMatch:
    sid: str
    condition: conditions_module.ConditionResult
    #: TRUE when the statement's action and resource both match, UNEVALUABLE
    #: when the resource ARN could not be determined and the statement is
    #: narrower than "*".
    scope: Tri


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _statements(policy: Mapping[str, Any]) -> list[tuple[str, Mapping[str, Any]]]:
    """Statements paired with a stable label for the report."""
    raw = policy.get("Statement")
    statements = _as_list(raw)
    labelled: list[tuple[str, Mapping[str, Any]]] = []
    for index, statement in enumerate(statements):
        if not isinstance(statement, Mapping):
            continue
        sid = str(statement.get("Sid") or f"statement[{index}]")
        labelled.append((sid, statement))
    return labelled


def _action_in_scope(statement: Mapping[str, Any], action: str) -> bool:
    if "NotAction" in statement:
        patterns = [str(p) for p in _as_list(statement["NotAction"])]
        return not any(action_matches(p, action) for p in patterns)
    patterns = [str(p) for p in _as_list(statement.get("Action"))]
    return any(action_matches(p, action) for p in patterns)


def _resource_in_scope(statement: Mapping[str, Any], resource_arn: str | None) -> Tri:
    """Three-valued resource match.

    A request whose resource ARN could not be determined still resolves against
    a statement scoped to ``*``, because that matches whatever the resource
    turns out to be. Against anything narrower the answer is genuinely unknown,
    and guessing either way would be a fabricated verdict.
    """
    negated = "NotResource" in statement
    element = statement.get("NotResource" if negated else "Resource")
    patterns = [str(p) for p in _as_list(element)]

    if not patterns:
        # An identity policy statement with no Resource element cannot grant or
        # deny anything on its own.
        return Tri.FALSE

    if resource_arn is None:
        if negated:
            # NotResource excludes named resources; without knowing the resource
            # we cannot say whether it falls outside the exclusion.
            return Tri.UNEVALUABLE
        return Tri.TRUE if any(is_full_wildcard(p) for p in patterns) else Tri.UNEVALUABLE

    matched = any(resource_matches(p, resource_arn) for p in patterns)
    if negated:
        matched = not matched
    return Tri.TRUE if matched else Tri.FALSE


def _match_statements(
    policy: Mapping[str, Any], request: AuthorizationRequest, effect: str
) -> list[_StatementMatch]:
    """Every statement of the given effect whose scope could cover the request."""
    context = request.context_dict
    matches: list[_StatementMatch] = []

    for sid, statement in _statements(policy):
        if str(statement.get("Effect", "")).strip() != effect:
            continue
        if not _action_in_scope(statement, request.action):
            continue

        scope = _resource_in_scope(statement, request.resource_arn)
        if scope is Tri.FALSE:
            continue

        matches.append(
            _StatementMatch(
                sid=sid,
                condition=conditions_module.evaluate(statement.get("Condition"), context),
                scope=scope,
            )
        )
    return matches


def _applies(match: _StatementMatch) -> Tri:
    """Whether a matched statement actually applies to the request."""
    if match.scope is Tri.UNEVALUABLE:
        return Tri.UNEVALUABLE
    if match.condition.value is Tri.FALSE:
        return Tri.FALSE
    if match.condition.value is Tri.UNEVALUABLE:
        return Tri.UNEVALUABLE
    return Tri.TRUE


def _unevaluable_detail(matches: Iterable[_StatementMatch]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    keys: list[str] = []
    notes: list[str] = []
    for match in matches:
        if _applies(match) is not Tri.UNEVALUABLE:
            continue
        keys.extend(match.condition.unevaluable_keys)
        notes.extend(match.condition.notes)
        if match.scope is Tri.UNEVALUABLE:
            notes.append(
                f"{match.sid}: the event did not carry enough information to "
                "build the resource ARN, and the statement is narrower than '*'"
            )
    return tuple(dict.fromkeys(keys)), tuple(dict.fromkeys(notes))


def evaluate_policy(
    policy: Mapping[str, Any],
    request: AuthorizationRequest,
    *,
    resource_policy_rule: bool = True,
) -> Decision:
    """Evaluate one request against a single identity-based policy.

    ``resource_policy_rule`` softens an implicit deny to INDETERMINATE for
    services whose resources can carry their own policy. It is switched off when
    evaluating a permission boundary: a boundary that omits an action denies it,
    and a resource policy cannot widen a boundary.
    """
    denies = _match_statements(policy, request, "Deny")
    allows = _match_statements(policy, request, "Allow")

    # 1. An explicit Deny that definitely applies settles it.
    for match in denies:
        if _applies(match) is Tri.TRUE:
            return Decision(Verdict.DENY, matched_sid=match.sid)

    applying_allows = [m for m in allows if _applies(m) is Tri.TRUE]
    unevaluable_denies = [m for m in denies if _applies(m) is Tri.UNEVALUABLE]
    unevaluable_allows = [m for m in allows if _applies(m) is Tri.UNEVALUABLE]

    if applying_allows:
        # 2. An Allow applies -- but a Deny we could not evaluate might still
        #    fire, so this is not yet an ALLOW.
        #
        #    This branch is the reason for test_unevaluable_condition_never_allows.
        #    Returning ALLOW here because "the Allow clearly matched" is the
        #    single most likely way to quietly break this engine in a refactor:
        #    it produces a confident ALLOW out of a Deny nobody could evaluate.
        if unevaluable_denies:
            keys, notes = _unevaluable_detail(unevaluable_denies)
            return Decision(
                Verdict.INDETERMINATE,
                reason=_reason_for(keys, request),
                matched_sid=unevaluable_denies[0].sid,
                unevaluable_keys=keys,
                notes=notes
                + (
                    "an Allow applies, but a Deny statement could not be "
                    "evaluated and may override it",
                ),
            )
        return Decision(Verdict.ALLOW, matched_sid=applying_allows[0].sid)

    # 3. No Allow applies. The absence of an Allow needs no context, so this is
    #    confident -- but only for services where the identity policy is the
    #    whole story. Where a resource-based policy could grant the call on its
    #    own, this evaluator simply cannot see the deciding document.
    if not unevaluable_allows:
        service = request.service
        if resource_policy_rule and service in RESOURCE_POLICY_CAPABLE_SERVICES:
            return Decision(
                Verdict.INDETERMINATE,
                reason=Reason.RESOURCE_POLICY_UNEVALUABLE,
                matched_sid=None,
                notes=(
                    "no Allow in the candidate policy matches this action and "
                    f"resource, but {service} resources can carry a resource-based "
                    "policy that grants this call on its own. This tool evaluates "
                    "identity policies only, so it cannot see that document.",
                ),
            )
        return Decision(
            Verdict.DENY,
            matched_sid=None,
            notes=("implicit deny: no Allow statement matches this action and resource",),
        )

    # 4. An Allow might apply but depends on something the event did not record.
    #    See test_unevaluable_condition_never_allows: this must never be ALLOW.
    keys, notes = _unevaluable_detail(unevaluable_allows + unevaluable_denies)
    return Decision(
        Verdict.INDETERMINATE,
        reason=_reason_for(keys, request),
        matched_sid=unevaluable_allows[0].sid,
        unevaluable_keys=keys,
        notes=notes,
    )


def _reason_for(keys: Sequence[str], request: AuthorizationRequest) -> Reason:
    from ..normalize.context import is_never_available

    if request.resource_arn is None and not keys:
        return Reason.UNKNOWN_RESOURCE
    if any(is_never_available(key) for key in keys):
        return Reason.NEVER_AVAILABLE_CONDITION_KEY
    if keys:
        return Reason.MISSING_CONDITION_KEY
    return Reason.UNKNOWN_RESOURCE


def evaluate_request(
    request: AuthorizationRequest,
    candidate_policy: Mapping[str, Any],
    boundary_policy: Mapping[str, Any] | None = None,
) -> Decision:
    """Evaluate a request against a candidate policy and optional boundary.

    A permission boundary does not grant anything; effective permission is the
    *intersection* of the identity policy and the boundary, so a call is allowed
    only when both allow it.
    """
    identity = evaluate_policy(candidate_policy, request)

    if boundary_policy is None:
        return identity

    # A boundary that omits an action denies it: a resource policy cannot widen
    # a permission boundary, so the softening rule does not apply here.
    boundary = evaluate_policy(boundary_policy, request, resource_policy_rule=False)

    # A confident deny on either side settles it: the intersection is empty.
    if identity.is_deny:
        return identity
    if boundary.is_deny:
        return Decision(
            Verdict.DENY,
            matched_sid=boundary.matched_sid,
            notes=boundary.notes + ("denied by the permission boundary",),
        )

    # Otherwise both must allow, and an unknown on either side is an unknown.
    for decision, side in ((identity, "candidate policy"), (boundary, "permission boundary")):
        if decision.verdict is Verdict.INDETERMINATE:
            return Decision(
                Verdict.INDETERMINATE,
                reason=decision.reason,
                matched_sid=decision.matched_sid,
                unevaluable_keys=decision.unevaluable_keys,
                notes=decision.notes + (f"unresolved in the {side}",),
            )

    return Decision(Verdict.ALLOW, matched_sid=identity.matched_sid)


def evaluate_mapped_request(
    request: AuthorizationRequest,
    candidate_policy: Mapping[str, Any],
    boundary_policy: Mapping[str, Any] | None = None,
) -> Decision:
    """Evaluate a request, surfacing mapping uncertainty ahead of policy logic.

    A request the mapper could not fully build is reported as such rather than
    being run through the engine, where a wildcard policy would turn a mapping
    gap into a confident ALLOW.
    """
    decision = evaluate_request(request, candidate_policy, boundary_policy)

    if request.confidence is Confidence.UNKNOWN_RESOURCE and decision.verdict is Verdict.ALLOW:
        # Only reachable when every matching statement is scoped to "*", so the
        # verdict is sound -- but say why it held despite the missing resource.
        return Decision(
            Verdict.ALLOW,
            matched_sid=decision.matched_sid,
            notes=decision.notes
            + (
                "resource ARN unknown, but every matching statement is scoped "
                "to '*' so the verdict does not depend on it",
            ),
        )
    return decision
