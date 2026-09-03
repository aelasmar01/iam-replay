"""Orchestration: events in, verdicts out (spec §4, §7, §8).

Kept separate from cli.py so the pipeline can be tested without going through
Click, and separate from the engine so evaluation stays a pure function of
(request, policy).
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from .dedupe import RequestGroup, deduplicate, split_by_outcome
from .evaluate.engine import Decision, evaluate_mapped_request
from .models import MappedEvent, Outcome, Reason, Verdict
from .normalize.mapper import Mapper, service_from_event_source
from .normalize.outcome import INCOMPLETE_DENIAL_LOGGING_CAVEAT
from .normalize.principal import matches
from .normalize.validation import is_validated
from .window import Window

DATA_EVENT_CAVEAT = (
    "Data events are not present in this trail. Object- and item-level calls "
    "(s3:GetObject, DynamoDB item operations, lambda:InvokeFunction) are not "
    "evaluated. A clean result is not evidence that nothing would break."
)

IDENTITY_POLICY_ONLY_CAVEAT = (
    "Only identity-based policies are evaluated. Service control policies, "
    "session policies, and resource-based policies (S3 bucket policies, KMS key "
    "policies) are not. A call authorized solely by a resource-based policy will "
    "appear here as a deny that would not actually occur."
)


@dataclass
class EventCounts:
    """The triage numbers that head every report (spec §4.1)."""

    scanned: int = 0
    in_window: int = 0
    for_principal: int = 0
    succeeded: int = 0
    already_denied: int = 0
    failed_post_authz: int = 0
    #: In-window events whose principal could not be resolved at all, so they
    #: cannot be attributed to anyone. Counted globally, never assumed to be
    #: this principal's.
    unattributable: int = 0
    unsupported_service: int = 0
    #: Distinct (service, eventName) mappings this run actually used, split by
    #: whether each has been validated against real AWS traffic. Surfaced in the
    #: report so a user can see whether *their* replay touched validated ground.
    mappings_used: set = field(default_factory=set)
    mappings_oracle_backed: set = field(default_factory=set)
    unmapped_event: int = 0
    no_authorization_required: int = 0
    unknown_principal: int = 0


@dataclass
class EvaluatedGroup:
    """A distinct authorization shape and what the candidate policy does to it."""

    group: RequestGroup
    decision: Decision


@dataclass
class ReplayReport:
    """Everything the table and JSON writers need."""

    principal: str
    window: Window
    counts: EventCounts = field(default_factory=EventCounts)
    would_deny: list[EvaluatedGroup] = field(default_factory=list)
    indeterminate: list[EvaluatedGroup] = field(default_factory=list)
    would_allow: list[EvaluatedGroup] = field(default_factory=list)
    new_access: list[EvaluatedGroup] = field(default_factory=list)
    caveats: list[str] = field(default_factory=list)

    @property
    def distinct_requests(self) -> int:
        return len(self.would_deny) + len(self.indeterminate) + len(self.would_allow)


def _tally_reason(counts: EventCounts, reason: Reason | None) -> None:
    if reason is Reason.UNSUPPORTED_SERVICE:
        counts.unsupported_service += 1
    elif reason is Reason.UNMAPPED_EVENT:
        counts.unmapped_event += 1
    elif reason is Reason.NO_AUTHORIZATION_REQUIRED:
        counts.no_authorization_required += 1
    elif reason is Reason.UNKNOWN_PRINCIPAL:
        counts.unknown_principal += 1


def replay(
    events: Iterable[dict[str, Any]],
    principal: str,
    candidate_policy: Mapping[str, Any],
    window: Window,
    boundary_policy: Mapping[str, Any] | None = None,
    mapper: Mapper | None = None,
) -> ReplayReport:
    """Map, triage, deduplicate and evaluate a stream of CloudTrail events."""
    mapper = mapper or Mapper()
    report = ReplayReport(principal=principal, window=window)
    counts = report.counts

    mapped_events: list[MappedEvent] = []

    for record in events:
        counts.scanned += 1
        mapped = mapper.map_event(record)

        if not window.covers(mapped.meta.event_time):
            continue
        counts.in_window += 1

        # Every event carries its resolved principal, mapped or not, so an
        # unmapped call belonging to someone else is excluded rather than
        # counted against this principal.
        if mapped.principal_arn is None:
            counts.unattributable += 1
            continue
        if not matches(mapped.principal_arn, principal):
            continue
        counts.for_principal += 1

        if mapped.meta.outcome is Outcome.SUCCEEDED:
            counts.succeeded += 1
        elif mapped.meta.outcome is Outcome.AUTHZ_DENIED:
            counts.already_denied += 1
        else:
            counts.failed_post_authz += 1

        _tally_reason(counts, mapped.reason)

        if mapped.requests:
            service = service_from_event_source(mapped.meta.event_source)
            pair = (service, mapped.meta.event_name)
            counts.mappings_used.add(pair)
            if is_validated(service, mapped.meta.event_name):
                counts.mappings_oracle_backed.add(pair)

        mapped_events.append(mapped)

    regression_set, already_denied = split_by_outcome(mapped_events)

    # Group only on context the policies actually read; see dedupe.py.
    relevant = _referenced_condition_keys(candidate_policy, boundary_policy)

    for group in deduplicate(regression_set, relevant):
        decision = evaluate_mapped_request(group.request, candidate_policy, boundary_policy)
        entry = EvaluatedGroup(group=group, decision=decision)
        if decision.verdict is Verdict.DENY:
            report.would_deny.append(entry)
        elif decision.verdict is Verdict.INDETERMINATE:
            report.indeterminate.append(entry)
        else:
            report.would_allow.append(entry)

    # Calls already denied under the current policy that the candidate would now
    # allow. Nearly free once triage exists, and often the finding a reviewer
    # most wants to see.
    for group in deduplicate(already_denied, relevant):
        decision = evaluate_mapped_request(group.request, candidate_policy, boundary_policy)
        if decision.verdict is Verdict.ALLOW:
            report.new_access.append(EvaluatedGroup(group=group, decision=decision))

    report.caveats = _caveats(report, candidate_policy)
    return report


def _referenced_condition_keys(
    candidate_policy: Mapping[str, Any], boundary_policy: Mapping[str, Any] | None
) -> frozenset[str]:
    """Every condition key the candidate or boundary policy could read."""
    from .evaluate.conditions import referenced_keys

    keys: set[str] = set()
    for policy in (candidate_policy, boundary_policy):
        if policy is None:
            continue
        for statement in _statements(policy):
            keys.update(referenced_keys(statement.get("Condition")))
    return frozenset(keys)


def _caveats(report: ReplayReport, candidate_policy: Mapping[str, Any]) -> list[str]:
    """Caveats that always apply, plus any this particular run earned."""
    from .evaluate.conditions import referenced_keys
    from .normalize.context import is_never_available

    caveats = [DATA_EVENT_CAVEAT, IDENTITY_POLICY_ONLY_CAVEAT, INCOMPLETE_DENIAL_LOGGING_CAVEAT]

    if report.window.truncated:
        caveats.append(
            f"The source held only {report.window.analyzed_days} days of history, "
            f"less than the {report.window.requested_days} requested. Everything "
            "below covers the shorter window."
        )

    never_available = sorted(
        {
            key
            for statement in _statements(candidate_policy)
            for key in referenced_keys(statement.get("Condition"))
            if is_never_available(key)
        }
    )
    if never_available:
        caveats.append(
            "The candidate policy depends on condition keys CloudTrail never "
            f"records ({', '.join(never_available)}). Every call reaching those "
            "statements is INDETERMINATE and can only be resolved by inspecting "
            "the resources themselves."
        )

    asserted = len(report.counts.mappings_used) - len(report.counts.mappings_oracle_backed)
    if asserted:
        caveats.append(
            f"{asserted} of the {len(report.counts.mappings_used)} event mappings this "
            "run used have never been checked against real AWS traffic. They are "
            "believed correct and covered by unit fixtures, but a wrong action or "
            "resource in one of them would produce a wrong verdict here."
        )

    if report.counts.unsupported_service or report.counts.unmapped_event:
        caveats.append(
            f"{report.counts.unsupported_service} events fell outside the "
            f"supported services and {report.counts.unmapped_event} had no "
            "mapping. Neither group was evaluated."
        )

    return caveats


def _statements(policy: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    raw = policy.get("Statement")
    if isinstance(raw, list):
        return [s for s in raw if isinstance(s, Mapping)]
    return [raw] if isinstance(raw, Mapping) else []
