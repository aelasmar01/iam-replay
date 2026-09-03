"""Collapse events into distinct authorization shapes (spec §8).

Millions of CloudTrail events collapse to hundreds of distinct authorization
shapes. Evaluating the distinct set and reporting with counts is what makes a
90-day replay tractable, and it is also what makes the report readable: a
reviewer wants to see "this call would break, 41,000 times" once, not 41,000
times.

The dedupe key is ``(principal_arn, action, resource_arn, context)`` -- the four
things the engine actually evaluates. Confidence and mapper notes are
deliberately *not* part of the key: the same authorization shape can arrive with
different confidence when one event carried ``sessionIssuer`` and another did
not. Those groups merge, keeping the lowest confidence seen and the union of the
notes, so the report never overstates how sure the mapper was.

**Only the context keys the policy actually references take part in the key.**
Evaluation reads no other key, so two requests differing only in, say,
``aws:UserAgent`` are guaranteed to evaluate identically -- splitting them
produces several identical rows in the report and no additional information. In
practice this is the difference between one ``iam:GetRole`` row and one row per
Lambda container that happened to run. Passing no key set keeps every key, which
is the conservative default for callers that have no policy in hand.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable

from .models import (
    AuthorizationRequest,
    Confidence,
    ContextValue,
    EventMeta,
    MappedEvent,
    Outcome,
)

#: Lowest (most cautious) first. Used to pick the confidence of a merged group.
_CONFIDENCE_ORDER = {
    Confidence.UNKNOWN_RESOURCE: 0,
    Confidence.INFERRED: 1,
    Confidence.EXACT: 2,
}

#: Cap on retained event IDs per group, per spec §8. Enough to go look one up
#: in the console, not enough to bloat the JSON output.
SAMPLE_LIMIT = 3

DedupeKey = tuple[str | None, str, str | None, tuple[tuple[str, ContextValue], ...]]


@dataclass
class RequestGroup:
    """One distinct authorization shape, with how often it occurred."""

    request: AuthorizationRequest
    count: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    sample_event_ids: list[str] = field(default_factory=list)
    #: How many distinct raw contexts collapsed into this group. Greater than 1
    #: means the events differed only in keys the policy does not reference.
    context_variants: set[tuple[tuple[str, ContextValue], ...]] = field(default_factory=set)
    #: Which outcome buckets contributed. A group is nearly always homogeneous,
    #: but a call that succeeded sometimes and was throttled other times lands
    #: in both, and the report should not have to guess.
    outcomes: Counter = field(default_factory=Counter)
    event_names: set[str] = field(default_factory=set)

    def absorb(self, meta: EventMeta, request: AuthorizationRequest) -> None:
        self.count += 1
        self.outcomes[meta.outcome] += 1
        self.context_variants.add(request.context)
        self.event_names.add(meta.event_name)

        if self.first_seen is None or meta.event_time < self.first_seen:
            self.first_seen = meta.event_time
        if self.last_seen is None or meta.event_time > self.last_seen:
            self.last_seen = meta.event_time
        if len(self.sample_event_ids) < SAMPLE_LIMIT and meta.event_id:
            self.sample_event_ids.append(meta.event_id)

        # Keep the most cautious confidence and every note, so merging groups
        # can only ever lower the claimed certainty.
        if _CONFIDENCE_ORDER[request.confidence] < _CONFIDENCE_ORDER[self.request.confidence]:
            merged_notes = tuple(dict.fromkeys(self.request.notes + request.notes))
            self.request = AuthorizationRequest(
                principal_arn=request.principal_arn,
                action=request.action,
                resource_arn=request.resource_arn,
                context=request.context,
                confidence=request.confidence,
                notes=merged_notes,
            )
        elif request.notes and set(request.notes) - set(self.request.notes):
            merged_notes = tuple(dict.fromkeys(self.request.notes + request.notes))
            self.request = AuthorizationRequest(
                principal_arn=self.request.principal_arn,
                action=self.request.action,
                resource_arn=self.request.resource_arn,
                context=self.request.context,
                confidence=self.request.confidence,
                notes=merged_notes,
            )


def key_for(
    request: AuthorizationRequest, relevant_keys: frozenset[str] | None = None
) -> DedupeKey:
    """Build the grouping key, optionally ignoring context the policy never reads."""
    context = request.context
    if relevant_keys is not None:
        folded = {key.casefold() for key in relevant_keys}
        context = tuple((k, v) for k, v in context if k.casefold() in folded)
    return (request.principal_arn, request.action, request.resource_arn, context)


def deduplicate(
    mapped_events: Iterable[MappedEvent],
    relevant_keys: frozenset[str] | None = None,
) -> list[RequestGroup]:
    """Group requests by authorization shape, newest-heaviest first.

    Sorted by count descending so the report leads with what matters most; ties
    break on action name so output is stable between runs over the same data.
    """
    groups: dict[DedupeKey, RequestGroup] = {}

    for mapped in mapped_events:
        for request in mapped.requests:
            key = key_for(request, relevant_keys)
            group = groups.get(key)
            if group is None:
                group = RequestGroup(request=request)
                groups[key] = group
            group.absorb(mapped.meta, request)

    return sorted(
        groups.values(),
        key=lambda g: (-g.count, g.request.action, g.request.resource_arn or ""),
    )


def split_by_outcome(
    mapped_events: Iterable[MappedEvent],
) -> tuple[list[MappedEvent], list[MappedEvent]]:
    """Partition into the regression set and the already-denied set (spec §4.1).

    The regression set is everything that got past authorization: SUCCEEDED
    plus FAILED_POST_AUTHZ. The already-denied set is evaluated separately, for
    *new access* the candidate policy would grant -- reporting those as
    regressions would fabricate them.
    """
    regression: list[MappedEvent] = []
    already_denied: list[MappedEvent] = []

    for mapped in mapped_events:
        if mapped.meta.outcome is Outcome.AUTHZ_DENIED:
            already_denied.append(mapped)
        else:
            regression.append(mapped)

    return regression, already_denied
