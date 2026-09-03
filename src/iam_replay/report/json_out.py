"""Machine-readable report (spec §8).

Stable schema. ``schema_version`` changes whenever a field's meaning changes,
so a consumer can fail loudly rather than silently misread a report.

Everything the table shows is here, plus the full context of every request --
the JSON is the audit artifact, so it does not collapse WOULD ALLOW to a count
the way the table does.
"""

from __future__ import annotations

import json
from typing import Any

from ..models import Verdict
from ..replay import EvaluatedGroup, ReplayReport

SCHEMA_VERSION = "1.0.0"


def _iso(value: Any) -> str | None:
    return value.isoformat() if value is not None else None


def _group_to_dict(entry: EvaluatedGroup) -> dict[str, Any]:
    request = entry.group.request
    decision = entry.decision

    return {
        "action": request.action,
        "resource": request.resource_arn,
        "principal": request.principal_arn,
        "verdict": decision.verdict.value,
        "reason": decision.reason.value if decision.reason else None,
        "matched_sid": decision.matched_sid,
        "unevaluable_condition_keys": list(decision.unevaluable_keys),
        "confidence": request.confidence.value,
        "count": entry.group.count,
        "first_seen": _iso(entry.group.first_seen),
        "last_seen": _iso(entry.group.last_seen),
        "sample_event_ids": list(entry.group.sample_event_ids),
        "event_names": sorted(entry.group.event_names),
        "outcomes": {outcome.value: n for outcome, n in entry.group.outcomes.items()},
        "context": {key: list(values) for key, values in request.context},
        "notes": list(request.notes) + list(decision.notes),
    }


def to_dict(report: ReplayReport) -> dict[str, Any]:
    window = report.window
    counts = report.counts

    return {
        "schema_version": SCHEMA_VERSION,
        "principal": report.principal,
        "window": {
            "source": window.source_name,
            "requested_days": window.requested_days,
            # Present always, never conditionally: a consumer must be able to
            # see that a 90-day request was served by 12 days of data.
            "analyzed_days": window.analyzed_days,
            # Whole days truncate: a 20-hour window is 0 analyzed_days. The
            # exact duration is here so a consumer is never misled by the round
            # number into thinking nothing was analyzed.
            "analyzed_seconds": window.analyzed_seconds,
            "analyzed_start": _iso(window.analyzed_start),
            "analyzed_end": _iso(window.analyzed_end),
            "truncated": window.truncated,
        },
        "counts": {
            "events_scanned": counts.scanned,
            "events_in_window": counts.in_window,
            "events_for_principal": counts.for_principal,
            "events_unattributable": counts.unattributable,
            "succeeded": counts.succeeded,
            "already_denied": counts.already_denied,
            "failed_post_authz": counts.failed_post_authz,
            "not_evaluated": {
                "unsupported_service": counts.unsupported_service,
                "unmapped_event": counts.unmapped_event,
                "no_authorization_required": counts.no_authorization_required,
                "unknown_principal": counts.unknown_principal,
            },
            "distinct_requests": report.distinct_requests,
        },
        "mapping_provenance": {
            "mappings_used": len(counts.mappings_used),
            "oracle_backed": len(counts.mappings_oracle_backed),
            "asserted": len(counts.mappings_used) - len(counts.mappings_oracle_backed),
            "asserted_mappings": sorted(
                f"{service}:{event}"
                for service, event in counts.mappings_used - counts.mappings_oracle_backed
            ),
        },
        "summary": {
            Verdict.DENY.value: len(report.would_deny),
            Verdict.INDETERMINATE.value: len(report.indeterminate),
            Verdict.ALLOW.value: len(report.would_allow),
            "new_access": len(report.new_access),
        },
        "would_deny": [_group_to_dict(e) for e in report.would_deny],
        "indeterminate": [_group_to_dict(e) for e in report.indeterminate],
        "new_access": [_group_to_dict(e) for e in report.new_access],
        "would_allow": [_group_to_dict(e) for e in report.would_allow],
        "caveats": list(report.caveats),
    }


def render(report: ReplayReport) -> str:
    return json.dumps(to_dict(report), indent=2, sort_keys=False)
