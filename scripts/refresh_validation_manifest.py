#!/usr/bin/env python3
"""Regenerate the manifest of oracle-backed event mappings.

A mapping earns a place here only by surviving both halves of the oracle
against real captured traffic:

* the positive oracle -- its requests are ALLOWed by the policy that actually
  authorized the call, and
* a negative control -- denying the exact (action, resource) the baseline names
  stops the call being allowed, proving the mapper landed on the permission a
  human wrote rather than merely on something the baseline happens to grant.

Everything else in the mapping files is *asserted*: believed correct, covered by
hand-written fixtures, never checked against AWS. The CLI prints the split at
runtime so a user replaying a production role can see whether their particular
replay touched validated ground.

Run after changing the fixture workload or recapturing events:

    python scripts/refresh_validation_manifest.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO))

from iam_replay.evaluate.engine import evaluate_mapped_request  # noqa: E402
from iam_replay.models import Outcome, Verdict  # noqa: E402
from iam_replay.normalize.mapper import Mapper  # noqa: E402
from iam_replay.sources.files import FileEventSource  # noqa: E402

LIVE = REPO / "tests" / "fixtures" / "cloudtrail" / "live"
MANIFEST = REPO / "src" / "iam_replay" / "normalize" / "validated_mappings.json"


def main() -> int:
    events_file = LIVE / "workload_events.json"
    baseline_file = LIVE / "policy-tight-baseline.json"

    if not events_file.exists() or not baseline_file.exists():
        print("no captured fixture; run scripts/capture_live_events.py first", file=sys.stderr)
        return 1

    # Imported here so the script works without the test package installed.
    sys.path.insert(0, str(REPO / "tests"))
    from test_negative_control import (  # noqa: E402
        baseline_pairs,
        negative_control_policy,
    )

    baseline = json.loads(baseline_file.read_text())
    mapper = Mapper()

    successful: list[tuple[str, str, object]] = []
    for record in FileEventSource(events_file).events():
        mapped = mapper.map_event(record)
        if mapped.meta.outcome is not Outcome.SUCCEEDED:
            continue
        service = mapped.meta.event_source.split(".", 1)[0]
        for request in mapped.requests:
            successful.append((service, mapped.meta.event_name, request))

    allowed = {
        (service, event_name)
        for service, event_name, request in successful
        if evaluate_mapped_request(request, baseline).verdict is Verdict.ALLOW
    }

    pinned: set[tuple[str, str]] = set()
    for _sid, action, resource in baseline_pairs(baseline):
        control = negative_control_policy(action, resource)
        for service, event_name, request in successful:
            decision = evaluate_mapped_request(request, control)
            if decision.verdict is Verdict.DENY and decision.matched_sid == "NegativeControl":
                pinned.add((service, event_name))

    validated = sorted(allowed & pinned)

    by_service: dict[str, list[str]] = {}
    for service, event_name in validated:
        by_service.setdefault(service, []).append(event_name)

    declared = {service: len(events) for service, events in mapper._mappings.items()}

    manifest = {
        "schema_version": "1.0.0",
        "note": (
            "Event mappings that survived both halves of the ground-truth oracle "
            "against real captured CloudTrail traffic. Every other mapping in this "
            "package is asserted, not tested against AWS. Regenerate with "
            "scripts/refresh_validation_manifest.py."
        ),
        "declared_totals": dict(sorted(declared.items())),
        "validated": {s: sorted(e) for s, e in sorted(by_service.items())},
    }

    MANIFEST.write_text(json.dumps(manifest, indent=2, sort_keys=False) + "\n")

    total_validated = sum(len(v) for v in by_service.values())
    total_declared = sum(declared.values())
    print(
        f"wrote {MANIFEST.relative_to(REPO)}: "
        f"{total_validated} validated of {total_declared} declared "
        f"({100 * total_validated / total_declared:.0f}%)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
