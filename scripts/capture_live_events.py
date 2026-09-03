#!/usr/bin/env python3
"""Snapshot real CloudTrail events from the lab account into a test fixture.

The ground-truth oracle (spec §9.1) has to replay *real* events -- hand-written
fixtures only prove the mapper matches its author's beliefs. But CI has no AWS
credentials and must be deterministic, so the events are captured once, scrubbed,
and committed.

The output is written in trail-file shape (``{"Records": [...]}``) rather than
the LookupEvents wrapper, so the committed fixture exercises the same code path
as a real synced trail.

Usage:
    AWS_PROFILE=sandbox python scripts/capture_live_events.py \
        --principal arn:aws:iam::123456789012:role/iam-replay-fixture-workload \
        --days 1 --out tests/fixtures/cloudtrail/live

Re-run whenever the fixture workload changes.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

import boto3

#: Account IDs are replaced with this so the committed fixture carries no real
#: one. The substitution is consistent, so ARNs still match across events and
#: the oracle's policy comparison stays meaningful.
PLACEHOLDER_ACCOUNT = "123456789012"

_ACCOUNT_ID = re.compile(r"\b\d{12}\b")


def lookup_events(days: int, region: str | None) -> Iterator[dict[str, Any]]:
    """Page through cloudtrail:LookupEvents, unwrapping to plain records.

    LookupEvents needs no trail: CloudTrail Event history is on by default for
    management events with 90 days of retention.
    """
    client = boto3.client("cloudtrail", region_name=region) if region else boto3.client("cloudtrail")
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)

    paginator = client.get_paginator("lookup_events")
    for page in paginator.paginate(StartTime=start, EndTime=end):
        for entry in page.get("Events", []):
            raw = entry.get("CloudTrailEvent")
            if not raw:
                continue
            try:
                yield json.loads(raw)
            except json.JSONDecodeError:
                continue


def scrub(record: Any, real_account: str) -> Any:
    """Replace the real account ID everywhere it appears, recursively."""
    if isinstance(record, dict):
        return {key: scrub(value, real_account) for key, value in record.items()}
    if isinstance(record, list):
        return [scrub(item, real_account) for item in record]
    if isinstance(record, str):
        return record.replace(real_account, PLACEHOLDER_ACCOUNT)
    return record


def matches_principal(record: dict[str, Any], wanted: str) -> bool:
    from iam_replay.normalize.principal import matches, resolve

    resolved = resolve(record.get("userIdentity"))
    return matches(resolved.arn, wanted)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--principal", required=True, help="Role ARN to capture events for")
    parser.add_argument("--days", type=int, default=1)
    parser.add_argument("--region", default=None)
    parser.add_argument("--out", default="tests/fixtures/cloudtrail/live")
    parser.add_argument(
        "--max-events",
        type=int,
        default=2000,
        help="Cap on captured events, to keep the committed fixture small",
    )
    args = parser.parse_args()

    from iam_replay.normalize.principal import normalize_principal_filter

    wanted = normalize_principal_filter(args.principal)
    real_account = _account_from_arn(wanted)
    if real_account is None:
        print(f"could not read an account ID out of {wanted!r}", file=sys.stderr)
        return 2

    captured: list[dict[str, Any]] = []
    scanned = 0
    for record in lookup_events(args.days, args.region):
        scanned += 1
        if not matches_principal(record, wanted):
            continue
        captured.append(scrub(record, real_account))
        if len(captured) >= args.max_events:
            break

    if not captured:
        print(
            f"scanned {scanned} events, none for {wanted}.\n"
            "If the workload was deployed recently, wait for a scheduled run: "
            "LookupEvents can lag a call by several minutes.",
            file=sys.stderr,
        )
        return 1

    captured.sort(key=lambda r: r.get("eventTime", ""))

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "workload_events.json"
    out_path.write_text(json.dumps({"Records": captured}, indent=2, sort_keys=True) + "\n")

    manifest = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "principal": wanted.replace(real_account, PLACEHOLDER_ACCOUNT),
        "requested_days": args.days,
        "events_scanned": scanned,
        "events_captured": len(captured),
        "account_id_replaced_with": PLACEHOLDER_ACCOUNT,
        "note": (
            "Real CloudTrail events from the fixture workload, account ID scrubbed. "
            "Regenerate with scripts/capture_live_events.py after changing the workload."
        ),
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

    remaining = sorted(_ACCOUNT_ID.findall(json.dumps(captured)) )
    leaked = {a for a in remaining if a != PLACEHOLDER_ACCOUNT}
    if leaked:
        print(f"warning: other 12-digit IDs remain in the fixture: {sorted(leaked)}", file=sys.stderr)

    print(f"captured {len(captured)} of {scanned} events -> {out_path}")
    return 0


def _account_from_arn(arn: str) -> str | None:
    parts = arn.split(":")
    return parts[4] if len(parts) > 4 and parts[4].isdigit() else None


if __name__ == "__main__":
    raise SystemExit(main())
