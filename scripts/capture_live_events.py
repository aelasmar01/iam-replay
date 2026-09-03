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

#: Matches a 12-digit run only where an account ID actually lives -- inside an
#: ARN's account field, or an accountId/recipientAccountId value. A bare
#: \b\d{12}\b also matches segments of UUIDs (event IDs contain a 12-hex-digit
#: tail, which is sometimes all decimal), producing false leak warnings.
_ACCOUNT_ID = re.compile(
    r"arn:[a-z0-9-]*:[^:\"]*:[^:\"]*:(\d{12}):"
    r"|\"(?:recipientAccountId|accountId)\"\s*:\s*\"(\d{12})\""
)


def lookup_events(
    days: int, region: str | None, since: datetime | None = None
) -> Iterator[dict[str, Any]]:
    """Page through cloudtrail:LookupEvents, unwrapping to plain records.

    LookupEvents needs no trail: CloudTrail Event history is on by default for
    management events with 90 days of retention.

    ``since`` overrides the day count. It exists because the fixture workload's
    history is not immutable: changing the workload leaves older events in the
    window that no longer reflect what it does, and those would be replayed
    against a baseline written for the current workload.
    """
    client = boto3.client("cloudtrail", region_name=region) if region else boto3.client("cloudtrail")
    end = datetime.now(timezone.utc)
    start = since if since is not None else end - timedelta(days=days)

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
    parser.add_argument(
        "--since",
        default=None,
        help=(
            "ISO-8601 start time, overriding --days. Use after changing the "
            "workload so stale events are not captured alongside current ones."
        ),
    )
    parser.add_argument("--region", default=None)
    parser.add_argument("--out", default="tests/fixtures/cloudtrail/live")
    parser.add_argument(
        "--name",
        default="workload_events",
        help="Basename for the captured file, so a second principal can be "
             "captured alongside the workload role without overwriting it.",
    )
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

    since = None
    if args.since:
        since = datetime.fromisoformat(args.since.replace("Z", "+00:00"))
        if since.tzinfo is None:
            since = since.replace(tzinfo=timezone.utc)

    captured: list[dict[str, Any]] = []
    scanned = 0
    for record in lookup_events(args.days, args.region, since):
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
    out_path = out_dir / f"{args.name}.json"
    out_path.write_text(json.dumps({"Records": captured}, indent=2, sort_keys=True) + "\n")

    manifest = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "principal": wanted.replace(real_account, PLACEHOLDER_ACCOUNT),
        "requested_days": args.days,
        "since": args.since,
        "events_scanned": scanned,
        "events_captured": len(captured),
        "account_id_replaced_with": PLACEHOLDER_ACCOUNT,
        "note": (
            "Real CloudTrail events from the fixture workload, account ID scrubbed. "
            "Regenerate with scripts/capture_live_events.py after changing the workload."
        ),
    }
    (out_dir / f"{args.name}-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

    found = {
        account
        for match in _ACCOUNT_ID.finditer(json.dumps(captured))
        for account in match.groups()
        if account
    }
    leaked = found - {PLACEHOLDER_ACCOUNT}
    if leaked:
        print(f"warning: other 12-digit IDs remain in the fixture: {sorted(leaked)}", file=sys.stderr)

    print(f"captured {len(captured)} of {scanned} events -> {out_path}")
    return 0


def _account_from_arn(arn: str) -> str | None:
    parts = arn.split(":")
    return parts[4] if len(parts) > 4 and parts[4].isdigit() else None


if __name__ == "__main__":
    raise SystemExit(main())
