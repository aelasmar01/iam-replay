"""Command-line interface (spec §5, §8).

Exit codes:
    0  the replay ran and no gate was tripped
    1  a gate tripped (--fail-on-deny / --fail-on-indeterminate)
    2  a tool error: bad arguments, unreadable policy, source failure

The distinction matters in CI. Exit 1 means "the tool worked and found
something"; exit 2 means "the tool did not work, so believe nothing."
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import click
from rich.console import Console

from . import __version__
from .normalize.principal import normalize_principal_filter
from .replay import replay
from .report import json_out, table
from .window import WindowError, resolve

EXIT_OK = 0
EXIT_GATE_TRIPPED = 1
EXIT_TOOL_ERROR = 2


class ToolError(Exception):
    """Anything that means the tool could not do its job."""


def _load_policy(path: Path, label: str) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text())
    except FileNotFoundError:
        raise ToolError(f"{label} not found: {path}") from None
    except json.JSONDecodeError as exc:
        raise ToolError(f"{label} is not valid JSON ({path}): {exc}") from None

    if not isinstance(document, dict) or "Statement" not in document:
        raise ToolError(
            f"{label} does not look like an IAM policy ({path}): no Statement element"
        )
    return document


def _parse_time(value: str | None, flag: str) -> datetime | None:
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ToolError(f"{flag} is not a valid ISO-8601 timestamp: {value!r}") from None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _build_source(source: str, path: Path | None, region: str | None, start, end):
    if source == "files":
        if path is None:
            raise ToolError("--source files requires --path")
        from .sources.files import FileEventSource

        try:
            return FileEventSource(path)
        except FileNotFoundError as exc:
            raise ToolError(str(exc)) from None

    from .sources.lookup import LookupEventSource

    return LookupEventSource(start=start, end=end, region=region)


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--principal",
    required=True,
    help="Role ARN or assumed-role ARN. Session ARNs are normalized to the role.",
)
@click.option(
    "--policy",
    required=True,
    type=click.Path(path_type=Path),
    help="Candidate identity policy to replay against.",
)
@click.option(
    "--boundary",
    type=click.Path(path_type=Path),
    help="Permission boundary. Effective permission is the intersection.",
)
@click.option(
    "--source",
    type=click.Choice(["lookup", "files"]),
    default="lookup",
    show_default=True,
    help="lookup: no setup, 90 days, management events only. files: a synced trail bucket.",
)
@click.option(
    "--path",
    type=click.Path(path_type=Path),
    help="Directory or file of CloudTrail JSON, for --source files.",
)
@click.option("--days", type=int, default=None, help="Window length. Default 90, minimum 1.")
@click.option("--since", default=None, help="ISO-8601 start. Cannot be combined with --days.")
@click.option("--until", default=None, help="ISO-8601 end. Requires --since.")
@click.option("--region", default=None, help="AWS region for --source lookup.")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["table", "json"]),
    default="table",
    show_default=True,
)
@click.option("--verbose", is_flag=True, help="List every WOULD ALLOW rather than counting them.")
@click.option("--fail-on-deny", is_flag=True, help="Exit 1 if anything would be denied.")
@click.option(
    "--fail-on-indeterminate",
    is_flag=True,
    help="Exit 1 if anything could not be determined.",
)
@click.version_option(__version__, prog_name="iam-replay")
def main(
    principal: str,
    policy: Path,
    boundary: Path | None,
    source: str,
    path: Path | None,
    days: int | None,
    since: str | None,
    until: str | None,
    region: str | None,
    output_format: str,
    verbose: bool,
    fail_on_deny: bool,
    fail_on_indeterminate: bool,
) -> None:
    """Replay a principal's CloudTrail history against a candidate IAM policy.

    Reports which historical calls the candidate policy would now deny. It is a
    reviewable list, not a recommendation, and it never applies a policy.
    """
    console = Console(stderr=False)
    error_console = Console(stderr=True)

    try:
        candidate_policy = _load_policy(policy, "candidate policy")
        boundary_policy = _load_policy(boundary, "permission boundary") if boundary else None
        normalized_principal = normalize_principal_filter(principal)

        since_dt = _parse_time(since, "--since")
        until_dt = _parse_time(until, "--until")

        # Resolve the window twice: once to validate the request and enforce the
        # source ceiling before any work happens, then again once the source can
        # say how much history it actually holds.
        provisional = resolve(source, None, days, since_dt, until_dt)
        event_source = _build_source(
            source, path, region, provisional.analyzed_start, provisional.analyzed_end
        )
        window = resolve(
            source, event_source.earliest_available(), days, since_dt, until_dt
        )

        report = replay(
            events=event_source.events(),
            principal=normalized_principal,
            candidate_policy=candidate_policy,
            window=window,
            boundary_policy=boundary_policy,
        )

    except WindowError as exc:
        error_console.print(f"[red]error:[/red] {exc}")
        sys.exit(EXIT_TOOL_ERROR)
    except ToolError as exc:
        error_console.print(f"[red]error:[/red] {exc}")
        sys.exit(EXIT_TOOL_ERROR)
    except Exception as exc:  # noqa: BLE001
        # Anything unexpected is a tool error, not a finding. Never let a crash
        # look like a clean result.
        error_console.print(f"[red]error:[/red] {type(exc).__name__}: {exc}")
        sys.exit(EXIT_TOOL_ERROR)

    if output_format == "json":
        click.echo(json_out.render(report))
    else:
        table.render(report, console, verbose=verbose)

    if fail_on_deny and report.would_deny:
        sys.exit(EXIT_GATE_TRIPPED)
    if fail_on_indeterminate and report.indeterminate:
        sys.exit(EXIT_GATE_TRIPPED)
    sys.exit(EXIT_OK)


if __name__ == "__main__":
    main()
