"""Human-readable report (spec §8).

Ordering is deliberate: denies first, then what could not be determined, then
new access, and only then the allows -- collapsed to a count unless asked for.
A reviewer opening this wants the problems, and burying six WOULD DENY lines
under four hundred WOULD ALLOW lines is how a report goes unread.
"""

from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.text import Text

from ..models import Confidence, Verdict
from ..replay import EvaluatedGroup, ReplayReport


def _fmt(count: int) -> str:
    return f"{count:,}"


def _when(group: EvaluatedGroup) -> str:
    first = group.group.first_seen
    last = group.group.last_seen
    if first is None or last is None:
        return "-"
    if first.date() == last.date():
        return first.date().isoformat()
    return f"{first.date().isoformat()} → {last.date().isoformat()}"


def _resource(group: EvaluatedGroup) -> str:
    return group.group.request.resource_arn or "(resource could not be determined)"


def render(report: ReplayReport, console: Console, verbose: bool = False) -> None:
    _render_header(report, console)
    _render_caveats(report, console)
    _render_denies(report, console)
    _render_indeterminate(report, console)
    _render_new_access(report, console)
    _render_allows(report, console, verbose)


def _render_header(report: ReplayReport, console: Console) -> None:
    counts = report.counts
    window = report.window

    console.print()
    console.print(f"[bold]Principal:[/bold]         {report.principal}")
    console.print(f"[bold]Source:[/bold]            {window.source_name}")
    console.print(f"[bold]Window requested:[/bold]  {window.requested_days} days")

    # Printed always, not only when it differs from the request. "I analyzed 90
    # days" over a trail holding twelve is the exact false comfort this tool
    # exists to prevent, and it is invisible unless stated unconditionally.
    analyzed = f"[bold]Window analyzed:[/bold]   {window.describe()}"
    if window.truncated:
        analyzed += "  [yellow](source held less history than requested)[/yellow]"
    console.print(analyzed)

    console.print(f"[bold]Events scanned:[/bold]    {_fmt(counts.scanned)}")
    console.print(f"  for this principal: {_fmt(counts.for_principal)}")
    console.print(f"    succeeded:        {_fmt(counts.succeeded)}")
    console.print(
        f"    already denied:   {_fmt(counts.already_denied)}"
        "        [dim](excluded from the regression set)[/dim]"
    )
    console.print(f"    failed post-authz:{_fmt(counts.failed_post_authz)}")

    skipped = (
        counts.unsupported_service
        + counts.unmapped_event
        + counts.no_authorization_required
        + counts.unknown_principal
    )
    if skipped:
        console.print(
            f"  not evaluated:      {_fmt(skipped)}"
            f"  [dim](unsupported service {counts.unsupported_service}, "
            f"unmapped {counts.unmapped_event}, "
            f"no authorization required {counts.no_authorization_required}, "
            f"no principal {counts.unknown_principal})[/dim]"
        )
    if counts.unattributable:
        console.print(
            f"  unattributable:     {_fmt(counts.unattributable)}"
            "  [dim](no resolvable principal; not counted against anyone)[/dim]"
        )
    console.print(f"[bold]Distinct requests:[/bold] {_fmt(report.distinct_requests)}")


def _render_caveats(report: ReplayReport, console: Console) -> None:
    console.print()
    for caveat in report.caveats:
        console.print(Text("⚠ ", style="yellow") + Text(caveat, style="yellow"))


def _section(console: Console, title: str, style: str, count: int) -> None:
    console.print()
    console.print(f"[bold {style}]{title}[/bold {style}]  ({count})")


def _confidence_marker(group: EvaluatedGroup) -> str:
    confidence = group.group.request.confidence
    if confidence is Confidence.EXACT:
        return ""
    return f" [dim]({confidence.value.lower()})[/dim]"


def _render_denies(report: ReplayReport, console: Console) -> None:
    _section(console, "WOULD DENY", "red", len(report.would_deny))
    if not report.would_deny:
        console.print("  [dim]none[/dim]")
        return

    table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
    table.add_column("Action")
    table.add_column("Resource", overflow="fold")
    table.add_column("Calls", justify="right")
    table.add_column("Seen")
    table.add_column("Why")

    for entry in report.would_deny:
        why = entry.decision.matched_sid or "implicit deny"
        if entry.decision.matched_sid:
            why = f"explicit Deny: {why}"
        table.add_row(
            entry.group.request.action + _confidence_marker(entry),
            _resource(entry),
            _fmt(entry.group.count),
            _when(entry),
            why,
        )
    console.print(table)


def _render_indeterminate(report: ReplayReport, console: Console) -> None:
    _section(console, "INDETERMINATE", "yellow", len(report.indeterminate))
    if not report.indeterminate:
        console.print("  [dim]none[/dim]")
        return

    console.print(
        "  [dim]The event did not record what these statements depend on. "
        "Not a guess in either direction.[/dim]"
    )

    by_reason: dict[str, list[EvaluatedGroup]] = {}
    for entry in report.indeterminate:
        reason = entry.decision.reason.value if entry.decision.reason else "unknown"
        by_reason.setdefault(reason, []).append(entry)

    for reason, entries in sorted(by_reason.items()):
        console.print(f"\n  [bold]{reason}[/bold]")
        for entry in entries:
            keys = ", ".join(entry.decision.unevaluable_keys)
            detail = f" — unevaluable: {keys}" if keys else ""
            console.print(
                f"    {entry.group.request.action} on {_resource(entry)} "
                f"[dim]×{_fmt(entry.group.count)}[/dim]{detail}"
            )


def _render_new_access(report: ReplayReport, console: Console) -> None:
    _section(console, "NEW ACCESS", "cyan", len(report.new_access))
    if not report.new_access:
        console.print("  [dim]none[/dim]")
        return

    console.print(
        "  [dim]Calls denied under the current policy that the candidate would "
        "now allow.[/dim]"
    )
    for entry in report.new_access:
        console.print(
            f"    {entry.group.request.action} on {_resource(entry)} "
            f"[dim]×{_fmt(entry.group.count)}[/dim]"
        )


def _render_allows(report: ReplayReport, console: Console, verbose: bool) -> None:
    _section(console, "WOULD ALLOW", "green", len(report.would_allow))
    if not verbose:
        total = sum(entry.group.count for entry in report.would_allow)
        console.print(
            f"  [dim]{_fmt(len(report.would_allow))} distinct requests, "
            f"{_fmt(total)} calls. Use --verbose to list them.[/dim]"
        )
        return

    for entry in report.would_allow:
        console.print(
            f"    {entry.group.request.action} on {_resource(entry)} "
            f"[dim]×{_fmt(entry.group.count)}[/dim]"
        )
