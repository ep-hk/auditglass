"""Command line interface."""

from __future__ import annotations

import json
import sys
from datetime import timedelta
from pathlib import Path

import click

from . import __version__
from .build import assemble
from .config import load_config, parse_duration
from .errors import AuditglassError
from .models import TimeWindow, _parse_dt, utcnow
from .policy.templates import TemplateRegistry
from .trigger.payload import incident_from_payload

DEMO_DIR = Path(__file__).parent / "_demo"


def _fail(exc: Exception) -> None:
    click.secho(f"error: {exc}", fg="red", err=True)
    sys.exit(1)


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="auditglass")
def main() -> None:
    """Read-only incident forensics for engineers without production access.

    This tool retrieves evidence and explains it. It never changes anything, and it
    contains no code that could.
    """


# --------------------------------------------------------------------------- #


@main.command()
@click.option("--simulate-outage", is_flag=True,
              help="Make the metrics backend fail, to exercise the evidence-gap path.")
@click.option("--max-rounds", type=int, default=None,
              help="Override the round budget. Set to 1 to see why one query is not enough.")
@click.option("--output", type=click.Path(path_type=Path), default=None,
              help="Where to write the run directory (default: ./runs).")
def demo(simulate_outage: bool, max_rounds: int | None, output: Path | None) -> None:
    """Run the bundled synthetic incident. No backend, no credentials, no API key.

    Every record in the fixture is synthetic and was written for this repository.
    """
    try:
        config = load_config(DEMO_DIR / "config.yaml")
        if output is not None:
            config.audit.run_root = output
        if max_rounds is not None:
            config.budget.max_rounds = max_rounds
        payload = json.loads((DEMO_DIR / "alert.json").read_text(encoding="utf-8"))
        incident = incident_from_payload(payload, config, source="demo")

        assembled = assemble(
            config, simulate_outage={"metrics"} if simulate_outage else None
        )
        try:
            diagnosis = assembled.run.execute(incident)
        finally:
            assembled.close()
    except AuditglassError as exc:
        _fail(exc)
        return

    _report_result(assembled, diagnosis)


@main.command(name="run")
@click.option("--config", "config_path", required=True, type=click.Path(path_type=Path))
@click.option("--alert-payload", type=click.Path(path_type=Path),
              help="JSON alert payload, or - for stdin.")
@click.option("--service", help="Primary service, for manual invocation.")
@click.option("--since", default=None, help="Window length ending now, e.g. 45m or 2h.")
@click.option("--start", default=None, help="Explicit window start (ISO 8601).")
@click.option("--end", default=None, help="Explicit window end (ISO 8601).")
@click.option("--incident-id", default=None)
def run_cmd(config_path, alert_payload, service, since, start, end, incident_id) -> None:
    """Diagnose an incident."""
    if not alert_payload and not service:
        _fail(AuditglassError("supply either --alert-payload or --service"))

    try:
        config = load_config(config_path)
        if alert_payload:
            raw = sys.stdin.read() if str(alert_payload) == "-" else Path(
                alert_payload
            ).read_text(encoding="utf-8")
            payload = json.loads(raw)
            source = f"payload:{alert_payload}"
        else:
            payload = {"service": service}
            source = "cli"
            if start and end:
                payload["window"] = TimeWindow(_parse_dt(start), _parse_dt(end)).to_dict()
            elif since:
                now = utcnow()
                payload["window"] = TimeWindow(
                    now - timedelta(seconds=parse_duration(since)), now
                ).to_dict()
        if incident_id:
            payload["incident_id"] = incident_id

        incident = incident_from_payload(payload, config, source=source)
        assembled = assemble(config)
        try:
            diagnosis = assembled.run.execute(incident)
        finally:
            assembled.close()
    except AuditglassError as exc:
        _fail(exc)
        return
    except json.JSONDecodeError as exc:
        _fail(AuditglassError(f"alert payload is not valid JSON: {exc}"))
        return

    _report_result(assembled, diagnosis)


def _report_result(assembled, diagnosis) -> None:
    run_dir = assembled.sink.run_dir
    click.echo()
    click.secho(f"  {diagnosis.summary}", bold=True)
    click.echo()
    for finding in diagnosis.findings:
        mark = "·" if finding.confidence.value == "supported" else "?"
        cites = f"  [{', '.join(finding.evidence_ids)}]" if finding.evidence_ids else ""
        click.echo(f"  {mark} {finding.statement}{cites}")
    if diagnosis.gaps:
        click.echo()
        click.secho(f"  {len(diagnosis.gaps)} evidence gap(s):", fg="yellow")
        for gap in diagnosis.gaps:
            click.echo(f"    - {gap.template_id}: {gap.reason}")
    click.echo()
    click.echo(f"  terminated: {diagnosis.termination.value} after {diagnosis.rounds_used} round(s)")
    click.echo(f"  run directory: {run_dir}")
    click.echo(f"  report:        {run_dir / 'report.md'}")
    click.echo()


# --------------------------------------------------------------------------- #


@main.command()
@click.option("--config", "config_path", required=True, type=click.Path(path_type=Path))
@click.option("--json", "as_json", is_flag=True)
def templates(config_path: Path, as_json: bool) -> None:
    """Show the query templates a planner may choose from.

    This is the complete set of things this deployment can ask a backend. There is no
    way to express a query outside it.
    """
    try:
        config = load_config(config_path)
        registry = TemplateRegistry.load(list(config.template_files))
    except AuditglassError as exc:
        _fail(exc)
        return

    if as_json:
        click.echo(json.dumps(registry.catalogue(), indent=2))
        return

    click.echo(f"\n{len(registry)} template(s), fingerprint {registry.fingerprint()[:23]}…\n")
    for entry in registry.catalogue():
        click.secho(f"  {entry['id']}", bold=True, nl=False)
        click.echo(f"  [{entry['backend']} · {entry['kind']}]")
        if entry["description"]:
            click.echo(f"    {entry['description']}")
        for name, spec in entry["params"].items():
            bits = [spec["type"]]
            if "values" in spec:
                bits.append(str(spec["values"]))
            if "range" in spec:
                bits.append(f"{spec['range'][0]}..{spec['range'][1]}")
            if "max_seconds" in spec:
                bits.append(f"max {spec['max_seconds']}s")
            if "from" in spec:
                bits.append(f"observed {spec['from']}")
            if not spec["required"]:
                bits.append("optional")
            click.echo(f"      {name}: {' · '.join(bits)}")
        click.echo()


@main.command()
@click.option("--config", "config_path", required=True, type=click.Path(path_type=Path))
def policy(config_path: Path) -> None:
    """Show the egress allowlist. Anything not listed is denied."""
    try:
        config = load_config(config_path)
    except AuditglassError as exc:
        _fail(exc)
        return

    click.echo(f"\nconfig hash: {config.config_hash()}\n")
    if not config.policy.endpoints:
        click.secho("  no endpoints declared — every outbound request will be denied", fg="yellow")
    for endpoint in config.policy.endpoints:
        click.secho(f"  {endpoint.name}", bold=True, nl=False)
        click.echo(f"  → {endpoint.scheme}://{endpoint.host}:{endpoint.effective_port()}"
                   f"  [{endpoint.backend}]")
        click.echo(f"    methods: {', '.join(endpoint.methods)}")
        for path in endpoint.paths:
            click.echo(f"    path:    {path}")
        click.echo()
    click.echo(f"  scope.services: {', '.join(config.scope.services)}")
    for service, downstreams in config.scope.topology.items():
        click.echo(f"  {service} → {', '.join(downstreams)}")
    click.echo()


@main.command()
@click.option("--config", "config_path", required=True, type=click.Path(path_type=Path))
@click.option("--dry-run", is_flag=True, help="List what would be removed.")
def purge(config_path: Path, dry_run: bool) -> None:
    """Delete run directories past their retention period."""
    from .audit.sink import purge as purge_runs

    try:
        config = load_config(config_path)
    except AuditglassError as exc:
        _fail(exc)
        return

    removed = purge_runs(config.audit.run_root, config.audit.retention_days, dry_run)
    verb = "would remove" if dry_run else "removed"
    click.echo(f"{verb} {len(removed)} run director{'y' if len(removed) == 1 else 'ies'} "
               f"older than {config.audit.retention_days} days")
    for name in removed:
        click.echo(f"  {name}")


if __name__ == "__main__":  # pragma: no cover
    main()
