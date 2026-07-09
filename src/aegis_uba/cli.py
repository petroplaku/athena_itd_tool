"""Aegis UBA command-line interface (Typer + Rich).

Runs on Linux, Windows and macOS with the same commands. Typical workflow::

    aegis init
    aegis generate --users 30 --days 30      # or: aegis ingest events.csv
    aegis analyze --respond
    aegis alerts
    aegis report
    aegis serve                              # launch the web dashboard
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from aegis_uba import __version__
from aegis_uba.config import get_config
from aegis_uba.datasets import REGISTRY, detect_cert_release, list_datasets, load_dataset
from aegis_uba.detect import Analyzer
from aegis_uba.ingest import generate_synthetic, load_events_from_file, sniff_format
from aegis_uba.models import RiskLevel
from aegis_uba.report import write_reports
from aegis_uba.response import ResponseAction, auto_respond, dispatch
from aegis_uba.storage import Store

app = typer.Typer(
    add_completion=True,
    no_args_is_help=True,
    help="Aegis UBA — AI-driven Insider Threat & User Behavior Analytics.",
)
console = Console()

_LEVEL_STYLE = {
    "LOW": "green",
    "MEDIUM": "yellow",
    "HIGH": "red",
    "CRITICAL": "bold white on red",
}


def _store() -> Store:
    return Store(get_config().db_path)


def _banner() -> None:
    console.print(Panel.fit(
        "[bold cyan]🛡  Aegis UBA[/]  [dim]v%s[/]\n"
        "[dim]AI-driven Insider Threat & User Behavior Analytics[/]" % __version__,
        border_style="cyan"))


# ---------------------------------------------------------------------------
@app.command()
def version() -> None:
    """Show version and data locations."""
    cfg = get_config()
    _banner()
    console.print(f"[dim]Data home:[/] {cfg.home}")
    console.print(f"[dim]Database :[/] {cfg.db_path}")
    console.print(f"[dim]Reports  :[/] {cfg.reports_dir}")


@app.command()
def init() -> None:
    """Initialize configuration and the local database."""
    cfg = get_config()
    cfg.save()
    _store()  # creates schema
    _banner()
    console.print(f"[green]✓[/] Initialized at [bold]{cfg.home}[/]")
    console.print("[dim]Next:[/] aegis generate  →  aegis analyze  →  aegis serve")


@app.command()
def generate(
    users: int = typer.Option(25, help="Number of synthetic users."),
    days: int = typer.Option(30, help="Days of history to generate."),
    seed: int = typer.Option(1337, help="Random seed for reproducibility."),
    out: Optional[Path] = typer.Option(None, help="Also export events to a CSV file."),
    reset: bool = typer.Option(False, "--reset", help="Clear existing events first."),
) -> None:
    """Generate a realistic synthetic dataset with planted insider-threat scenarios."""
    store = _store()
    if reset:
        store.reset()
    with console.status("[cyan]Generating synthetic activity…"):
        events, planted = generate_synthetic(users=users, days=days, seed=seed)
        n = store.add_events(events)
    console.print(f"[green]✓[/] Ingested [bold]{n}[/] events for [bold]{users}[/] users "
                  f"over [bold]{days}[/] days.")
    console.print(f"[dim]Planted scenarios (ground truth): "
                  f"{', '.join(sorted({p['scenario'] for p in planted}))}[/]")
    if out:
        _export_csv(events, out)
        console.print(f"[green]✓[/] Wrote CSV → [bold]{out}[/]")


@app.command()
def ingest(
    path: Path = typer.Argument(..., exists=True, help="CSV / JSON / auth.log file."),
    fmt: Optional[str] = typer.Option(None, "--format", help="csv | json | authlog (auto if omitted)."),
    reset: bool = typer.Option(False, "--reset", help="Clear existing events first."),
) -> None:
    """Ingest and normalize events from a real log/export file."""
    store = _store()
    if reset:
        store.reset()
    detected = fmt or sniff_format(path)
    with console.status(f"[cyan]Parsing {detected} → normalizing events…"):
        events = load_events_from_file(path, fmt)
        n = store.add_events(events)
    if n == 0:
        console.print("[yellow]⚠ No events parsed. Check the file format / columns.[/]")
        raise typer.Exit(code=1)
    console.print(f"[green]✓[/] Ingested [bold]{n}[/] events "
                  f"([dim]{detected}[/]) from [bold]{path.name}[/].")


@app.command()
def train(
    contamination: Optional[float] = typer.Option(None, help="Override anomaly fraction for training."),
) -> None:
    """Train the anomaly model on stored events and persist it for live scoring."""
    cfg = get_config()
    store = _store()
    events = store.iter_events()
    if not events:
        console.print("[yellow]⚠ No events. Ingest or load a dataset first.[/]")
        raise typer.Exit(code=1)
    if contamination is not None:
        cfg.thresholds.contamination = contamination
    with console.status("[cyan]Training Isolation Forest + learning baselines…"):
        analyzer = Analyzer(cfg.thresholds).fit(events)
        analyzer.save(cfg.model_path)
    info = analyzer.info()
    console.print(f"[green]✓[/] Model trained on [bold]{info['train_events']}[/] events / "
                  f"[bold]{info['train_users']}[/] users → [dim]{cfg.model_path}[/]")
    console.print(f"[dim]features={info['features']} contamination={info['contamination']}[/]")


dataset_app = typer.Typer(help="Manage and load real-world datasets.", no_args_is_help=True)
app.add_typer(dataset_app, name="dataset")


@dataset_app.command("list")
def dataset_list() -> None:
    """List datasets Aegis can ingest for training / assessment."""
    t = Table(box=box.ROUNDED, header_style="bold cyan")
    t.add_column("Key"); t.add_column("Name"); t.add_column("Source"); t.add_column("Notes", style="dim")
    for d in list_datasets():
        t.add_row(d.key, d.name, d.source, d.description[:60] + "…")
    console.print(t)


@dataset_app.command("info")
def dataset_info(key: str = typer.Argument(..., help="Dataset key (e.g. cert).")) -> None:
    """Show details and citation for a dataset."""
    d = REGISTRY.get(key.lower())
    if not d:
        console.print(f"[red]Unknown dataset:[/] {key}")
        raise typer.Exit(code=1)
    console.print(Panel.fit(
        f"[bold]{d.name}[/]\n[dim]{d.source}[/]\n\n{d.description}\n\n"
        f"[cyan]URL:[/] {d.url}\n[cyan]Cite:[/] {d.citation}",
        border_style="cyan", title=d.key))


@dataset_app.command("inspect")
def dataset_inspect(path: Path = typer.Argument(..., exists=True, help="CERT release directory.")) -> None:
    """Report which CERT CSVs are present in a directory."""
    rel = detect_cert_release(path)
    console.print(f"[bold]{rel['path']}[/]")
    console.print(f"  sources present: [green]{', '.join(rel['present']) or 'none'}[/]")
    console.print(f"  LDAP snapshots: {len(rel['ldap_snapshots'])}")


@dataset_app.command("load")
def dataset_load(
    key: str = typer.Argument(..., help="Dataset key (cert | synthetic)."),
    path: Optional[Path] = typer.Option(None, help="Dataset directory (required for cert)."),
    limit: Optional[int] = typer.Option(None, help="Cap rows per source (cert)."),
    include_http: bool = typer.Option(False, "--http", help="Include high-volume http.csv (cert)."),
    users: int = typer.Option(30, help="Users (synthetic)."),
    days: int = typer.Option(30, help="Days (synthetic)."),
    reset: bool = typer.Option(True, "--reset/--append", help="Clear existing events first."),
) -> None:
    """Load a dataset into the local store, ready to train / analyze."""
    store = _store()
    if reset:
        store.reset()
    kwargs: dict = {}
    if key.lower() == "cert":
        if not path:
            console.print("[red]--path is required for the cert dataset.[/]")
            raise typer.Exit(code=1)
        kwargs = {"path": path, "limit_per_source": limit, "include_http": include_http}
    else:
        kwargs = {"users": users, "days": days}
    with console.status(f"[cyan]Loading dataset '{key}'…"):
        events = load_dataset(key, **kwargs)
        n = store.add_events(events)
    console.print(f"[green]✓[/] Loaded [bold]{n}[/] events from [bold]{key}[/] "
                  f"([dim]{len(store.distinct_users())} users[/]).")


@app.command()
def analyze(
    respond: bool = typer.Option(False, "--respond", help="Auto-dispatch (simulated) responses for HIGH/CRITICAL."),
    force: bool = typer.Option(False, "--force", help="Enforce responses instead of simulating (use with care)."),
) -> None:
    """Run ML + rule detection, score every user, and store explainable alerts."""
    cfg = get_config()
    store = _store()
    events = store.iter_events()
    if not events:
        console.print("[yellow]⚠ No events. Run 'aegis generate' or 'aegis ingest' first.[/]")
        raise typer.Exit(code=1)
    with console.status("[cyan]Training Isolation Forest & evaluating rules…"):
        alerts = Analyzer(cfg.thresholds).analyze(events)
        store.replace_alerts(alerts)

    _print_alert_table(alerts[:15], title="Top risk (highest first)")
    flagged = [a for a in alerts if a.risk_level.rank >= RiskLevel.MEDIUM.rank]
    console.print(f"\n[bold]{len(flagged)}[/] users at MEDIUM+ risk out of "
                  f"[bold]{len(alerts)}[/] analyzed.")

    if respond:
        acted = 0
        for a in alerts:
            if a.risk_level.rank >= RiskLevel.HIGH.rank:
                auto_respond(store, cfg, a, force=force)
                acted += 1
        mode = "ENFORCED" if force else "SIMULATED"
        console.print(f"[green]✓[/] Dispatched [bold]{mode}[/] responses for "
                      f"[bold]{acted}[/] HIGH/CRITICAL users.")


@app.command()
def alerts(
    min_level: str = typer.Option("MEDIUM", "--min-level", help="LOW | MEDIUM | HIGH | CRITICAL."),
    limit: int = typer.Option(25, help="Max rows to show."),
) -> None:
    """List stored alerts, highest risk first."""
    store = _store()
    try:
        lvl = RiskLevel(min_level.upper())
    except ValueError:
        console.print(f"[red]Invalid level:[/] {min_level}")
        raise typer.Exit(code=1)
    rows = store.get_alerts(min_level=lvl)[:limit]
    if not rows:
        console.print("[dim]No alerts at or above that level. Run 'aegis analyze'.[/]")
        return
    _print_alert_table(rows, title=f"Alerts ≥ {lvl.value}")


@app.command()
def show(user: str = typer.Argument(..., help="Username to inspect.")) -> None:
    """Show the full explainable finding for a single user."""
    store = _store()
    match = [a for a in store.get_alerts() if a.user == user]
    if not match:
        console.print(f"[yellow]No alert for '{user}'. Run 'aegis analyze'.[/]")
        raise typer.Exit(code=1)
    a = match[0]
    style = _LEVEL_STYLE[a.risk_level.value]
    console.print(Panel.fit(
        f"[bold]{a.user}[/]  [{style}]{a.risk_level.value}[/]  "
        f"[bold]{a.risk_score:.0f}[/]/100\n"
        f"[dim]{a.department} · {a.role} · {a.event_count} events · {a.window_start.date()}[/]",
        border_style="cyan"))
    t = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    t.add_column("Factor"); t.add_column("Weight", justify="right"); t.add_column("Detail")
    for e in a.explanations:
        t.add_row(e.factor, f"+{e.weight:.0f}", e.detail)
    console.print(t)
    console.print("[bold]Recommended response:[/] " +
                  ", ".join(f"[cyan]{x}[/]" for x in a.recommended_actions))


@app.command()
def respond(
    user: str = typer.Argument(..., help="Target user."),
    action: str = typer.Option("notify_soc", "--action",
                               help="lock_account | revoke_sessions | require_mfa | disable_downloads | notify_soc"),
    force: bool = typer.Option(False, "--force", help="Enforce instead of simulate."),
    reason: str = typer.Option("", help="Reason recorded in the audit trail."),
) -> None:
    """Dispatch a single (simulated) response action against a user."""
    cfg = get_config()
    store = _store()
    try:
        act = ResponseAction(action.lower())
    except ValueError:
        console.print(f"[red]Unknown action:[/] {action}")
        raise typer.Exit(code=1)
    res = dispatch(store, cfg, user, act, force=force, reason=reason)
    console.print(f"[green]✓[/] [{('red' if force else 'yellow')}]{res['mode']}[/] "
                  f"{res['action']} → [bold]{user}[/]  [dim](webhook: {res['webhook']})[/]")


@app.command()
def report(
    out: Optional[Path] = typer.Option(None, help="Output directory (default: data home/reports)."),
) -> None:
    """Generate HTML + JSON reports for SOC / HR / compliance."""
    cfg = get_config()
    store = _store()
    alerts_ = store.get_alerts()
    if not alerts_:
        console.print("[yellow]⚠ No alerts. Run 'aegis analyze' first.[/]")
        raise typer.Exit(code=1)
    paths = write_reports(alerts_, cfg, out)
    console.print(f"[green]✓[/] HTML  → [bold]{paths['html']}[/]")
    console.print(f"[green]✓[/] JSON  → [bold]{paths['json']}[/]")


@app.command()
def responses(limit: int = typer.Option(20, help="Rows to show.")) -> None:
    """Show the response audit trail."""
    store = _store()
    rows = store.get_responses()[:limit]
    if not rows:
        console.print("[dim]No response actions recorded yet.[/]")
        return
    t = Table(box=box.SIMPLE, header_style="bold")
    t.add_column("When"); t.add_column("User"); t.add_column("Action")
    t.add_column("Mode"); t.add_column("Detail")
    for r in rows:
        mode_style = "red" if r["mode"] == "ENFORCED" else "yellow"
        t.add_row(r["created_at"][:19], r["user"], r["action"],
                  f"[{mode_style}]{r['mode']}[/]", r["detail"])
    console.print(t)


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", help="Bind address."),
    port: int = typer.Option(8000, help="Port."),
    open_browser: bool = typer.Option(False, "--open", "-o", help="Open the dashboard in a browser."),
    reload: bool = typer.Option(False, "--reload", help="Auto-reload (development)."),
) -> None:
    """Launch the web dashboard (browser GUI)."""
    import threading
    import time
    import uvicorn

    _banner()
    url = f"http://{host}:{port}"
    console.print(f"[green]➜[/] Dashboard: [bold underline]{url}[/]  [dim](Ctrl+C to stop)[/]")
    if open_browser:
        def _open() -> None:
            import webbrowser
            time.sleep(1.5)
            webbrowser.open(url)
        threading.Thread(target=_open, daemon=True).start()
    uvicorn.run("aegis_uba.web.server:app", host=host, port=port, reload=reload,
                log_level="warning")


@app.command()
def gui(
    host: str = typer.Option("127.0.0.1", help="Bind address."),
    port: int = typer.Option(8000, help="Port."),
) -> None:
    """Launch the dashboard and open it in your browser (desktop-app style)."""
    serve(host=host, port=port, open_browser=True, reload=False)


@app.command()
def monitor(
    eps: float = typer.Option(6.0, help="Simulated events per second."),
    inject_prob: float = typer.Option(0.08, help="Probability of injecting a threat per tick."),
    duration: int = typer.Option(0, help="Seconds to run (0 = until Ctrl+C)."),
) -> None:
    """Run the real-time monitor in the terminal (live feed + rolling alerts)."""
    import time
    from rich.live import Live
    from rich.layout import Layout
    from aegis_uba.stream import ENGINE

    cfg = get_config()
    store = _store()
    if store.event_count() == 0:
        console.print("[yellow]No data — generating a warmup corpus…[/]")
    _banner()
    ENGINE.start(eps=eps, inject_prob=inject_prob)
    console.print(f"[green]➜[/] Live monitor running [dim](eps={eps}, inject={inject_prob}) — Ctrl+C to stop[/]\n")

    def render() -> Table:
        t = Table(box=box.SIMPLE, header_style="bold cyan",
                  title="[bold]Aegis UBA — Live Telemetry[/]")
        t.add_column("Time", style="dim"); t.add_column("User", style="cyan")
        t.add_column("Action"); t.add_column("Detail", style="dim")
        for item in reversed(ENGINE.recent_feed(16)):
            if item.get("type") == "event":
                t.add_row(item["ts"][11:19], item["user"], item["action"],
                          f"{item['source_ip']} {('· '+item['country']) if item.get('country') not in (None,'US') else ''}")
            elif item.get("type") == "inject":
                t.add_row(item["ts"][11:19], item["user"], "[red]⚡ INJECT[/]",
                          f"[red]scenario: {item['scenario']}[/]")
            elif item.get("type") == "alert":
                t.add_row("", f"[bold]{item['user']}[/]",
                          f"[{_LEVEL_STYLE[item['risk_level']]}]{item['risk_level']}[/]",
                          f"{item['top_factor']} · {item['risk_score']:.0f}")
        return t

    try:
        start = time.time()
        with Live(render(), console=console, refresh_per_second=4) as live:
            while True:
                time.sleep(0.4)
                live.update(render())
                if duration and time.time() - start >= duration:
                    break
    except KeyboardInterrupt:
        pass
    finally:
        st = ENGINE.stop()
        console.print(f"\n[green]✓[/] Stopped. Streamed [bold]{st['events_emitted']}[/] events, "
                      f"injected [bold]{st['anomalies_injected']}[/] threats. "
                      f"Run [cyan]aegis alerts[/] to review.")


@app.command()
def reset(yes: bool = typer.Option(False, "--yes", help="Skip confirmation.")) -> None:
    """Delete all events, alerts and response history."""
    if not yes:
        typer.confirm("Delete ALL local Aegis data (events, alerts, responses)?", abort=True)
    _store().reset()
    console.print("[green]✓[/] Local data cleared.")


# ---------------------------------------------------------------------------
def _print_alert_table(rows, title: str) -> None:
    t = Table(title=title, box=box.ROUNDED, header_style="bold cyan", title_style="bold")
    t.add_column("User"); t.add_column("Dept/Role", style="dim")
    t.add_column("Risk", justify="right"); t.add_column("Level")
    t.add_column("Top factor")
    for a in rows:
        style = _LEVEL_STYLE[a.risk_level.value]
        top = a.explanations[0].factor if a.explanations else "—"
        t.add_row(a.user, f"{a.department}/{a.role}", f"{a.risk_score:.0f}",
                  f"[{style}]{a.risk_level.value}[/]", top)
    console.print(t)


def _export_csv(events, path: Path) -> None:
    import csv
    fields = ["timestamp", "user", "action", "host", "source_ip", "resource",
              "bytes", "success", "department", "role", "country"]
    with Path(path).open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        for e in events:
            w.writerow({
                "timestamp": e.timestamp.isoformat(), "user": e.user,
                "action": e.action.value, "host": e.host, "source_ip": e.source_ip,
                "resource": e.resource, "bytes": e.bytes, "success": e.success,
                "department": e.department, "role": e.role, "country": e.country,
            })


def main() -> None:
    app()


if __name__ == "__main__":
    main()
