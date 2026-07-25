"""ATHENA ITD command-line interface (Typer + Rich).

Runs on Linux, Windows and macOS with the same commands. Typical workflow::

    athena init
    athena generate --users 30 --days 30      # or: athena ingest events.csv
    athena analyze --respond
    athena alerts
    athena report
    athena serve                              # launch the web dashboard
"""
from __future__ import annotations

from pathlib import Path

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from athena_itd import __version__
from athena_itd.config import get_config
from athena_itd.datasets import REGISTRY, detect_cert_release, list_datasets, load_dataset
from athena_itd.detect import Analyzer
from athena_itd.ingest import generate_synthetic, load_events_from_file, sniff_format
from athena_itd.models import RiskLevel
from athena_itd.report import write_reports
from athena_itd.response import ResponseAction, auto_respond, dispatch
from athena_itd.storage import Store

app = typer.Typer(
    add_completion=True,
    no_args_is_help=True,
    help="ATHENA ITD — AI-driven Insider Threat Detection.",
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
        f"[bold yellow]🦉  ATHENA ITD[/]  [dim]v{__version__}[/]\n"
        "[dim]AI-driven Insider Threat Detection[/]",
        border_style="yellow"))


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
    console.print("[dim]Next:[/] athena generate  →  athena analyze  →  athena serve")


@app.command()
def generate(
    users: int = typer.Option(25, help="Number of synthetic users."),
    days: int = typer.Option(30, help="Days of history to generate."),
    seed: int = typer.Option(1337, help="Random seed for reproducibility."),
    out: Path | None = typer.Option(None, help="Also export events to a CSV file."),
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
    fmt: str | None = typer.Option(None, "--format", help="csv | json | authlog (auto if omitted)."),
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
    contamination: float | None = typer.Option(None, help="Override anomaly fraction for training."),
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
        analyzer = Analyzer(config=cfg).fit(events)
        analyzer.save(cfg.model_path)
    info = analyzer.info()
    console.print(f"[green]✓[/] Model trained on [bold]{info['train_events']}[/] events / "
                  f"[bold]{info['train_users']}[/] users → [dim]{cfg.model_path}[/]")
    console.print(f"[dim]features={info['features']} contamination={info['contamination']}[/]")


dataset_app = typer.Typer(help="Manage and load real-world datasets.", no_args_is_help=True)
app.add_typer(dataset_app, name="dataset")


@dataset_app.command("list")
def dataset_list() -> None:
    """List datasets ATHENA can ingest for training / assessment."""
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
    path: Path | None = typer.Option(None, help="Dataset directory (required for cert)."),
    limit: int | None = typer.Option(None, help="Cap rows per source (cert)."),
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
        console.print("[yellow]⚠ No events. Run 'athena generate' or 'athena ingest' first.[/]")
        raise typer.Exit(code=1)
    with console.status("[cyan]Training Isolation Forest & evaluating rules…"):
        alerts = Analyzer(config=cfg).analyze(events, watchlist=store.watchlist_multipliers())
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
        console.print("[dim]No alerts at or above that level. Run 'athena analyze'.[/]")
        return
    _print_alert_table(rows, title=f"Alerts ≥ {lvl.value}")


@app.command()
def show(user: str = typer.Argument(..., help="Username to inspect.")) -> None:
    """Show the full explainable finding for a single user."""
    store = _store()
    match = [a for a in store.get_alerts() if a.user == user]
    if not match:
        console.print(f"[yellow]No alert for '{user}'. Run 'athena analyze'.[/]")
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
    out: Path | None = typer.Option(None, help="Output directory (default: data home/reports)."),
) -> None:
    """Generate HTML + JSON reports for SOC / HR / compliance."""
    cfg = get_config()
    store = _store()
    alerts_ = store.get_alerts()
    if not alerts_:
        console.print("[yellow]⚠ No alerts. Run 'athena analyze' first.[/]")
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
    host: str = typer.Option("127.0.0.1", help="Bind address (0.0.0.0 for all interfaces)."),
    port: int = typer.Option(8000, help="Port."),
    open_browser: bool = typer.Option(False, "--open", "-o", help="Open the dashboard in a browser."),
    reload: bool = typer.Option(False, "--reload", help="Auto-reload (development)."),
    tls_cert: str = typer.Option("", "--tls-cert", help="Path to a TLS certificate (PEM) to serve HTTPS."),
    tls_key: str = typer.Option("", "--tls-key", help="Path to the matching TLS private key (PEM)."),
    workers: int = typer.Option(1, help="Worker processes (production: set >1; disables --reload)."),
    proxy_headers: bool = typer.Option(False, "--proxy-headers",
                                       help="Trust X-Forwarded-* from a front proxy (needed for correct HTTPS/HSTS)."),
    access_log: bool = typer.Option(False, "--access-log", help="Emit per-request access logs."),
) -> None:
    """Launch the web dashboard / SOC console (production-capable)."""
    import threading
    import time

    import uvicorn

    scheme = "https" if tls_cert and tls_key else "http"
    _banner()
    url = f"{scheme}://{host}:{port}"
    console.print(f"[green]➜[/] Dashboard: [bold underline]{url}[/]  [dim](Ctrl+C to stop)[/]")
    if scheme == "http" and host not in ("127.0.0.1", "localhost", "::1"):
        console.print("[yellow]⚠  Serving plain HTTP on a non-loopback address.[/] "
                      "Terminate TLS at a reverse proxy or pass --tls-cert/--tls-key.")
    if open_browser:
        def _open() -> None:
            import webbrowser
            time.sleep(1.5)
            webbrowser.open(url)
        threading.Thread(target=_open, daemon=True).start()
    uvicorn.run(
        "athena_itd.web.server:app", host=host, port=port,
        reload=reload and workers <= 1,
        workers=workers if not reload else 1,
        log_level="info" if access_log else "warning",
        access_log=access_log,
        proxy_headers=proxy_headers,
        forwarded_allow_ips="*" if proxy_headers else None,
        ssl_certfile=tls_cert or None,
        ssl_keyfile=tls_key or None,
    )


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

    from athena_itd.stream import ENGINE

    store = _store()
    if store.event_count() == 0:
        console.print("[yellow]No data — generating a warmup corpus…[/]")
    _banner()
    ENGINE.start(eps=eps, inject_prob=inject_prob)
    console.print(f"[green]➜[/] Live monitor running [dim](eps={eps}, inject={inject_prob}) — Ctrl+C to stop[/]\n")

    def render() -> Table:
        t = Table(box=box.SIMPLE, header_style="bold cyan",
                  title="[bold]ATHENA ITD — Live Telemetry[/]")
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
                      f"Run [cyan]athena alerts[/] to review.")



# --- v3: triage, watchlist, cases, governance ------------------------------
watchlist_app = typer.Typer(help="Manage the heightened-scrutiny watchlist.")
app.add_typer(watchlist_app, name="watchlist")


@watchlist_app.command("list")
def watchlist_list() -> None:
    """Show active and expired watchlist entries."""
    entries = _store().watchlist(active_only=False)
    if not entries:
        console.print("[dim]Watchlist is empty.[/]")
        return
    t = Table(box=box.ROUNDED, header_style="bold cyan")
    t.add_column("User"); t.add_column("Reason"); t.add_column("×", justify="right")
    t.add_column("Added by", style="dim"); t.add_column("Expires", style="dim")
    for e in entries:
        t.add_row(e.user, e.reason, f"{e.multiplier:.2f}", e.added_by,
                  e.expires_at.date().isoformat() if e.expires_at else "never")
    console.print(t)


@watchlist_app.command("add")
def watchlist_add(
    user: str = typer.Argument(..., help="Username to watch."),
    reason: str = typer.Option("heightened scrutiny", "--reason", "-r"),
    multiplier: float = typer.Option(1.35, "--multiplier", "-m", min=1.0, max=3.0),
    days: int | None = typer.Option(None, "--days", help="Auto-expire after N days."),
) -> None:
    """Add a user to the watchlist (risk boosted on next analysis)."""
    from datetime import datetime, timedelta, timezone

    from athena_itd.models import WatchlistEntry
    expires = datetime.now(timezone.utc) + timedelta(days=days) if days else None
    _store().watchlist_add(WatchlistEntry(user=user, reason=reason,
                                          multiplier=multiplier, added_by="cli",
                                          expires_at=expires))
    console.print(f"[green]✓[/] [bold]{user}[/] watchlisted (risk ×{multiplier:.2f}).")


@watchlist_app.command("remove")
def watchlist_remove(user: str = typer.Argument(...)) -> None:
    """Remove a user from the watchlist."""
    if _store().watchlist_remove(user):
        console.print(f"[green]✓[/] {user} removed from watchlist.")
    else:
        console.print(f"[yellow]{user} was not on the watchlist.[/]")


users_app = typer.Typer(help="Console user accounts & roles (RBAC).",
                        no_args_is_help=True)
app.add_typer(users_app, name="users")


@users_app.command("list")
def users_list() -> None:
    """List console accounts and their roles."""
    from athena_itd.config import Config
    cfg = Config.load()
    if not cfg.security.users:
        console.print("[dim]No users yet. Add one: [/][cyan]athena users add <name> --role admin[/]")
        return
    t = Table(box=box.ROUNDED, header_style="bold cyan")
    t.add_column("Username"); t.add_column("Role"); t.add_column("Status", style="dim")
    for name, u in sorted(cfg.security.users.items()):
        active = u.get("active", True)
        t.add_row(name, u.get("role", "viewer"),
                  "[green]active[/]" if active else "[red]disabled[/]")
    console.print(t)
    if not cfg.security.auth_enabled:
        console.print("[yellow]⚠ Auth is disabled.[/] Enable it: "
                      "[cyan]athena users enable-auth[/]")


@users_app.command("add")
def users_add(
    username: str = typer.Argument(..., help="New account username."),
    role: str = typer.Option("viewer", "--role", "-r", help="viewer | analyst | admin."),
    password: str | None = typer.Option(None, "--password", "-p",
                                           help="Password (prompted if omitted)."),
) -> None:
    """Create a console account."""
    from athena_itd import auth
    from athena_itd.config import Config
    if role not in auth.ROLES:
        console.print(f"[red]Role must be one of {auth.ROLES}.[/]"); raise typer.Exit(1)
    cfg = Config.load()
    if username in cfg.security.users:
        console.print(f"[red]User '{username}' already exists.[/]"); raise typer.Exit(1)
    if password is None:
        password = typer.prompt("Password", hide_input=True, confirmation_prompt=True)
    try:
        pw_hash = auth.hash_password(password)
    except ValueError as exc:
        console.print(f"[red]{exc}[/]"); raise typer.Exit(1)
    cfg.security.users[username] = {"password_hash": pw_hash, "role": role, "active": True}
    cfg.save()
    console.print(f"[green]✓[/] Created [bold]{username}[/] ([cyan]{role}[/]).")


@users_app.command("passwd")
def users_passwd(
    username: str = typer.Argument(...),
    password: str | None = typer.Option(None, "--password", "-p"),
) -> None:
    """Reset a user's password (invalidates their active sessions)."""
    from athena_itd import auth
    from athena_itd.config import Config
    cfg = Config.load()
    if username not in cfg.security.users:
        console.print(f"[red]No such user '{username}'.[/]"); raise typer.Exit(1)
    if password is None:
        password = typer.prompt("New password", hide_input=True, confirmation_prompt=True)
    try:
        cfg.security.users[username]["password_hash"] = auth.hash_password(password)
    except ValueError as exc:
        console.print(f"[red]{exc}[/]"); raise typer.Exit(1)
    cfg.save()
    _store().delete_user_sessions(username)
    console.print(f"[green]✓[/] Password updated for [bold]{username}[/]; sessions revoked.")


@users_app.command("role")
def users_role(username: str = typer.Argument(...),
               role: str = typer.Argument(..., help="viewer | analyst | admin.")) -> None:
    """Change a user's role."""
    from athena_itd import auth
    from athena_itd.config import Config
    if role not in auth.ROLES:
        console.print(f"[red]Role must be one of {auth.ROLES}.[/]"); raise typer.Exit(1)
    cfg = Config.load()
    if username not in cfg.security.users:
        console.print(f"[red]No such user '{username}'.[/]"); raise typer.Exit(1)
    cfg.security.users[username]["role"] = role
    cfg.save()
    console.print(f"[green]✓[/] [bold]{username}[/] is now [cyan]{role}[/].")


@users_app.command("disable")
def users_disable(username: str = typer.Argument(...)) -> None:
    """Disable an account (blocks login, revokes sessions)."""
    from athena_itd.config import Config
    cfg = Config.load()
    if username not in cfg.security.users:
        console.print(f"[red]No such user '{username}'.[/]"); raise typer.Exit(1)
    cfg.security.users[username]["active"] = False
    cfg.save()
    _store().delete_user_sessions(username)
    console.print(f"[yellow]✓ {username} disabled.[/]")


@users_app.command("remove")
def users_remove(username: str = typer.Argument(...)) -> None:
    """Delete a console account."""
    from athena_itd.config import Config
    cfg = Config.load()
    if username not in cfg.security.users:
        console.print(f"[red]No such user '{username}'.[/]"); raise typer.Exit(1)
    admins = [u for u, v in cfg.security.users.items()
              if v.get("role") == "admin" and v.get("active", True)]
    if cfg.security.users[username].get("role") == "admin" and admins == [username]:
        console.print("[red]Refusing to delete the last active admin.[/]"); raise typer.Exit(1)
    del cfg.security.users[username]
    cfg.save()
    _store().delete_user_sessions(username)
    console.print(f"[green]✓[/] Deleted {username}.")


@users_app.command("sessions")
def users_sessions() -> None:
    """List active sign-in sessions."""
    sessions = _store().list_sessions()
    if not sessions:
        console.print("[dim]No active sessions.[/]"); return
    t = Table(title="Active sessions", box=box.ROUNDED, header_style="bold cyan")
    t.add_column("User"); t.add_column("Role"); t.add_column("Source IP", style="dim")
    t.add_column("Signed in", style="dim"); t.add_column("Expires", style="dim")
    for s in sessions:
        t.add_row(s["username"], s["role"], s.get("source_ip") or "—",
                  s["created_at"][:19], s["expires_at"][:19])
    console.print(t)


@users_app.command("revoke")
def users_revoke(username: str = typer.Argument(..., help="Sign this user out everywhere.")) -> None:
    """Revoke all active sessions for a user (forces re-login)."""
    n = _store().delete_user_sessions(username)
    console.print(f"[green]✓[/] Revoked {n} session(s) for {username}.")


@users_app.command("enable-auth")
def users_enable_auth(
    disable: bool = typer.Option(False, "--disable", help="Turn auth OFF instead."),
) -> None:
    """Enable (or disable) console authentication."""
    from athena_itd.config import Config
    cfg = Config.load()
    if not disable and not cfg.security.users:
        console.print("[red]Create an admin first:[/] [cyan]athena users add admin --role admin[/]")
        raise typer.Exit(1)
    cfg.security.auth_enabled = not disable
    cfg.security.ensure_api_key()
    cfg.save()
    state = "disabled" if disable else "ENABLED"
    console.print(f"[green]✓[/] Console authentication {state}.")
    if not disable:
        console.print(f"[dim]Service/API key (for automation):[/] {cfg.security.api_key}")


cases_app = typer.Typer(help="Investigation case management.")
app.add_typer(cases_app, name="cases")


@cases_app.command("list")
def cases_list(open_only: bool = typer.Option(False, "--open")) -> None:
    """List investigation cases."""
    cases = _store().get_cases(open_only=open_only)
    if not cases:
        console.print("[dim]No cases.[/]")
        return
    t = Table(box=box.ROUNDED, header_style="bold cyan")
    t.add_column("#", justify="right"); t.add_column("Title"); t.add_column("Subject")
    t.add_column("Severity"); t.add_column("Status"); t.add_column("Verdict", style="dim")
    for c in cases:
        style = _LEVEL_STYLE[c.severity.value]
        t.add_row(str(c.id), c.title, c.subject_user,
                  f"[{style}]{c.severity.value}[/]", c.status.value, c.verdict.value)
    console.print(t)


@cases_app.command("open")
def cases_open(
    title: str = typer.Argument(...),
    user: str = typer.Option(..., "--user", "-u", help="Subject user."),
    severity: str = typer.Option("MEDIUM", "--severity", "-s"),
) -> None:
    """Open a new investigation case."""
    from athena_itd.models import Case
    case = _store().create_case(Case(title=title, subject_user=user,
                                     severity=RiskLevel(severity.upper()), owner="cli"))
    console.print(f"[green]✓[/] Case [bold]#{case.id}[/] opened for {user}.")


@cases_app.command("close")
def cases_close(
    case_id: int = typer.Argument(...),
    verdict: str = typer.Option("unknown", "--verdict",
                                help="true_positive | false_positive | benign_true_positive"),
    confirmed: bool = typer.Option(False, "--confirmed",
                                   help="Close as confirmed insider incident."),
) -> None:
    """Close a case with a verdict."""
    from datetime import datetime, timezone
    status = "closed_confirmed" if confirmed else "closed_unsubstantiated"
    ok = _store().update_case(case_id, status=status, verdict=verdict.lower(),
                              closed_at=datetime.now(timezone.utc).isoformat())
    console.print(f"[green]✓[/] Case #{case_id} → {status}." if ok
                  else f"[red]Unknown case #{case_id}.[/]")


@app.command()
def mitre() -> None:
    """Show MITRE ATT&CK coverage of the detector suite (+ live alert hits)."""
    from athena_itd import mitre as mitre_mod
    from athena_itd.detect import detector_mitre_map
    hits: dict[str, int] = {}
    for a in _store().get_alerts():
        for tech in a.mitre_techniques:
            hits[tech] = hits.get(tech, 0) + 1
    m = mitre_mod.coverage_matrix(detector_mitre_map(), hits)
    console.print(Panel(f"[bold]{m['covered_techniques']}[/] of "
                        f"[bold]{m['total_techniques']}[/] observable techniques covered "
                        f"([cyan]{m['coverage_pct']}%[/])", title="ATT&CK coverage"))
    t = Table(box=box.ROUNDED, header_style="bold cyan")
    t.add_column("Tactic"); t.add_column("Covered", justify="right"); t.add_column("Techniques")
    for col in m["tactics"]:
        techs = ", ".join(f"[{'red' if c['hits'] else 'cyan' if c['covered'] else 'dim'}]"
                          f"{c['id']}[/]" for c in col["techniques"])
        t.add_row(col["tactic"], f"{col['covered']}/{col['total']}", techs)
    console.print(t)


@app.command()
def compliance() -> None:
    """Show the control-framework coverage report (GDPR, HIPAA, ISO, SOC2, PCI, NIST)."""
    from athena_itd import compliance as compliance_mod
    from athena_itd.detect import detector_compliance_map
    evidence: dict[str, int] = {}
    for a in _store().get_alerts():
        for d in a.detectors:
            evidence[d] = evidence.get(d, 0) + 1
    rep = compliance_mod.coverage_report(detector_compliance_map(), evidence)
    console.print(Panel(f"[bold]{rep['total_covered']}[/] of [bold]{rep['total_controls']}[/] "
                        f"mapped controls evidenced ([cyan]{rep['overall_pct']}%[/])",
                        title="Compliance coverage"))
    t = Table(box=box.ROUNDED, header_style="bold cyan")
    t.add_column("Framework"); t.add_column("Authority", style="dim")
    t.add_column("Coverage", justify="right"); t.add_column("Gaps", style="dim")
    for f in rep["frameworks"]:
        t.add_row(f["name"], f["authority"], f"{f['covered']}/{f['total']} ({f['coverage_pct']}%)",
                  ", ".join(f["gaps"]) or "—")
    console.print(t)


@app.command()
def feedback_stats() -> None:
    """Per-detector precision from analyst verdicts (the tuning signal)."""
    stats = _store().detector_precision()
    if not stats:
        console.print("[dim]No analyst feedback recorded yet.[/]")
        return
    t = Table(box=box.ROUNDED, header_style="bold cyan")
    t.add_column("Detector"); t.add_column("TP", justify="right")
    t.add_column("FP", justify="right"); t.add_column("Benign", justify="right")
    t.add_column("Precision", justify="right")
    for det, s in sorted(stats.items()):
        prec = f"{s['precision']*100:.0f}%" if s.get("precision") is not None else "—"
        t.add_row(det, str(s["true_positive"]), str(s["false_positive"]),
                  str(s["benign_true_positive"]), prec)
    console.print(t)


@app.command()
def purge() -> None:
    """Apply the retention policy (delete data older than the configured windows)."""
    cfg = get_config()
    removed = _store().purge(cfg.retention.event_days, cfg.retention.alert_days,
                             cfg.retention.audit_days)
    console.print(f"[green]✓[/] Purge complete: {removed}")


@app.command()
def intel(path: Path = typer.Argument(..., exists=True,
                                      help="JSON threat-intel file of CIDR ranges.")) -> None:
    """Layer an operator-supplied network-reputation feed over the built-in seed."""
    from athena_itd.geo import load_intel_file
    n = load_intel_file(path)
    console.print(f"[green]✓[/] {n} network ranges loaded into the reputation engine.")


@app.command()
def reset(
    yes: bool = typer.Option(False, "--yes", help="Skip confirmation."),
    full: bool = typer.Option(False, "--full",
                              help="Also delete cases and the watchlist."),
) -> None:
    """Delete events, alerts, responses, notes and feedback (audit kept)."""
    scope = "ALL data incl. cases & watchlist" if full else \
            "events, alerts, responses, notes, feedback"
    if not yes:
        typer.confirm(f"Delete {scope}?", abort=True)
    removed = _store().reset(full=full)
    total = sum(removed.values())
    console.print(f"[green]✓[/] Cleared {total} records "
                  f"({', '.join(f'{k}:{v}' for k, v in removed.items() if v)}).")


@app.command()
def doctor() -> None:
    """Run a deployment self-check (config, datastore, model, auth posture)."""
    import sqlite3

    cfg = get_config()
    checks: list[tuple[str, str, str]] = []   # (status, name, detail)

    def add(ok: str, name: str, detail: str = "") -> None:
        checks.append((ok, name, detail))

    # 1. data home writable
    try:
        cfg.ensure_dirs()
        probe = cfg.home / ".doctor_write_test"
        probe.write_text("ok", encoding="utf-8"); probe.unlink()
        add("PASS", "Data home writable", str(cfg.home))
    except Exception as exc:  # noqa: BLE001
        add("FAIL", "Data home writable", str(exc))

    # 2. database present + integrity
    if cfg.db_path.exists():
        try:
            con = sqlite3.connect(str(cfg.db_path))
            res = con.execute("PRAGMA integrity_check").fetchone()
            con.close()
            if res and res[0] == "ok":
                add("PASS", "Database integrity", str(cfg.db_path))
            else:
                add("FAIL", "Database integrity", str(res))
        except Exception as exc:  # noqa: BLE001
            add("FAIL", "Database integrity", str(exc))
    else:
        add("WARN", "Database", "not initialized yet — run `athena init`")

    # 3. trained model
    if cfg.model_path.exists():
        add("PASS", "ML model", "persisted — live scoring uses the trained ensemble")
    else:
        add("WARN", "ML model", "not trained — run `athena train` for best accuracy")

    # 4. authentication posture
    if cfg.security.auth_enabled:
        admins = [u for u, m in cfg.security.users.items()
                  if m.get("role") == "admin" and m.get("active", True)]
        if admins:
            add("PASS", "Authentication", f"enabled · {len(admins)} active admin(s)")
        else:
            add("FAIL", "Authentication", "enabled but NO active admin — you can be locked out")
        # flag the shipped default credential if it's still in use
        from athena_itd import auth as _auth
        default_admin = cfg.security.users.get("admin")
        if default_admin and _auth.verify_password("a6m1n!!",
                                                    default_admin.get("password_hash", "")):
            add("WARN", "Default admin password",
                "'admin' still uses the legacy pre-3.2 default — run `athena users passwd admin`")
        # self-service sign-up posture
        if cfg.security.allow_signup:
            add("WARN", "Self-service sign-up",
                f"open — anyone can register as '{cfg.security.signup_role}' "
                "(set ATHENA_ALLOW_SIGNUP=false to close)")
        key = cfg.security.api_key
        if key and len(key) < 24:
            add("WARN", "API key strength", "shorter than 24 chars — regenerate with a 32-byte value")
    else:
        add("WARN", "Authentication",
            "disabled — fine for local use, REQUIRED before sharing (ATHENA_AUTH_ENABLED=true)")

    # 5. response enforcement gate
    if cfg.security.allow_enforced_response:
        add("WARN", "Response enforcement", "ENABLED — real actions can fire (per-call force still required)")
    else:
        add("PASS", "Response enforcement", "simulated by default (safe)")

    # 6. retention
    add("PASS" if cfg.retention.auto_purge else "WARN", "Retention auto-purge",
        "on" if cfg.retention.auto_purge else "off — set a policy to meet privacy obligations")

    # render
    style = {"PASS": "green", "WARN": "yellow", "FAIL": "bold red"}
    icon = {"PASS": "✓", "WARN": "!", "FAIL": "✗"}
    t = Table(title="ATHENA ITD — deployment self-check", box=box.ROUNDED,
              header_style="bold cyan", title_style="bold")
    t.add_column(""); t.add_column("Check"); t.add_column("Detail", style="dim")
    for ok, name, detail in checks:
        t.add_row(f"[{style[ok]}]{icon[ok]}[/]", name, detail)
    console.print(t)

    fails = sum(1 for c in checks if c[0] == "FAIL")
    warns = sum(1 for c in checks if c[0] == "WARN")
    if fails:
        console.print(f"[bold red]{fails} failing check(s)[/] — resolve before production.")
        raise typer.Exit(1)
    console.print("[green]All critical checks passed[/]" +
                  (f" · {warns} warning(s) to review." if warns else "."))


@app.command()
def backup(
    out: Path = typer.Option(None, "--out", "-o",
                             help="Destination file (default: <home>/backups/…)."),
) -> None:
    """Create a consistent snapshot of the database (safe while running)."""
    import sqlite3
    from datetime import datetime

    cfg = get_config()
    if not cfg.db_path.exists():
        console.print("[red]No database to back up — run `athena init` first.[/]")
        raise typer.Exit(1)
    if out is None:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        out = cfg.home / "backups" / f"athena-{stamp}.sqlite3"
    out.parent.mkdir(parents=True, exist_ok=True)
    src = sqlite3.connect(str(cfg.db_path))
    dst = sqlite3.connect(str(out))
    with dst:
        src.backup(dst)          # online backup — consistent even under WAL writes
    dst.close(); src.close()
    size = out.stat().st_size
    console.print(f"[green]✓[/] Backup written: {out} ({size/1024:.0f} KiB)")


@app.command()
def restore(
    src: Path = typer.Argument(..., exists=True, help="Backup file to restore from."),
    yes: bool = typer.Option(False, "--yes", help="Skip confirmation."),
) -> None:
    """Restore the database from a backup snapshot (overwrites current data)."""
    import shutil

    cfg = get_config()
    if not yes:
        typer.confirm(
            f"Overwrite {cfg.db_path} with {src}? Stop any running server first.",
            abort=True)
    cfg.ensure_dirs()
    # drop WAL sidecars so the restored file is authoritative
    for suffix in ("-wal", "-shm"):
        side = cfg.db_path.with_name(cfg.db_path.name + suffix)
        if side.exists():
            side.unlink()
    shutil.copyfile(src, cfg.db_path)
    console.print(f"[green]✓[/] Restored database from {src}. Restart the server if it was running.")


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
