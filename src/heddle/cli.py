"""Heddle CLI -- the primary interface for managing agents."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from heddle import __version__

console = Console()


def _get_registry():
    from heddle.mcp.registry import Registry
    return Registry()


@click.group()
@click.version_option(__version__, prog_name="heddle")
def cli():
    """Heddle -- The WEFT Agent & MCP Mesh Runtime."""


# ── Phase 1: Core commands ───────────────────────────────────────────

@cli.command()
@click.argument("config_path", type=click.Path(exists=True))
@click.option("--host", default="0.0.0.0", help="Bind address")
@click.option("--port", default=8200, type=int, help="Port for MCP server")
@click.option("--transport", default="streamable-http",
              type=click.Choice(["streamable-http", "sse", "stdio"]), help="MCP transport")
def run(config_path: str, host: str, port: int, transport: str):
    """Run an agent from a YAML config file."""
    from heddle.runtime.engine import AgentRunner
    runner = AgentRunner()
    config = runner.load(config_path)
    spec = config.agent
    console.print(f"\n[bold cyan]Heddle[/] Starting agent [bold]{spec.name}[/] v{spec.version}")
    console.print(f"  Tools: {len(spec.exposes)} exposed, {len(spec.consumes)} consumed")
    console.print(f"  Trust tier: {spec.runtime.trust_tier}")
    console.print(f"  Endpoint: http://{host}:{port}/mcp\n")
    runner.register(config, config_path=config_path, port=port)
    runner.run(config, host=host, port=port, transport=transport)


@cli.command()
@click.argument("config_path", type=click.Path(exists=True))
def validate(config_path: str):
    """Validate an agent config without running it."""
    from heddle.runtime.engine import AgentRunner
    from heddle.config.loader import ConfigError
    runner = AgentRunner()
    try:
        result = runner.dry_run(config_path)
    except ConfigError as exc:
        console.print(f"[bold red]Validation failed:[/]\n{exc}")
        sys.exit(1)
    console.print(f"[bold green]OK[/] Config valid: [bold]{result['agent']}[/] v{result['version']}")
    console.print(f"  {result['description']}")
    if result["tools"]:
        table = Table(title="Exposed Tools")
        table.add_column("Tool", style="cyan")
        table.add_column("Bridge", style="yellow")
        table.add_column("Parameters")
        for t in result["tools"]:
            table.add_row(t["name"], t["bridge_type"], ", ".join(t["parameters"]) or "-")
        console.print(table)


@cli.command("list")
def list_agents():
    """List all registered agents."""
    registry = _get_registry()
    agents = registry.list_agents()
    if not agents:
        console.print("[dim]No agents registered. Run 'heddle run <config>' to register one.[/]")
        return
    table = Table(title="Heddle Agents")
    table.add_column("Agent", style="bold cyan")
    table.add_column("Version")
    table.add_column("Status", style="bold")
    table.add_column("Trust")
    table.add_column("Tools", justify="right")
    table.add_column("Port", justify="right")
    status_colors = {"running": "green", "stopped": "dim", "error": "red", "registered": "yellow"}
    for a in agents:
        status = a["status"]
        color = status_colors.get(status, "white")
        table.add_row(a["name"], a["version"], f"[{color}]{status}[/]",
                      f"T{a['trust_tier']}", str(len(a["tools"])),
                      str(a["port"]) if a["port"] else "-")
    console.print(table)


@cli.command()
def registry():
    """Show the full tool registry."""
    reg = _get_registry()
    tools = reg.list_all_tools()
    if not tools:
        console.print("[dim]No tools in registry.[/]")
        return
    table = Table(title="Heddle Tool Registry")
    table.add_column("Agent", style="cyan")
    table.add_column("Tool", style="bold")
    table.add_column("Description")
    table.add_column("Bridge")
    for t in tools:
        table.add_row(t["agent_name"], t["name"], (t["description"] or "-")[:60], t["bridge_type"])
    console.print(table)


@cli.command()
@click.argument("name")
def info(name: str):
    """Show detailed info about a registered agent."""
    reg = _get_registry()
    agent = reg.get_agent(name)
    if not agent:
        console.print(f"[red]Agent '{name}' not found in registry.[/]")
        sys.exit(1)
    console.print(f"\n[bold cyan]{agent['name']}[/] v{agent['version']}")
    console.print(f"  {agent['description']}")
    console.print(f"  Status: {agent['status']}  |  Trust: T{agent['trust_tier']}")
    if agent["port"]:
        console.print(f"  Endpoint: http://{agent['host']}:{agent['port']}/mcp")
    if agent["tools"]:
        console.print(f"\n  [bold]Tools ({len(agent['tools'])}):[/]")
        for t in agent["tools"]:
            params = json.loads(t["parameters"]) if isinstance(t["parameters"], str) else t["parameters"]
            console.print(f"    * {t['name']} ({t['bridge_type']}) -- {', '.join(params.keys()) if params else '-'}")


@cli.command()
def discovery():
    """Dump the discovery manifest as JSON."""
    reg = _get_registry()
    click.echo(json.dumps(reg.discovery_manifest(), indent=2))


# ── Phase 2: Generate ───────────────────────────────────────────────

@cli.command()
@click.argument("description")
@click.option("--model", default="qwen3:14b", help="Ollama model for generation")
@click.option("--discover", default=None, help="Base URL to auto-discover API endpoints")
@click.option("--output-dir", default=None, type=click.Path(), help="Output directory")
@click.option("--dry-run", is_flag=True, help="Validate only, don't save")
@click.option("--retries", default=2, type=int, help="Max retries on validation failure")
def generate(description: str, model: str, discover: str | None,
             output_dir: str | None, dry_run: bool, retries: int):
    """Generate an agent config from a natural language description."""
    asyncio.run(_generate_async(description, model, discover, output_dir, dry_run, retries))


async def _generate_async(description, model, discover_url, output_dir, dry_run, retries):
    from heddle.generator.agent_gen import generate_agent, retry_generate
    from heddle.generator.llm import LLMClient
    llm = LLMClient(model=model)
    if not await llm.check_available():
        console.print("[bold red]Ollama not reachable.[/]")
        sys.exit(1)
    console.print(f"\n[bold cyan]Heddle Generate[/]  Model: {model}")
    console.print(f"  {description}")
    context = ""
    if discover_url:
        from heddle.generator.discover import discover_api, format_discovery_context
        console.print(f"  Discovering: {discover_url}...")
        disc = await discover_api(discover_url)
        context = format_discovery_context(disc)
        console.print(f"  Found {len(disc.get('endpoints', []))} endpoint(s)")
    console.print()
    with console.status("[bold]Generating..."):
        result = await (retry_generate if retries > 0 else generate_agent)(
            description, model=model, context=context,
            **({"max_retries": retries, "output_dir": output_dir, "validate_only": dry_run} if retries > 0
               else {"output_dir": output_dir, "validate_only": dry_run}),
        )
    if result["errors"]:
        console.print("[bold red]Generation failed:[/]")
        for err in result["errors"]:
            console.print(f"  {err}")
        console.print(Panel(Syntax(result["yaml_text"][:2000], "yaml"), title="Raw output", border_style="red"))
        sys.exit(1)
    spec = result["config"].agent
    console.print(f"[bold green]OK[/] Generated: [bold]{spec.name}[/] v{spec.version}")
    console.print(f"  {spec.description[:100]}")
    if spec.exposes:
        table = Table(title="Generated tools")
        table.add_column("Tool", style="cyan")
        table.add_column("Bridge", style="yellow")
        table.add_column("Parameters")
        bridge_names = {ep.tool_name for ep in spec.http_bridge}
        for t in spec.exposes:
            table.add_row(t.name, "http" if t.name in bridge_names else "stub",
                          ", ".join(t.parameters.keys()) or "-")
        console.print(table)
    if result.get("path"):
        console.print(f"\n  Saved to: [bold]{result['path']}[/]")
        console.print(f"  Run: heddle run {result['path']} --port 8201")


# ── Phase 3: Security commands ───────────────────────────────────────

@cli.group()
def audit():
    """Audit log management."""


@audit.command("show")
@click.option("-n", "--count", default=20, help="Number of entries")
@click.option("--event", default=None, help="Filter by event type")
@click.option("--agent", default=None, help="Filter by agent name")
@click.option("--tool", default=None, help="Filter by tool name")
@click.option("--since", default=None, help="Only entries after this ISO timestamp")
@click.option("--until", "until_", default=None, help="Only entries before this ISO timestamp")
def audit_show(count: int, event: str | None, agent: str | None,
               tool: str | None, since: str | None, until_: str | None):
    """Show recent audit log entries."""
    from heddle.security.audit import get_audit_logger
    logger = get_audit_logger()
    entries = logger.recent(count, event_type=event, agent=agent,
                            tool=tool, since=since, until=until_)
    if not entries:
        console.print("[dim]No audit entries.[/]")
        return
    table = Table(title=f"Audit Log (last {len(entries)})")
    table.add_column("Time", style="dim", width=19)
    table.add_column("Event", style="bold")
    table.add_column("Agent", style="cyan")
    table.add_column("Detail")
    for e in entries:
        ts = e.get("timestamp", "")[:19]
        evt = e.get("event", "?")
        agent = e.get("agent", "?")
        if evt == "tool_call":
            detail = f"{e.get('tool','')} [{e.get('status','')}] {e.get('duration_ms',0):.0f}ms"
        elif evt == "http_bridge":
            detail = f"{e.get('method','')} {e.get('url','')[:40]} -> {e.get('status_code','')}"
        elif evt == "trust_violation":
            detail = f"[red]{e.get('action','')}[/]: {e.get('detail','')[:50]}"
        elif evt == "credential_access":
            g = "[green]granted[/]" if e.get("granted") else "[red]denied[/]"
            detail = f"{e.get('credential_key','')} {g}"
        elif evt == "agent_lifecycle":
            detail = f"{e.get('action','')} {e.get('detail','')[:40]}"
        else:
            detail = str(e)[:60]
        table.add_row(ts, evt, agent, detail)
    console.print(table)


@audit.command("verify")
def audit_verify():
    """Verify audit log chain integrity."""
    from heddle.security.audit import get_audit_logger
    logger = get_audit_logger()
    valid, count, msg = logger.verify_chain()
    if valid:
        console.print(f"[bold green]OK[/] {msg}")
    else:
        console.print(f"[bold red]TAMPERED[/] {msg}")
        sys.exit(1)


@cli.group()
def secrets():
    """Credential broker management."""


@secrets.command("list")
def secrets_list():
    """List stored secret keys (not values)."""
    from heddle.security.credentials import get_credential_broker
    broker = get_credential_broker()
    keys = broker.list_secrets()
    if not keys:
        console.print("[dim]No secrets stored. Use 'heddle secrets set <key> <value>'[/]")
        return
    for k in keys:
        console.print(f"  {k}")
    console.print(f"\n  {len(keys)} secret(s)")


@secrets.command("set")
@click.argument("key")
@click.argument("value")
def secrets_set(key: str, value: str):
    """Store a secret."""
    from heddle.security.credentials import get_credential_broker
    broker = get_credential_broker()
    broker.set_secret(key, value)
    console.print(f"[green]OK[/] Secret '{key}' stored")


@secrets.command("grant")
@click.argument("agent_name")
@click.argument("key")
def secrets_grant(agent_name: str, key: str):
    """Grant an agent access to a secret."""
    from heddle.security.credentials import get_credential_broker
    broker = get_credential_broker()
    broker.grant_access(agent_name, key)
    console.print(f"[green]OK[/] Granted '{agent_name}' access to '{key}'")


@secrets.command("revoke")
@click.argument("agent_name")
@click.argument("key")
def secrets_revoke(agent_name: str, key: str):
    """Revoke an agent's access to a secret."""
    from heddle.security.credentials import get_credential_broker
    broker = get_credential_broker()
    if broker.revoke_access(agent_name, key):
        console.print(f"[green]OK[/] Revoked '{agent_name}' access to '{key}'")
    else:
        console.print(f"[yellow]No change[/] — '{agent_name}' didn't have access to '{key}'")


@secrets.command("policy")
def secrets_policy():
    """Show the credential access policy."""
    from heddle.security.credentials import get_credential_broker
    broker = get_credential_broker()
    table = Table(title="Credential Policy")
    table.add_column("Agent", style="cyan")
    table.add_column("Allowed Secrets")
    reg = _get_registry()
    agents = reg.list_agents()
    agent_names = {a["name"] for a in agents}
    # Show registered agents + any in policy
    from heddle.security.credentials import DEFAULT_POLICY_FILE
    import json as _json
    try:
        policy = _json.loads(DEFAULT_POLICY_FILE.read_text())
    except Exception:
        policy = {}
    for name in sorted(agent_names | set(policy.keys())):
        grants = broker.list_agent_grants(name)
        table.add_row(name, ", ".join(grants) if grants else "[dim]-[/]")
    console.print(table)


# ── Phase 4: Mesh commands ───────────────────────────────────────────

@cli.command()
@click.argument("agents_dir", type=click.Path(exists=True), default="agents")
@click.option("--host", default="0.0.0.0", help="Bind address")
@click.option("--base-port", default=8200, type=int, help="Starting port")
@click.option("--transport", default="streamable-http")
def mesh(agents_dir: str, host: str, base_port: int, transport: str):
    """Start all agents from a directory as a mesh.

    \b
    Example:
      heddle mesh agents/            # starts all .yaml configs
      heddle mesh agents/ --base-port 8300
    """
    from heddle.runtime.multi import MultiAgentRunner
    runner = MultiAgentRunner()
    count = runner.add_directory(agents_dir, base_port=base_port)
    if count == 0:
        console.print(f"[yellow]No agent configs found in {agents_dir}[/]")
        sys.exit(1)
    console.print(f"\n[bold cyan]Heddle Mesh[/] Starting {count} agents")
    for entry in runner._agents:
        console.print(f"  {entry['name']} -> http://{host}:{entry['port']}/mcp")
    console.print()
    try:
        asyncio.run(runner.run_all(host=host, transport=transport))
    except KeyboardInterrupt:
        console.print("\n[dim]Mesh stopped[/]")


@cli.command()
@click.argument("uri", type=str)
def probe(uri: str):
    """Probe a running Heddle agent or MCP server for available tools.

    \b
    Example:
      heddle probe http://localhost:8200/mcp
    """
    asyncio.run(_probe_async(uri))


async def _probe_async(uri: str):
    from heddle.mcp.client import HeddleMCPClient, MCPClientError
    client = HeddleMCPClient("cli-probe", uri)
    try:
        tools = await client.list_tools()
    except MCPClientError as exc:
        console.print(f"[red]Cannot connect:[/] {exc}")
        sys.exit(1)
    console.print(f"\n[bold cyan]{uri}[/]  ({len(tools)} tools)")
    table = Table()
    table.add_column("Tool", style="bold")
    table.add_column("Description")
    for t in tools:
        console.print(f"  {t['name']}: {t.get('description','')[:70]}")
    console.print()



# ── Phase 3f: Signing & Quarantine ───────────────────────────────────

@cli.group()
def sign():
    """Config signing and verification."""


@sign.command("all")
@click.argument("agents_dir", type=click.Path(exists=True), default="agents")
def sign_all(agents_dir: str):
    """Sign all agent configs in a directory."""
    from heddle.security.signing import ConfigSigner
    signer = ConfigSigner()
    count = signer.sign_all(agents_dir)
    console.print(f"[green]OK[/] Signed {count} configs")
    for name, sig in signer.list_signatures().items():
        console.print(f"  {name}: {sig[:16]}...")


@sign.command("verify")
@click.argument("agents_dir", type=click.Path(exists=True), default="agents")
def sign_verify(agents_dir: str):
    """Verify all agent config signatures."""
    from heddle.security.signing import ConfigSigner, SignatureError
    signer = ConfigSigner()
    results = signer.verify_all(agents_dir)
    all_valid = True
    for r in results:
        if r["status"] == "valid":
            console.print(f"  [green]OK[/] {r['file']}")
        else:
            console.print(f"  [red]FAIL[/] {r['file']}: {r.get('error','')}")
            all_valid = False
    if all_valid:
        console.print(f"\n[green]All {len(results)} configs verified[/]")
    else:
        sys.exit(1)


@sign.command("config")
@click.argument("config_path", type=click.Path(exists=True))
def sign_config(config_path: str):
    """Sign a single agent config."""
    from heddle.security.signing import ConfigSigner
    signer = ConfigSigner()
    sig = signer.sign(config_path)
    console.print(f"[green]OK[/] {config_path}: {sig[:16]}...")


@cli.group()
def quarantine():
    """AI-generated agent quarantine management."""


@quarantine.command("list")
def quarantine_list():
    """List quarantined agent configs."""
    from heddle.security.signing import AgentQuarantine
    q = AgentQuarantine()
    entries = q.list_all()
    if not entries:
        console.print("[dim]No quarantined configs.[/]")
        return
    table = Table(title="Quarantine")
    table.add_column("File", style="cyan")
    table.add_column("Source")
    table.add_column("Status", style="bold")
    table.add_column("Date")
    status_colors = {"pending": "yellow", "promoted": "green", "rejected": "red"}
    for e in entries:
        color = status_colors.get(e["status"], "white")
        table.add_row(e["file"], e["source"], f"[{color}]{e['status']}[/]",
                      e.get("quarantined_at", "")[:10])
    console.print(table)


@quarantine.command("promote")
@click.argument("filename")
@click.option("--agents-dir", default="agents", type=click.Path(exists=True))
def quarantine_promote(filename: str, agents_dir: str):
    """Promote a quarantined config to the live agents directory."""
    from heddle.security.signing import AgentQuarantine
    q = AgentQuarantine()
    try:
        dest = q.promote(filename, agents_dir)
        console.print(f"[green]OK[/] Promoted {filename} -> {dest}")
    except FileNotFoundError:
        console.print(f"[red]Not found[/] in quarantine: {filename}")
        sys.exit(1)


@quarantine.command("reject")
@click.argument("filename")
@click.option("--reason", default="", help="Rejection reason")
def quarantine_reject(filename: str, reason: str):
    """Reject a quarantined config."""
    from heddle.security.signing import AgentQuarantine
    q = AgentQuarantine()
    q.reject(filename, reason=reason)
    console.print(f"[yellow]Rejected[/] {filename}" + (f": {reason}" if reason else ""))


# ── Phase 3a: Sandbox ────────────────────────────────────────────────

@cli.command()
@click.argument("config_path", type=click.Path(exists=True))
def sandbox(config_path: str):
    """Show sandbox configuration for an agent."""
    from heddle.config.loader import load_agent_config
    from heddle.security.sandbox import SandboxManager
    config = load_agent_config(config_path)
    mgr = SandboxManager()
    report = mgr.validate_sandbox(config)
    sb = report["sandbox"]
    console.print(f"\n[bold cyan]Sandbox: {report['agent']}[/]")
    console.print(f"  Image: {sb['image']}")
    console.print(f"  Memory: {sb['memory']}  |  CPU: {sb['cpu']}")
    console.print(f"  Network: {sb['network']}  |  Read-only: {sb['readonly']}")
    console.print(f"  Timeout: {sb['timeout']}s")
    console.print(f"  Docker: {'available' if report['docker_available'] else 'not available'}")
    if sb["hosts"]:
        console.print(f"  Allowed hosts: {', '.join(sb['hosts'])}")
    if report["warnings"]:
        for w in report["warnings"]:
            console.print(f"  [yellow]Warning:[/] {w}")
    if report["issues"]:
        for i in report["issues"]:
            console.print(f"  [red]Issue:[/] {i}")
    console.print(f"\n  Docker run args:")
    for arg in report["docker_run_args"]:
        console.print(f"    {arg}")


if __name__ == "__main__":
    cli()
