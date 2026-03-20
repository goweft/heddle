"""LOOM CLI -- the primary interface for managing agents."""

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

from loom import __version__

console = Console()


def _get_registry():
    from loom.mcp.registry import Registry
    return Registry()


@click.group()
@click.version_option(__version__, prog_name="loom")
def cli():
    """LOOM -- The WEFT Agent & MCP Mesh Runtime."""


@cli.command()
@click.argument("config_path", type=click.Path(exists=True))
@click.option("--host", default="0.0.0.0", help="Bind address")
@click.option("--port", default=8200, type=int, help="Port for MCP server")
@click.option("--transport", default="streamable-http",
              type=click.Choice(["streamable-http", "sse", "stdio"]), help="MCP transport")
def run(config_path: str, host: str, port: int, transport: str):
    """Run an agent from a YAML config file."""
    from loom.runtime.engine import AgentRunner
    runner = AgentRunner()
    config = runner.load(config_path)
    spec = config.agent
    console.print(f"\n[bold cyan]LOOM[/] Starting agent [bold]{spec.name}[/] v{spec.version}")
    console.print(f"  Tools: {len(spec.exposes)} exposed, {len(spec.consumes)} consumed")
    console.print(f"  Trust tier: {spec.runtime.trust_tier}")
    console.print(f"  Endpoint: http://{host}:{port}/mcp\n")
    runner.register(config, config_path=config_path, port=port)
    runner.run(config, host=host, port=port, transport=transport)


@cli.command()
@click.argument("config_path", type=click.Path(exists=True))
def validate(config_path: str):
    """Validate an agent config without running it."""
    from loom.runtime.engine import AgentRunner
    from loom.config.loader import ConfigError
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
        console.print("[dim]No agents registered. Run 'loom run <config>' to register one.[/]")
        return
    table = Table(title="LOOM Agents")
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
    table = Table(title="LOOM Tool Registry")
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
@click.option("--output-dir", default=None, type=click.Path(), help="Output directory for generated config")
@click.option("--dry-run", is_flag=True, help="Validate only, don't save")
@click.option("--retries", default=2, type=int, help="Max retries on validation failure")
def generate(description: str, model: str, discover: str | None,
             output_dir: str | None, dry_run: bool, retries: int):
    """Generate an agent config from a natural language description.

    \b
    Examples:
      loom generate "agent that wraps the Uptime Kuma API at localhost:3001"
      loom generate "RSS feed monitor that posts to Rocket.Chat" --model qwen3.5:9b
      loom generate "bridge to Gitea API" --discover http://localhost:3080
    """
    asyncio.run(_generate_async(description, model, discover, output_dir, dry_run, retries))


async def _generate_async(description: str, model: str, discover_url: str | None,
                          output_dir: str | None, dry_run: bool, retries: int):
    from loom.generator.agent_gen import generate_agent, retry_generate
    from loom.generator.llm import LLMClient

    # Check LLM availability
    llm = LLMClient(model=model)
    if not await llm.check_available():
        console.print("[bold red]Ollama not reachable.[/] Is it running on localhost:11434?")
        sys.exit(1)

    console.print(f"\n[bold cyan]LOOM Generate[/]")
    console.print(f"  Model: {model}")
    console.print(f"  Description: {description}")

    # Optional API discovery
    context = ""
    if discover_url:
        from loom.generator.discover import discover_api, format_discovery_context
        console.print(f"  Discovering: {discover_url}...")
        disc = await discover_api(discover_url)
        context = format_discovery_context(disc)
        ep_count = len(disc.get("endpoints", []))
        console.print(f"  Found {ep_count} endpoint(s)")
        if disc.get("openapi"):
            title = disc["openapi"].get("info", {}).get("title", "?")
            console.print(f"  OpenAPI: {title}")

    console.print()

    # Generate with retries
    with console.status("[bold]Generating agent config..."):
        if retries > 0:
            result = await retry_generate(
                description, model=model, context=context,
                max_retries=retries,
                output_dir=output_dir,
            )
        else:
            result = await generate_agent(
                description, model=model, context=context,
                output_dir=output_dir, validate_only=dry_run,
            )

    # Display results
    if result["errors"]:
        console.print("[bold red]Generation failed:[/]")
        for err in result["errors"]:
            console.print(f"  {err}")
        console.print()
        console.print(Panel(
            Syntax(result["yaml_text"][:2000], "yaml", theme="monokai"),
            title="Raw output (first 2000 chars)",
            border_style="red",
        ))
        sys.exit(1)

    config = result["config"]
    spec = config.agent

    console.print(f"[bold green]OK[/] Generated: [bold]{spec.name}[/] v{spec.version}")
    console.print(f"  {spec.description[:100]}")

    if spec.exposes:
        table = Table(title="Generated tools")
        table.add_column("Tool", style="cyan")
        table.add_column("Bridge", style="yellow")
        table.add_column("Parameters")
        bridge_names = {ep.tool_name for ep in spec.http_bridge}
        for t in spec.exposes:
            table.add_row(
                t.name,
                "http" if t.name in bridge_names else "stub",
                ", ".join(t.parameters.keys()) or "-",
            )
        console.print(table)

    if result.get("path"):
        console.print(f"\n  Saved to: [bold]{result['path']}[/]")
        console.print(f"  Validate: loom validate {result['path']}")
        console.print(f"  Run:      loom run {result['path']} --port 8201")
    elif dry_run:
        console.print("\n  [dim](dry run -- not saved)[/]")
        console.print(Panel(
            Syntax(result["yaml_text"], "yaml", theme="monokai"),
            title="Generated config",
            border_style="cyan",
        ))


if __name__ == "__main__":
    cli()
