#!/usr/bin/env python3
"""Generate RSSHub agent via LLM."""
import asyncio, sys
sys.path.insert(0, "/mnt/workspace/projects/loom/src")

import loom.security.audit as _a
_a._global_audit = None

from loom.generator.agent_gen import retry_generate

async def main():
    result = await retry_generate(
        "agent that bridges the RSSHub API at localhost:1200 for fetching RSS feeds",
        model="qwen3:14b",
        context=(
            "RSSHub is a self-hosted RSS feed generator. The API works like this:\n"
            "  GET /<route> — returns RSS/Atom XML for any supported route\n"
            "  GET /<route>.json — returns JSON format instead of XML\n"
            "  GET /api/radar/rules — lists all available feed radar rules (huge JSON)\n\n"
            "Useful routes on this instance:\n"
            "  /hn/frontpage.json — Hacker News front page\n"
            "  /github/trending/daily/all.json — GitHub trending repos\n"
            "  /arxiv/search_query=AI/0/10.json — arXiv AI papers\n"
            "  /reuters/world.json — Reuters world news\n\n"
            "All feed routes support .json suffix for JSON output.\n"
            "Parameters go in the URL path, not query strings.\n"
            "The agent should expose 3-4 tools for common feed types.\n"
            "Use the .json suffix on all URLs so responses are JSON, not XML."
        ),
        max_retries=2,
        output_dir="/mnt/workspace/projects/loom/agents",
    )
    if result["errors"]:
        print("FAILED:", result["errors"])
        print(result["yaml_text"][:2000])
        return
    c = result["config"]
    print(f"OK: {c.agent.name} v{c.agent.version}")
    for t in c.agent.exposes:
        bridge = [b for b in c.agent.http_bridge if b.tool_name == t.name]
        url = bridge[0].url if bridge else "no bridge"
        print(f"  {t.name} -> {url}")
    if result.get("path"):
        print(f"\nSaved: {result['path']}")

asyncio.run(main())
