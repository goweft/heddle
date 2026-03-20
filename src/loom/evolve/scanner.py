"""LOOM evolution scanner — discovers MCP servers, agent patterns, and
library upgrades from GitHub, HuggingFace, and the MCP registries.

Can be run manually via `loom evolve scan` or on a cron schedule.
Feeds results into the LOOM evolve suggestion system.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

import httpx

from loom.evolve import LoomEvolve, EvolveSuggestion

logger = logging.getLogger(__name__)

# Sources to scan
MCP_REGISTRY_URL = "https://registry.modelcontextprotocol.io/servers"
GITHUB_SEARCH_QUERIES = [
    "mcp-server python fastmcp",
    "model context protocol agent",
    "mcp server prometheus grafana monitoring",
    "mcp server homelab docker",
    "mcp server security audit",
]


async def scan_github_trending(evolve: LoomEvolve) -> list[EvolveSuggestion]:
    """Scan GitHub trending for relevant MCP/agent repos."""
    suggestions = []

    async with httpx.AsyncClient(timeout=15.0) as client:
        # Use RSSHub for GitHub trending
        for language in ["python", "typescript"]:
            try:
                resp = await client.get(
                    f"http://localhost:1200/github/trending/daily/{language}.json"
                )
                if resp.status_code == 200:
                    data = resp.json()
                    items = data.get("items", [])
                    repos = []
                    for item in items:
                        # Parse repo info from the feed item
                        title = item.get("title", "")
                        url = item.get("url", "")
                        desc = item.get("content_text", item.get("summary", ""))
                        repos.append({
                            "name": title,
                            "description": desc,
                            "url": url,
                            "stars": 0,
                        })
                    matched = evolve.match_mcp_patterns(repos)
                    suggestions.extend(matched)
                    logger.info(
                        "GitHub trending (%s): %d repos, %d MCP-relevant",
                        language, len(repos), len(matched),
                    )
            except Exception as exc:
                logger.warning("Failed to scan GitHub trending (%s): %s", language, exc)

    return suggestions


async def scan_github_search(evolve: LoomEvolve) -> list[EvolveSuggestion]:
    """Search GitHub for specific MCP server patterns via Gitea search proxy."""
    suggestions = []

    async with httpx.AsyncClient(timeout=15.0) as client:
        for query in GITHUB_SEARCH_QUERIES:
            try:
                # Use Gitea as a proxy — search its mirrored repos
                resp = await client.get(
                    f"http://localhost:3080/api/v1/repos/search",
                    params={"q": query, "limit": 10},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    repos_data = data.get("data", []) if isinstance(data, dict) else data
                    repos = [
                        {
                            "name": r.get("full_name", r.get("name", "")),
                            "description": r.get("description", ""),
                            "url": r.get("html_url", ""),
                            "stars": r.get("stars_count", 0),
                        }
                        for r in repos_data
                    ]
                    matched = evolve.match_mcp_patterns(repos)
                    suggestions.extend(matched)
            except Exception as exc:
                logger.warning("GitHub search failed for '%s': %s", query, exc)

    return suggestions


async def scan_huggingface_mcp(evolve: LoomEvolve) -> list[EvolveSuggestion]:
    """Scan HuggingFace for MCP-tagged spaces."""
    suggestions = []

    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            resp = await client.get(
                "https://huggingface.co/api/spaces",
                params={"filter": "mcp-server", "limit": 20, "sort": "likes"},
            )
            if resp.status_code == 200:
                spaces = resp.json()
                for space in spaces:
                    name = space.get("id", "")
                    desc = space.get("cardData", {}).get("short_description", "")
                    likes = space.get("likes", 0)

                    suggestions.append(EvolveSuggestion(
                        category="ai",
                        title=f"HF MCP Space: {name}",
                        description=f"{desc}. Likes: {likes}",
                        source="huggingface",
                        source_url=f"https://huggingface.co/spaces/{name}",
                        relevance=min(1.0, likes / 1000),
                        effort="medium",
                    ))
                logger.info("HuggingFace MCP spaces: %d found", len(spaces))
        except Exception as exc:
            logger.warning("HuggingFace scan failed: %s", exc)

    return suggestions


async def scan_weft_evolve_recommendations(evolve: LoomEvolve) -> list[EvolveSuggestion]:
    """Pull recommendations from the existing weft-evolve system that
    are relevant to LOOM agent development."""
    suggestions = []

    # Read from weft-evolve's data if available
    evolve_db = Path.home() / ".weft" / "news-agents" / "evolve_recommendations.json"
    if not evolve_db.exists():
        # Try the SQLite database
        import sqlite3
        db_path = Path.home() / ".weft" / "news-agents" / "data" / "evolve.db"
        if db_path.exists():
            try:
                conn = sqlite3.connect(str(db_path))
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT * FROM recommendations WHERE status='new' "
                    "ORDER BY relevance DESC LIMIT 20"
                ).fetchall()
                for row in rows:
                    url = row["url"] if "url" in row.keys() else ""
                    desc = row["rationale"] if "rationale" in row.keys() else ""
                    suggestions.append(EvolveSuggestion(
                        category="ai",
                        title=f"weft-evolve: {row['source_repo']}",
                        description=desc[:200],
                        source="weft-evolve",
                        source_url=url,
                        relevance=row["relevance"] if "relevance" in row.keys() else 0.5,
                    ))
                conn.close()
            except Exception as exc:
                logger.warning("weft-evolve DB read failed: %s", exc)

    return suggestions


from pathlib import Path

async def run_full_scan() -> dict[str, Any]:
    """Run all scanners and return a summary."""
    evolve = LoomEvolve()
    all_suggestions = []

    # 1. Coverage gaps (always available, no network needed)
    gaps = evolve.analyze_coverage_gaps()
    for gap in gaps:
        s = EvolveSuggestion(
            category="coverage",
            title=f"Missing agent: {gap['service']}",
            description=gap["suggestion"],
            source="local",
            relevance=0.9,
            effort=gap["effort"],
        )
        all_suggestions.append(s)

    # 2. GitHub trending
    try:
        trending = await scan_github_trending(evolve)
        all_suggestions.extend(trending)
    except Exception as exc:
        logger.warning("GitHub trending scan failed: %s", exc)

    # 3. HuggingFace MCP spaces
    try:
        hf = await scan_huggingface_mcp(evolve)
        all_suggestions.extend(hf)
    except Exception as exc:
        logger.warning("HuggingFace scan failed: %s", exc)

    # 4. weft-evolve cross-reference
    try:
        we = await scan_weft_evolve_recommendations(evolve)
        all_suggestions.extend(we)
    except Exception as exc:
        logger.warning("weft-evolve scan failed: %s", exc)

    # Deduplicate by title
    seen = set()
    unique = []
    for s in all_suggestions:
        key = s.title if isinstance(s, EvolveSuggestion) else s.get("title", "")
        if key not in seen:
            seen.add(key)
            unique.append(s)

    # Save unique suggestions
    for s in unique:
        if isinstance(s, EvolveSuggestion):
            evolve.add_suggestion(s)

    return {
        "total_found": len(all_suggestions),
        "unique": len(unique),
        "by_source": {
            "coverage_gaps": len(gaps),
            "github_trending": len([s for s in all_suggestions if isinstance(s, EvolveSuggestion) and s.source == "github"]),
            "huggingface": len([s for s in all_suggestions if isinstance(s, EvolveSuggestion) and s.source == "huggingface"]),
            "weft_evolve": len([s for s in all_suggestions if isinstance(s, EvolveSuggestion) and s.source == "weft-evolve"]),
        },
        "summary": evolve.summary(),
    }
