"""Heddle orchestrating agent: daily-ops.

This is the first Heddle agent that uses its own LLM brain to reason
across multiple data sources. It demonstrates the "advanced agent"
pattern: consume tools from other agents, synthesize, and produce
new intelligence.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

import httpx

from heddle.generator.llm import LLMClient
from heddle.security.audit import get_audit_logger

logger = logging.getLogger(__name__)

PROMETHEUS_URL = "http://localhost:9090"
INTEL_URL = "http://localhost:9090"
OLLAMA_URL = "http://localhost:11434"


async def _fetch_json(url: str, params: dict | None = None) -> dict | list | None:
    """Fetch JSON from a URL, return None on failure."""
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(url, params=params)
            if resp.status_code == 200:
                return resp.json()
    except Exception as exc:
        logger.warning("Fetch failed %s: %s", url, exc)
    return None


async def _post_json(url: str, body: dict, headers: dict | None = None) -> dict | None:
    """POST JSON, return response or None."""
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, json=body, headers=headers)
            if resp.status_code == 200:
                return resp.json()
    except Exception as exc:
        logger.warning("POST failed %s: %s", url, exc)
    return None


async def gather_system_health() -> dict[str, Any]:
    """Gather system health data from Prometheus."""
    health = {"targets": [], "metrics": {}, "alerts": []}

    # Scrape targets
    data = await _fetch_json(f"{PROMETHEUS_URL}/api/v1/targets")
    if data:
        for t in data.get("data", {}).get("activeTargets", []):
            health["targets"].append({
                "job": t["labels"].get("job", "?"),
                "health": t["health"],
                "url": t.get("scrapeUrl", ""),
            })

    # Key metrics
    queries = {
        "memory_available_gb": "node_memory_MemAvailable_bytes / 1e9",
        "memory_total_gb": "node_memory_MemTotal_bytes / 1e9",
        "cpu_usage_percent": "100 - (avg by(instance) (rate(node_cpu_seconds_total{mode='idle'}[5m])) * 100)",
        "disk_available_gb": 'node_filesystem_avail_bytes{mountpoint="/"} / 1e9',
        "load_avg_1m": "node_load1",
    }
    for name, query in queries.items():
        data = await _fetch_json(f"{PROMETHEUS_URL}/api/v1/query", {"query": query})
        if data and data.get("data", {}).get("result"):
            val = data["data"]["result"][0]["value"][1]
            health["metrics"][name] = round(float(val), 2)

    # Alerts
    data = await _fetch_json(f"{PROMETHEUS_URL}/api/v1/alerts")
    if data:
        health["alerts"] = [
            {"name": a.get("labels", {}).get("alertname", "?"), "state": a.get("state", "?")}
            for a in data.get("data", {}).get("alerts", [])
        ]

    return health


async def gather_intel_summary() -> dict[str, Any]:
    """Gather intelligence data from intel-rag."""
    intel = {"trending": [], "stats": {}, "patterns": []}

    # Get the auth token
    from heddle.security.credentials import get_credential_broker
    broker = get_credential_broker()
    try:
        token = broker.get_credential("intel-rag-bridge", "intel-rag-token")
        headers = {"Authorization": f"Bearer {token}"}
    except Exception:
        headers = {}

    # Trending entities
    data = await _fetch_json(f"{INTEL_URL}/api/trending?hours=24&limit=10")
    if data:
        intel["trending"] = [
            {"name": t["name"], "type": t["type"], "mentions": t["recent_count"]}
            for t in data.get("trending", [])
        ]

    # Stats
    data = await _fetch_json(f"{INTEL_URL}/api/stats/v2")
    if data:
        intel["stats"] = {
            "articles": data.get("articles", 0),
            "entities": data.get("entities", 0),
        }

    # Patterns
    data = await _fetch_json(f"{INTEL_URL}/api/patterns")
    if data:
        patterns = data if isinstance(data, list) else data.get("patterns", [])
        intel["patterns"] = patterns[:5] if patterns else []

    return intel


async def gather_model_status() -> dict[str, Any]:
    """Gather Ollama model status."""
    status = {"installed": [], "running": []}

    data = await _fetch_json(f"{OLLAMA_URL}/api/tags")
    if data:
        status["installed"] = [
            {"name": m["name"], "size_gb": round(m["size"] / 1e9, 1)}
            for m in data.get("models", [])
        ]

    data = await _fetch_json(f"{OLLAMA_URL}/api/ps")
    if data:
        status["running"] = [
            {"name": m["name"], "vram_gb": round(m.get("size_vram", 0) / 1e9, 1)}
            for m in data.get("models", [])
        ]

    return status


async def daily_briefing() -> str:
    """Generate the daily operations briefing.

    Gathers data from all sources, then uses Ollama to synthesize.
    """
    audit = get_audit_logger()
    start = time.monotonic()

    # 1. Gather data from all sources in parallel
    import asyncio
    health_task = asyncio.create_task(gather_system_health())
    intel_task = asyncio.create_task(gather_intel_summary())
    model_task = asyncio.create_task(gather_model_status())

    health = await health_task
    intel = await intel_task
    models = await model_task

    gather_time = time.monotonic() - start

    # 2. Build the LLM prompt
    prompt = f"""You are a concise operations analyst. Generate a daily briefing from this data.
Use markdown formatting. Keep it under 500 words. Be specific with numbers.

## SYSTEM HEALTH (from Prometheus)
Targets: {json.dumps(health['targets'])}
Metrics: {json.dumps(health['metrics'])}
Alerts: {json.dumps(health['alerts'])}

## INTELLIGENCE FEED (from intel-rag)
Stats: {json.dumps(intel['stats'])}
Top trending entities (24h): {json.dumps(intel['trending'])}
Detected patterns: {json.dumps(intel['patterns'][:3]) if intel['patterns'] else 'None'}

## LLM MODELS (from Ollama)
Installed: {json.dumps(models['installed'])}
Currently running: {json.dumps(models['running'])}

Generate a briefing with sections: System Status, Intelligence Highlights, Model Status, Action Items.
"""

    # 3. Call Ollama for synthesis
    llm = LLMClient(provider="ollama", model="qwen3:14b", temperature=0.3)
    try:
        response = await llm.generate(prompt, system="You are a concise daily operations briefer. No thinking tags. Just the briefing.")
        # Strip <think> tags if present
        import re
        response = re.sub(r"<think>.*?</think>", "", response, flags=re.DOTALL).strip()
    except Exception as exc:
        response = (
            f"# Daily Ops Briefing (LLM unavailable)\n\n"
            f"## System Health\n{json.dumps(health, indent=2)}\n\n"
            f"## Intelligence\n{json.dumps(intel, indent=2)}\n\n"
            f"## Models\n{json.dumps(models, indent=2)}"
        )

    duration = (time.monotonic() - start) * 1000
    audit.log_tool_call("daily-ops", "daily_briefing", {}, "success", duration_ms=duration)

    return response


async def system_health_check() -> str:
    """Quick health check — just Prometheus data."""
    health = await gather_system_health()
    return json.dumps(health, indent=2)


async def threat_landscape() -> str:
    """Synthesized threat landscape from intel-rag."""
    intel = await gather_intel_summary()

    llm = LLMClient(provider="ollama", model="qwen3:14b", temperature=0.3)
    prompt = f"""Analyze this intelligence data and produce a brief threat landscape summary.
Focus on: key entities, emerging patterns, and anything requiring attention.
Keep it under 300 words. Markdown format.

Trending entities: {json.dumps(intel['trending'])}
Article count: {intel['stats'].get('articles', '?')}
Patterns: {json.dumps(intel['patterns'][:5]) if intel['patterns'] else 'None detected'}
"""
    try:
        response = await llm.generate(prompt, system="You are a concise intelligence analyst. No thinking tags.")
        import re
        response = re.sub(r"<think>.*?</think>", "", response, flags=re.DOTALL).strip()
    except Exception as exc:
        response = f"# Threat Landscape (LLM unavailable)\n\n{json.dumps(intel, indent=2)}"

    return response
