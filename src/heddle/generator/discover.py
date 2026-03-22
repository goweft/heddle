"""API discovery — probe a running HTTP service to find endpoints.

Used by the generator to auto-discover what a target API exposes,
so the user can say "wrap the API at localhost:8080" and LOOM
figures out the available endpoints.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# Common paths to probe for API discovery
PROBE_PATHS = [
    "/openapi.json",
    "/swagger.json",
    "/api/openapi.json",
    "/docs/openapi.json",
    "/api-docs",
    "/health",
    "/api/health",
    "/api",
    "/api/v1",
    "/api/v2",
]


async def discover_api(base_url: str) -> dict[str, Any]:
    """Probe a base URL and return discovered API info.

    Tries OpenAPI/Swagger first, then falls back to probing
    common paths and checking what responds.
    """
    base_url = base_url.rstrip("/")
    result: dict[str, Any] = {
        "base_url": base_url,
        "openapi": None,
        "endpoints": [],
        "health": None,
    }

    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
        # Try OpenAPI spec first
        for path in ["/openapi.json", "/swagger.json", "/api/openapi.json"]:
            try:
                resp = await client.get(f"{base_url}{path}")
                if resp.status_code == 200:
                    spec = resp.json()
                    result["openapi"] = spec
                    result["endpoints"] = _extract_openapi_endpoints(spec)
                    logger.info("Found OpenAPI spec at %s%s", base_url, path)
                    return result
            except Exception:
                continue

        # Fallback: probe common paths
        for path in PROBE_PATHS:
            try:
                resp = await client.get(f"{base_url}{path}")
                if resp.status_code == 200:
                    content_type = resp.headers.get("content-type", "")
                    entry = {
                        "path": path,
                        "method": "GET",
                        "status": resp.status_code,
                        "content_type": content_type,
                    }
                    if "json" in content_type:
                        try:
                            body = resp.json()
                            if isinstance(body, dict):
                                entry["keys"] = list(body.keys())[:10]
                        except Exception:
                            pass
                    result["endpoints"].append(entry)

                    if "health" in path:
                        result["health"] = entry
            except Exception:
                continue

    logger.info("Discovered %d endpoints at %s", len(result["endpoints"]), base_url)
    return result


def _extract_openapi_endpoints(spec: dict) -> list[dict[str, Any]]:
    """Extract endpoint info from an OpenAPI spec."""
    endpoints = []
    paths = spec.get("paths", {})
    for path, methods in paths.items():
        for method, details in methods.items():
            if method.upper() not in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                continue
            endpoint = {
                "path": path,
                "method": method.upper(),
                "summary": details.get("summary", ""),
                "description": details.get("description", ""),
                "parameters": [],
            }
            for param in details.get("parameters", []):
                endpoint["parameters"].append({
                    "name": param.get("name"),
                    "in": param.get("in"),
                    "type": param.get("schema", {}).get("type", "string"),
                    "required": param.get("required", False),
                })
            # Request body for POST/PUT
            body = details.get("requestBody", {})
            if body:
                content = body.get("content", {})
                json_schema = content.get("application/json", {}).get("schema", {})
                if json_schema:
                    endpoint["body_schema"] = json_schema
            endpoints.append(endpoint)
    return endpoints


def format_discovery_context(discovery: dict[str, Any]) -> str:
    """Format discovery results as context for the LLM prompt."""
    lines = [f"TARGET API: {discovery['base_url']}"]

    if discovery.get("openapi"):
        info = discovery["openapi"].get("info", {})
        lines.append(f"API Title: {info.get('title', 'Unknown')}")
        lines.append(f"API Version: {info.get('version', '?')}")

    if discovery["endpoints"]:
        lines.append(f"\nDiscovered {len(discovery['endpoints'])} endpoints:")
        for ep in discovery["endpoints"]:
            params = ""
            if ep.get("parameters"):
                param_strs = [f"{p['name']}:{p['type']}" for p in ep["parameters"]]
                params = f" params=[{', '.join(param_strs)}]"
            summary = f" -- {ep['summary']}" if ep.get("summary") else ""
            lines.append(f"  {ep['method']} {ep['path']}{params}{summary}")

    if discovery.get("health"):
        lines.append(f"\nHealth endpoint: {discovery['health']['path']} (200 OK)")

    return "\n".join(lines)
