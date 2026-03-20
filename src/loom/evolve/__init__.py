"""LOOM agent evolution — passive research and self-improvement.

Scans GitHub, HuggingFace, and the MCP ecosystem for:
1. New MCP server patterns that could become LOOM agents
2. Library upgrades for existing agents
3. New API integrations relevant to weftbox services
4. Agent orchestration patterns from the community

Works with the existing weft-evolve system and LOOM's own generator
to create a feedback loop: discover → evaluate → generate → validate.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from loom.security.audit import get_audit_logger

logger = logging.getLogger(__name__)

EVOLVE_DIR = Path.home() / ".loom" / "evolve"
SUGGESTIONS_FILE = EVOLVE_DIR / "suggestions.json"

# MCP server patterns we're specifically looking for
RELEVANT_PATTERNS = {
    "monitoring": ["prometheus", "grafana", "alertmanager", "victoriametrics", "datadog"],
    "devops": ["kubernetes", "docker", "portainer", "terraform", "ansible"],
    "data": ["sqlite", "postgres", "redis", "chromadb", "qdrant", "milvus"],
    "messaging": ["rocketchat", "slack", "discord", "matrix"],
    "code": ["gitea", "github", "gitlab", "git"],
    "ai": ["ollama", "huggingface", "openai", "anthropic", "langchain"],
    "feeds": ["rss", "rsshub", "news", "arxiv", "hn", "reddit"],
    "homelab": ["homeassistant", "proxmox", "unraid", "nas", "plex"],
    "security": ["vault", "keycloak", "crowdsec", "wazuh"],
}

# Services actually running on weftbox
WEFTBOX_SERVICES = {
    "prometheus": {"port": 9092, "has_agent": True},
    "grafana": {"port": 3005, "has_agent": False},
    "ollama": {"port": 11434, "has_agent": True},
    "gitea": {"port": 3080, "has_agent": True},
    "rsshub": {"port": 1200, "has_agent": True},
    "weft-intel": {"port": 9090, "has_agent": True},
    "uptime-kuma": {"port": 3004, "has_agent": False},
    "portainer": {"port": 9000, "has_agent": False},
    "open-webui": {"port": 8080, "has_agent": False},
    "rocketchat": {"port": None, "has_agent": False},
    "nexus": {"port": 8080, "has_agent": False},
}


class EvolveSuggestion:
    """A suggested improvement or new agent."""

    def __init__(
        self,
        category: str,
        title: str,
        description: str,
        source: str,
        source_url: str = "",
        relevance: float = 0.0,
        effort: str = "medium",
        status: str = "new",
    ):
        self.category = category
        self.title = title
        self.description = description
        self.source = source
        self.source_url = source_url
        self.relevance = relevance
        self.effort = effort
        self.status = status
        self.created_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "source": self.source,
            "source_url": self.source_url,
            "relevance": self.relevance,
            "effort": self.effort,
            "status": self.status,
            "created_at": self.created_at,
        }


class LoomEvolve:
    """Manages the evolution and self-improvement of the LOOM platform."""

    def __init__(self):
        EVOLVE_DIR.mkdir(parents=True, exist_ok=True)
        self._audit = get_audit_logger()
        self._suggestions: list[dict] = self._load_suggestions()

    def _load_suggestions(self) -> list[dict]:
        if SUGGESTIONS_FILE.exists():
            try:
                return json.loads(SUGGESTIONS_FILE.read_text())
            except Exception:
                pass
        return []

    def _save_suggestions(self) -> None:
        SUGGESTIONS_FILE.write_text(json.dumps(self._suggestions, indent=2))

    def add_suggestion(self, suggestion: EvolveSuggestion) -> int:
        """Add a new suggestion and return its index."""
        self._suggestions.append(suggestion.to_dict())
        self._save_suggestions()
        self._audit.log_agent_lifecycle(
            "loom-evolve", "suggestion",
            f"New: {suggestion.title} ({suggestion.category})",
        )
        return len(self._suggestions) - 1

    def get_suggestions(
        self,
        category: str | None = None,
        status: str | None = None,
    ) -> list[dict]:
        results = self._suggestions
        if category:
            results = [s for s in results if s["category"] == category]
        if status:
            results = [s for s in results if s["status"] == status]
        return results

    def update_status(self, index: int, status: str) -> bool:
        if 0 <= index < len(self._suggestions):
            self._suggestions[index]["status"] = status
            self._save_suggestions()
            return True
        return False

    # ── Analysis methods ─────────────────────────────────────────────

    def analyze_coverage_gaps(self) -> list[dict]:
        """Find weftbox services that don't have LOOM agents yet."""
        gaps = []
        for service, info in WEFTBOX_SERVICES.items():
            if not info["has_agent"]:
                gaps.append({
                    "service": service,
                    "port": info["port"],
                    "suggestion": f"Create a LOOM bridge agent for {service}",
                    "effort": "low" if info["port"] else "medium",
                })
        return gaps

    def match_mcp_patterns(self, repos: list[dict]) -> list[EvolveSuggestion]:
        """Match discovered repos against relevant patterns.

        Takes a list of repo dicts (from GitHub trending, HF search, etc.)
        and returns suggestions for repos that match our interests.
        """
        suggestions = []
        for repo in repos:
            name = repo.get("name", "").lower()
            desc = (repo.get("description", "") or "").lower()
            url = repo.get("url", repo.get("html_url", ""))
            stars = repo.get("stars", repo.get("stargazers_count", 0))
            combined = f"{name} {desc}"

            for category, keywords in RELEVANT_PATTERNS.items():
                matched_keywords = [k for k in keywords if k in combined]
                if matched_keywords and "mcp" in combined:
                    relevance = min(1.0, len(matched_keywords) * 0.3 + (stars / 10000))
                    suggestions.append(EvolveSuggestion(
                        category=category,
                        title=f"MCP server: {repo.get('name', '?')}",
                        description=(
                            f"{repo.get('description', 'No description')[:200]}. "
                            f"Stars: {stars}. Matched: {', '.join(matched_keywords)}"
                        ),
                        source="github",
                        source_url=url,
                        relevance=relevance,
                        effort="low" if "fastmcp" in combined or "python" in combined else "medium",
                    ))

        return suggestions

    def generate_agent_brief(self, service_name: str) -> str:
        """Generate a natural language brief for the LLM agent generator.

        This is what gets passed to `loom generate` to create a new agent.
        """
        info = WEFTBOX_SERVICES.get(service_name, {})
        port = info.get("port", "unknown")

        # Service-specific prompts
        service_briefs = {
            "grafana": (
                f"agent that bridges the Grafana API at localhost:{port}. "
                "Expose tools to list dashboards, get dashboard JSON by UID, "
                "query datasources, and list alert rules. "
                "Grafana API docs: GET /api/dashboards/home, GET /api/search?type=dash-db, "
                "GET /api/dashboards/uid/<uid>, GET /api/datasources, GET /api/ruler/grafana/api/v1/rules. "
                "Some endpoints need an API key in the Authorization header."
            ),
            "portainer": (
                f"agent that bridges the Portainer API at localhost:{port}. "
                "Expose tools to list Docker containers, get container stats, "
                "list stacks, and get endpoint info. "
                "Portainer API: GET /api/endpoints, GET /api/endpoints/<id>/docker/containers/json, "
                "GET /api/stacks. Auth via X-API-Key header."
            ),
            "open-webui": (
                f"agent that bridges the Open WebUI API at localhost:{port}. "
                "Expose tools to list available models, list chat history, "
                "and check system health. "
                "API: GET /api/models, GET /api/v1/chats, GET /health."
            ),
        }

        return service_briefs.get(service_name, (
            f"agent that bridges the {service_name} API at localhost:{port}. "
            "Discover available endpoints and expose the most useful ones as tools."
        ))

    def summary(self) -> dict:
        """Get a summary of the evolution state."""
        return {
            "total_suggestions": len(self._suggestions),
            "by_status": {
                s: len([x for x in self._suggestions if x["status"] == s])
                for s in {"new", "reviewing", "accepted", "dismissed", "implemented"}
            },
            "by_category": {
                c: len([x for x in self._suggestions if x["category"] == c])
                for c in set(x["category"] for x in self._suggestions)
            } if self._suggestions else {},
            "coverage_gaps": len(self.analyze_coverage_gaps()),
            "weftbox_services": len(WEFTBOX_SERVICES),
            "agents_deployed": sum(1 for s in WEFTBOX_SERVICES.values() if s["has_agent"]),
        }
