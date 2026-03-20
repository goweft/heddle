"""Load and validate LOOM agent YAML configs."""

from __future__ import annotations

from pathlib import Path
from typing import Union

import yaml
from pydantic import ValidationError

from loom.config.schema import AgentConfig


class ConfigError(Exception):
    """Raised when an agent config is invalid."""


def load_agent_config(path: Union[str, Path]) -> AgentConfig:
    """Load an agent YAML config and return a validated AgentConfig."""
    path = Path(path)
    if not path.exists():
        raise ConfigError(f"Config file not found: {path}")
    if not path.suffix in (".yaml", ".yml"):
        raise ConfigError(f"Config must be .yaml or .yml: {path}")

    try:
        raw = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in {path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise ConfigError(f"Config must be a YAML mapping, got {type(raw).__name__}")

    return validate_config(raw, source=str(path))


def validate_config(data: dict, source: str = "<unknown>") -> AgentConfig:
    """Validate a parsed dict against the AgentConfig schema."""
    try:
        config = AgentConfig.model_validate(data)
    except ValidationError as exc:
        lines = [f"Config validation failed ({source}):"]
        for err in exc.errors():
            loc = " -> ".join(str(p) for p in err["loc"])
            lines.append(f"  * {loc}: {err['msg']}")
        raise ConfigError("\n".join(lines)) from exc

    exposed_names = {t.name for t in config.agent.exposes}
    for ep in config.agent.http_bridge:
        if ep.tool_name not in exposed_names:
            raise ConfigError(
                f"http_bridge references tool '{ep.tool_name}' "
                f"which is not in exposes. Available: {exposed_names}"
            )

    return config


def discover_configs(directory: Union[str, Path]) -> list[Path]:
    """Find all .yaml/.yml agent configs in a directory."""
    d = Path(directory)
    if not d.is_dir():
        return []
    configs = []
    for ext in ("*.yaml", "*.yml"):
        configs.extend(d.glob(ext))
    return sorted(configs)
