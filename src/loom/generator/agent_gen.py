"""Generate LOOM agent configs from natural language descriptions.

Flow:
  1. User provides a plain-english description
  2. We build a structured prompt with the schema spec + example
  3. LLM generates YAML
  4. We parse, validate, and optionally dry-run it
  5. Save to agents/ directory
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

import yaml

from loom.config.loader import validate_config, ConfigError
from loom.config.schema import AgentConfig
from loom.generator.llm import LLMClient, DEFAULT_MODEL

logger = logging.getLogger(__name__)

AGENTS_DIR = Path("/mnt/workspace/projects/loom/agents")

# ── System prompt ────────────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are LOOM Agent Generator. You produce valid YAML agent configurations
for the LOOM platform. LOOM turns YAML configs into MCP servers automatically.

IMPORTANT RULES:
- Output ONLY the YAML. No markdown fences, no explanation, no preamble.
- The YAML must start with "agent:" at the top level.
- Every exposed tool that wraps an HTTP API MUST have a matching http_bridge entry.
- Tool names must be lowercase with underscores (snake_case).
- Agent names must be lowercase with hyphens (kebab-case).
- Use provider: none for pure API bridge agents (no LLM needed in the agent).
- Use provider: ollama when the agent needs to call an LLM for processing.
- Set trust_tier: 1 for read-only agents, 2 for agents that write data.
- Include meaningful descriptions for every tool and parameter.
"""

# ── Schema reference (compact) ───────────────────────────────────────

SCHEMA_REF = """\
YAML SCHEMA:

agent:
  name: string (kebab-case, required)
  version: string (semver, default "1.0.0")
  description: string (what this agent does)

  model:
    provider: ollama | nexus | anthropic | openai | none
    model: string (e.g. "qwen3:14b")
    temperature: float (0.0-2.0, default 0.3)

  consumes: []  # MCP tools this agent calls (Phase 4)

  exposes:
    - name: string (snake_case tool name)
      description: string (what the tool does)
      parameters:
        param_name:
          type: string | integer | number | boolean | array | object
          description: string
          required: true | false
          default: any (optional)
      returns:
        type: string
        description: string

  http_bridge:
    - tool_name: string (must match an exposed tool name)
      method: GET | POST | PUT | DELETE | PATCH
      url: string (use {{param_name}} for URL templates)
      headers:
        Header-Name: "value"
      body_template:         # for POST/PUT
        key: "{{param_name}}"
      query_params:          # for GET query strings
        param_name: query_key
      response_path: string  # optional dot-path to extract from response

  runtime:
    sandbox: none | docker
    trust_tier: 1 (read-only) | 2 (scoped write) | 3 (full scope) | 4 (human-in-loop)
    max_execution_time: "30s" | "60s" | "120s"

  triggers:
    - type: on_demand | cron | webhook
      schedule: "cron expression"  # for cron type
"""

# ── Example (trimmed) ────────────────────────────────────────────────

EXAMPLE_CONFIG = """\
EXAMPLE (a working agent that bridges a REST API):

agent:
  name: weft-intel-bridge
  version: "1.0.0"
  description: "Bridge to the WEFT Intelligence platform for news analysis."

  model:
    provider: none

  consumes: []

  exposes:
    - name: get_trending
      description: "Get currently trending entities by mention velocity."
      parameters:
        hours:
          type: integer
          description: "Lookback window in hours"
          required: false
          default: 24
        limit:
          type: integer
          description: "Max entities to return"
          required: false
          default: 20
      returns:
        type: string
        description: "JSON array of trending entities"

    - name: ask_intel
      description: "Ask a question using RAG over indexed news articles."
      parameters:
        question:
          type: string
          description: "The question to ask"
          required: true
      returns:
        type: string
        description: "AI-generated answer with citations"

  http_bridge:
    - tool_name: get_trending
      method: GET
      url: "http://localhost:9090/api/trending"
      query_params:
        hours: hours
        limit: limit

    - tool_name: ask_intel
      method: POST
      url: "http://localhost:9090/api/query"
      body_template:
        question: "{{question}}"
      headers:
        Content-Type: "application/json"

  runtime:
    sandbox: none
    trust_tier: 1
    max_execution_time: 60s

  triggers:
    - type: on_demand
"""


def _build_prompt(description: str, context: str = "") -> str:
    """Build the generation prompt from user description and optional context."""
    parts = [SCHEMA_REF, EXAMPLE_CONFIG]

    if context:
        parts.append(f"ADDITIONAL CONTEXT:\n{context}")

    parts.append(
        f"Generate a LOOM agent YAML config for the following description. "
        f"Output ONLY valid YAML starting with 'agent:'.\n\n"
        f"DESCRIPTION: {description}"
    )

    return "\n\n".join(parts)


def _extract_yaml(text: str) -> str:
    """Extract YAML from LLM response, stripping markdown fences and thinking."""
    # Strip <think>...</think> blocks (some models like qwen3 produce these)
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)

    # Strip markdown code fences
    text = re.sub(r"```ya?ml\s*\n?", "", text)
    text = re.sub(r"```\s*$", "", text, flags=re.MULTILINE)

    # Find the YAML block starting with "agent:"
    match = re.search(r"^(agent:.*)", text, re.DOTALL | re.MULTILINE)
    if match:
        return match.group(1).strip()

    # Fallback: return cleaned text
    return text.strip()


async def generate_agent(
    description: str,
    model: str = DEFAULT_MODEL,
    context: str = "",
    output_dir: str | Path | None = None,
    validate_only: bool = False,
) -> dict[str, Any]:
    """Generate a LOOM agent config from a natural language description.

    Returns a dict with:
      - yaml_text: the raw YAML string
      - config: validated AgentConfig (if validation passes)
      - path: Path where the config was saved (if not validate_only)
      - errors: list of validation errors (if any)
    """
    output_dir = Path(output_dir) if output_dir else AGENTS_DIR

    # 1. Build prompt and call LLM
    prompt = _build_prompt(description, context)
    llm = LLMClient(provider="ollama", model=model)

    logger.info("Generating agent config with %s...", model)
    raw_response = await llm.generate(prompt, system=SYSTEM_PROMPT)

    # 2. Extract YAML from response
    yaml_text = _extract_yaml(raw_response)

    result: dict[str, Any] = {
        "yaml_text": yaml_text,
        "config": None,
        "path": None,
        "errors": [],
        "raw_response": raw_response,
    }

    # 3. Parse YAML
    try:
        parsed = yaml.safe_load(yaml_text)
    except yaml.YAMLError as exc:
        result["errors"].append(f"YAML parse error: {exc}")
        return result

    if not isinstance(parsed, dict) or "agent" not in parsed:
        result["errors"].append("Generated YAML missing top-level 'agent:' key")
        return result

    # 4. Validate against schema
    try:
        config = validate_config(parsed, source="<generated>")
        result["config"] = config
    except ConfigError as exc:
        result["errors"].append(str(exc))
        return result

    # 5. Save if not validate_only
    if not validate_only and config:
        agent_name = config.agent.name
        output_path = output_dir / f"{agent_name}.yaml"
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path.write_text(yaml_text)
        result["path"] = output_path
        logger.info("Saved generated config to %s", output_path)

    return result


async def retry_generate(
    description: str,
    model: str = DEFAULT_MODEL,
    context: str = "",
    max_retries: int = 2,
    output_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Generate with retry on validation failure.

    On each retry, feeds the validation errors back to the LLM
    so it can fix them.
    """
    result = await generate_agent(
        description, model=model, context=context,
        output_dir=output_dir, validate_only=True,
    )

    attempt = 1
    while result["errors"] and attempt <= max_retries:
        logger.info("Retry %d/%d — feeding errors back to LLM", attempt, max_retries)
        error_context = (
            f"{context}\n\nPREVIOUS ATTEMPT FAILED WITH ERRORS:\n"
            + "\n".join(result["errors"])
            + "\n\nFix the errors and output corrected YAML."
        )
        result = await generate_agent(
            description, model=model, context=error_context,
            output_dir=output_dir, validate_only=True,
        )
        attempt += 1

    # Final save if valid
    if not result["errors"] and result["config"]:
        out = Path(output_dir) if output_dir else AGENTS_DIR
        agent_name = result["config"].agent.name
        output_path = out / f"{agent_name}.yaml"
        out.mkdir(parents=True, exist_ok=True)
        output_path.write_text(result["yaml_text"])
        result["path"] = output_path

    return result
