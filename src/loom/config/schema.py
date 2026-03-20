"""Pydantic v2 models for LOOM agent YAML configuration.

Every agent in LOOM is defined by a YAML config file validated against
these models.  The schema is designed to be AI-generatable -- an LLM can
produce a valid config from a natural-language description.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ModelProvider(str, Enum):
    ollama = "ollama"
    nexus = "nexus"
    anthropic = "anthropic"
    openai = "openai"
    none = "none"

class SandboxType(str, Enum):
    docker = "docker"
    gvisor = "gvisor"
    none = "none"

class TrustTier(int, Enum):
    observer = 1
    worker = 2
    operator = 3
    privileged = 4

class TriggerType(str, Enum):
    cron = "cron"
    on_demand = "on_demand"
    webhook = "webhook"


class ModelConfig(BaseModel):
    provider: ModelProvider = ModelProvider.none
    model: str = ""
    temperature: float = Field(default=0.3, ge=0.0, le=2.0)
    max_tokens: int = Field(default=4096, gt=0)
    system_prompt: str = ""
    model_config = ConfigDict(use_enum_values=True)


class ParameterDef(BaseModel):
    type: str = "string"
    description: str = ""
    required: bool = True
    default: Any = None
    enum: list[str] | None = None


class ReturnDef(BaseModel):
    type: str = "string"
    description: str = ""
    items: dict[str, str] | None = None


class ConsumedTool(BaseModel):
    uri: str = Field(..., description="MCP server URI")
    tools: list[str] = Field(default_factory=list)


class ExposedTool(BaseModel):
    name: str = Field(..., min_length=1, max_length=64)
    description: str = ""
    parameters: dict[str, ParameterDef] = Field(default_factory=dict)
    returns: ReturnDef = Field(default_factory=ReturnDef)

    @field_validator("name")
    @classmethod
    def validate_tool_name(cls, v: str) -> str:
        if not v.replace("_", "").replace("-", "").isalnum():
            raise ValueError(f"Tool name must be alphanumeric with _ or -: {v!r}")
        return v


class HttpEndpoint(BaseModel):
    tool_name: str = Field(..., description="Which exposed tool this endpoint backs")
    method: Literal["GET", "POST", "PUT", "DELETE", "PATCH"] = "GET"
    url: str = Field(..., description="Full URL template")
    headers: dict[str, str] = Field(default_factory=dict)
    body_template: dict[str, Any] | None = None
    query_params: dict[str, str] = Field(default_factory=dict)
    response_path: str | None = None


class TriggerConfig(BaseModel):
    type: TriggerType
    schedule: str | None = None
    webhook_path: str | None = None
    model_config = ConfigDict(use_enum_values=True)


class RuntimeConfig(BaseModel):
    sandbox: SandboxType = SandboxType.none
    trust_tier: TrustTier = TrustTier.worker
    max_execution_time: str = "30s"
    env: dict[str, str] = Field(default_factory=dict)
    model_config = ConfigDict(use_enum_values=True)


class AgentSpec(BaseModel):
    name: str = Field(..., min_length=1, max_length=64)
    version: str = "1.0.0"
    description: str = ""
    model: ModelConfig = Field(default_factory=ModelConfig)
    consumes: list[ConsumedTool] = Field(default_factory=list)
    exposes: list[ExposedTool] = Field(default_factory=list)
    http_bridge: list[HttpEndpoint] = Field(default_factory=list)
    runtime: RuntimeConfig = Field(default_factory=RuntimeConfig)
    triggers: list[TriggerConfig] = Field(default_factory=list)

    @field_validator("name")
    @classmethod
    def validate_agent_name(cls, v: str) -> str:
        if not v.replace("_", "").replace("-", "").isalnum():
            raise ValueError(f"Agent name must be alphanumeric with _ or -: {v!r}")
        return v


class AgentConfig(BaseModel):
    agent: AgentSpec
