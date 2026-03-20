"""LOOM VRAM Orchestrator — intelligent GPU memory management.

Manages model loading across Ollama (primary) and llama.cpp (secondary),
tracks VRAM usage, provides intelligent model selection based on
available capacity, and optimizes GPU memory allocation.

Hardware: AMD RX 7900 XTX (24GB VRAM, ROCm/gfx1100)
Models: 7 Ollama + 30 GGUFs on NVMe (124GB library)
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import time
from typing import Any

import httpx

from loom.security.audit import get_audit_logger

logger = logging.getLogger(__name__)

OLLAMA_URL = "http://localhost:11434"
MODEL_MANAGER_URL = "http://localhost:8090"
CONTROL_HUB_URL = "http://localhost:8095"
VRAM_TOTAL_GB = 24.0


async def _fetch(url: str, timeout: float = 10.0) -> dict | list | None:
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                return resp.json()
    except Exception as exc:
        logger.warning("Fetch failed %s: %s", url, exc)
    return None


async def _post(url: str, body: dict, timeout: float = 60.0) -> dict | None:
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(url, json=body)
            return resp.json()
    except Exception as exc:
        logger.warning("POST failed %s: %s", url, exc)
    return None


def _get_gpu_vram() -> dict[str, float]:
    """Get GPU VRAM usage from rocm-smi."""
    try:
        r = subprocess.run(
            ["rocm-smi", "--showmemuse"],
            capture_output=True, text=True, timeout=5,
        )
        # Parse VRAM from rocm-smi output
        used_bytes = 0
        total_bytes = int(VRAM_TOTAL_GB * 1e9)
        for line in r.stdout.split("\n"):
            if "Used" in line and "VRAM" in line:
                nums = re.findall(r"(\d+)", line)
                if nums:
                    used_bytes = int(nums[0])
    except Exception:
        used_bytes = 0
        total_bytes = int(VRAM_TOTAL_GB * 1e9)

    # Fallback: get from rocm-smi --showmeminfo
    try:
        r = subprocess.run(
            ["rocm-smi"],
            capture_output=True, text=True, timeout=5,
        )
        for line in r.stdout.split("\n"):
            if "VRAM" in line and "Used" in line:
                nums = re.findall(r"(\d+)", line)
                if len(nums) >= 1:
                    used_bytes = int(nums[0])
    except Exception:
        pass

    return {
        "total_gb": VRAM_TOTAL_GB,
        "used_gb": round(used_bytes / 1e9, 2),
        "available_gb": round(VRAM_TOTAL_GB - used_bytes / 1e9, 2),
    }


def _get_gpu_stats() -> dict[str, Any]:
    """Get GPU temperature, power, and utilization."""
    stats = {"temp_junction_c": 0, "temp_edge_c": 0, "power_w": 0, "utilization_pct": 0}
    try:
        r = subprocess.run(["rocm-smi"], capture_output=True, text=True, timeout=5)
        for line in r.stdout.split("\n"):
            if "junction" in line.lower() and "(C)" in line:
                nums = re.findall(r"(\d+\.?\d*)", line)
                if nums: stats["temp_junction_c"] = float(nums[-1])
            elif "edge" in line.lower() and "(C)" in line:
                nums = re.findall(r"(\d+\.?\d*)", line)
                if nums: stats["temp_edge_c"] = float(nums[-1])
            elif "Power" in line and "(W)" in line:
                nums = re.findall(r"(\d+\.?\d*)", line)
                if nums: stats["power_w"] = float(nums[-1])
            elif "GPU use" in line:
                nums = re.findall(r"(\d+)", line)
                if nums: stats["utilization_pct"] = int(nums[-1])
    except Exception:
        pass
    return stats


# ── Tool implementations ─────────────────────────────────────────────

async def vram_status() -> str:
    """Comprehensive VRAM and GPU status report."""
    audit = get_audit_logger()
    start = time.monotonic()

    # GPU hardware stats
    gpu = _get_gpu_stats()
    vram = _get_gpu_vram()

    # Ollama loaded models
    ps = await _fetch(f"{OLLAMA_URL}/api/ps")
    running = []
    ollama_vram = 0.0
    if ps and "models" in ps:
        for m in ps["models"]:
            vram_gb = m.get("size_vram", 0) / 1e9
            ollama_vram += vram_gb
            running.append({
                "name": m["name"],
                "vram_gb": round(vram_gb, 1),
                "size_gb": round(m.get("size", 0) / 1e9, 1),
            })

    # llama.cpp status
    llama = await _fetch(f"{CONTROL_HUB_URL}/api/llama/status")
    llama_running = llama.get("running", False) if llama else False

    result = {
        "gpu": {
            "model": "AMD RX 7900 XTX",
            "vram_total_gb": VRAM_TOTAL_GB,
            "vram_used_gb": round(ollama_vram, 1) if running else vram["used_gb"],
            "vram_available_gb": round(VRAM_TOTAL_GB - ollama_vram, 1) if running else vram["available_gb"],
            "temperature_c": gpu["temp_junction_c"],
            "power_w": gpu["power_w"],
            "utilization_pct": gpu["utilization_pct"],
        },
        "loaded_models": running,
        "llama_cpp_running": llama_running,
        "can_load_more": (VRAM_TOTAL_GB - ollama_vram) > 3.0,
    }

    duration = (time.monotonic() - start) * 1000
    audit.log_tool_call("vram-orchestrator", "vram_status", {}, "success", duration_ms=duration)
    return json.dumps(result, indent=2)


async def list_all_models() -> str:
    """List all models across Ollama and GGUF library."""
    audit = get_audit_logger()

    # Ollama models
    tags = await _fetch(f"{OLLAMA_URL}/api/tags")
    ollama_models = []
    if tags and "models" in tags:
        ollama_models = [
            {"name": m["name"], "size_gb": round(m["size"] / 1e9, 1), "source": "ollama"}
            for m in tags["models"]
        ]

    # Currently loaded
    ps = await _fetch(f"{OLLAMA_URL}/api/ps")
    loaded_names = set()
    if ps and "models" in ps:
        loaded_names = {m["name"] for m in ps["models"]}

    for m in ollama_models:
        m["loaded"] = m["name"] in loaded_names

    # GGUF library
    gguf_models = await _fetch(f"{MODEL_MANAGER_URL}/api/models")
    library = []
    if isinstance(gguf_models, list):
        library = [
            {"name": m.get("name", "?"), "size_gb": round(m.get("size", 0) / 1e9, 1),
             "source": "gguf_library", "tier": m.get("id", "?")}
            for m in gguf_models
        ]

    result = {
        "ollama": {"count": len(ollama_models), "models": ollama_models},
        "gguf_library": {"count": len(library), "models": library},
        "loaded": list(loaded_names),
        "vram_total_gb": VRAM_TOTAL_GB,
    }

    audit.log_tool_call("vram-orchestrator", "list_all_models", {}, "success")
    return json.dumps(result, indent=2)


async def smart_load(model_name: str) -> str:
    """Intelligently load a model, evicting others if needed."""
    audit = get_audit_logger()
    start = time.monotonic()

    # Check what's currently loaded
    ps = await _fetch(f"{OLLAMA_URL}/api/ps")
    running = ps.get("models", []) if ps else []
    current_vram = sum(m.get("size_vram", 0) / 1e9 for m in running)

    # Get model size estimate
    tags = await _fetch(f"{OLLAMA_URL}/api/tags")
    model_size = 0.0
    if tags:
        for m in tags.get("models", []):
            if m["name"] == model_name:
                model_size = m["size"] / 1e9
                break

    # Check if already loaded
    loaded_names = {m["name"] for m in running}
    if model_name in loaded_names:
        duration = (time.monotonic() - start) * 1000
        audit.log_tool_call("vram-orchestrator", "smart_load",
                            {"model": model_name}, "success", duration_ms=duration)
        return json.dumps({
            "status": "already_loaded",
            "model": model_name,
            "vram_used_gb": round(current_vram, 1),
        })

    # Check if we need to evict
    available = VRAM_TOTAL_GB - current_vram
    evicted = []

    if model_size > 0 and available < model_size + 1.0:  # 1GB buffer
        # Sort by VRAM usage (evict smallest first to free minimum needed)
        sortable = sorted(running, key=lambda m: m.get("size_vram", 0))
        for m in sortable:
            if available >= model_size + 1.0:
                break
            mname = m["name"]
            freed = m.get("size_vram", 0) / 1e9
            # Unload via Ollama
            await _post(f"{OLLAMA_URL}/api/generate",
                        {"model": mname, "prompt": "", "keep_alive": 0})
            evicted.append({"name": mname, "freed_gb": round(freed, 1)})
            available += freed
            audit.log_agent_lifecycle("vram-orchestrator", "evict",
                                      f"Evicted {mname} ({freed:.1f}GB) for {model_name}")

    # Load the model (warm it up with a tiny prompt)
    load_result = await _post(
        f"{OLLAMA_URL}/api/generate",
        {"model": model_name, "prompt": "hi", "stream": False,
         "options": {"num_predict": 1}},
        timeout=120.0,
    )

    # Check result
    ps_after = await _fetch(f"{OLLAMA_URL}/api/ps")
    new_running = ps_after.get("models", []) if ps_after else []
    new_vram = sum(m.get("size_vram", 0) / 1e9 for m in new_running)

    loaded = model_name in {m["name"] for m in new_running}

    duration = (time.monotonic() - start) * 1000
    result = {
        "status": "loaded" if loaded else "failed",
        "model": model_name,
        "evicted": evicted,
        "vram_used_gb": round(new_vram, 1),
        "vram_available_gb": round(VRAM_TOTAL_GB - new_vram, 1),
        "loaded_models": [m["name"] for m in new_running],
        "duration_ms": round(duration),
    }

    audit.log_tool_call("vram-orchestrator", "smart_load",
                        {"model": model_name}, "success" if loaded else "error",
                        duration_ms=duration)
    return json.dumps(result, indent=2)


async def smart_generate(model_name: str, prompt: str, system: str = "") -> str:
    """Generate text with automatic model management."""
    audit = get_audit_logger()
    start = time.monotonic()

    # Ensure model is loaded
    load_result = json.loads(await smart_load(model_name))
    if load_result["status"] == "failed":
        return json.dumps({"error": f"Failed to load {model_name}", "load_result": load_result})

    # Generate
    body = {"model": model_name, "prompt": prompt, "stream": False}
    if system:
        body["system"] = system

    gen_result = await _post(f"{OLLAMA_URL}/api/generate", body, timeout=120.0)

    if gen_result:
        response = gen_result.get("response", "")
        # Strip thinking tags
        response = re.sub(r"<think>.*?</think>", "", response, flags=re.DOTALL).strip()

        duration = (time.monotonic() - start) * 1000
        result = {
            "response": response,
            "model": model_name,
            "eval_count": gen_result.get("eval_count", 0),
            "eval_duration_ms": gen_result.get("eval_duration", 0) / 1e6,
            "total_duration_ms": round(duration),
            "evicted": load_result.get("evicted", []),
        }
        audit.log_tool_call("vram-orchestrator", "smart_generate",
                            {"model": model_name, "prompt_len": len(prompt)},
                            "success", duration_ms=duration)
        return json.dumps(result, indent=2)

    return json.dumps({"error": "Generation failed"})


async def unload_model(model_name: str) -> str:
    """Unload a model from Ollama to free VRAM."""
    audit = get_audit_logger()

    # Get pre-unload state
    ps = await _fetch(f"{OLLAMA_URL}/api/ps")
    running = ps.get("models", []) if ps else []
    target = None
    for m in running:
        if m["name"] == model_name:
            target = m
            break

    if not target:
        return json.dumps({"status": "not_loaded", "model": model_name})

    freed = target.get("size_vram", 0) / 1e9

    # Unload by setting keep_alive to 0
    await _post(f"{OLLAMA_URL}/api/generate",
                {"model": model_name, "prompt": "", "keep_alive": 0})

    # Wait and verify
    import asyncio
    await asyncio.sleep(1)
    ps_after = await _fetch(f"{OLLAMA_URL}/api/ps")
    still_loaded = model_name in {m["name"] for m in ps_after.get("models", [])} if ps_after else True

    result = {
        "status": "unloaded" if not still_loaded else "still_loaded",
        "model": model_name,
        "freed_gb": round(freed, 1) if not still_loaded else 0,
        "vram_available_gb": round(VRAM_TOTAL_GB - sum(
            m.get("size_vram", 0) / 1e9 for m in ps_after.get("models", [])
        ), 1) if ps_after else "?",
    }

    audit.log_agent_lifecycle("vram-orchestrator", "unload",
                              f"{model_name}: freed {freed:.1f}GB")
    return json.dumps(result, indent=2)


async def model_library() -> str:
    """Browse the full GGUF model library."""
    audit = get_audit_logger()

    models = await _fetch(f"{MODEL_MANAGER_URL}/api/models")
    storage = await _fetch(f"{MODEL_MANAGER_URL}/api/storage")

    result = {
        "models": [],
        "storage": storage if isinstance(storage, list) else [],
        "total_count": 0,
        "total_size_gb": 0,
    }

    if isinstance(models, list):
        result["total_count"] = len(models)
        result["total_size_gb"] = round(sum(m.get("size", 0) for m in models) / 1e9, 1)
        result["models"] = [
            {"name": m.get("name", "?"), "size_gb": round(m.get("size", 0) / 1e9, 1),
             "tier": m.get("id", "?")}
            for m in models
        ]

    audit.log_tool_call("vram-orchestrator", "model_library", {}, "success")
    return json.dumps(result, indent=2)


async def optimize_vram() -> str:
    """Analyze VRAM usage and suggest optimizations using local LLM."""
    audit = get_audit_logger()
    start = time.monotonic()

    # Gather current state
    status = json.loads(await vram_status())
    models = json.loads(await list_all_models())

    # Get recent audit data for usage patterns
    recent = audit.recent(100, event_type="tool_call")
    model_calls = {}
    for e in recent:
        tool = e.get("tool", "")
        if "generate" in tool or "model" in tool.lower():
            agent = e.get("agent", "?")
            model_calls[agent] = model_calls.get(agent, 0) + 1

    # Build analysis prompt
    from loom.generator.llm import LLMClient
    llm = LLMClient(provider="ollama", model="qwen3:14b", temperature=0.2)

    prompt = f"""Analyze this GPU VRAM state and suggest optimizations.
Be concise (under 300 words). Markdown format. No thinking tags.

GPU: AMD RX 7900 XTX, 24GB VRAM
Current state: {json.dumps(status['gpu'])}
Loaded models: {json.dumps(status['loaded_models'])}

Ollama library: {len(models['ollama']['models'])} models
  {json.dumps([m['name'] + f" ({m['size_gb']}GB)" for m in models['ollama']['models']])}

Recent model usage from audit: {json.dumps(model_calls)}

Questions to answer:
1. Are the right models loaded for current usage?
2. Could we fit more useful models in 24GB?
3. Any models that should be unloaded?
4. Recommended model loading strategy for this workload?
"""

    try:
        response = await llm.generate(prompt, system="You are a GPU resource optimization analyst.")
        response = re.sub(r"<think>.*?</think>", "", response, flags=re.DOTALL).strip()
    except Exception as exc:
        response = f"# VRAM Optimization (LLM unavailable)\n\nGPU: {json.dumps(status['gpu'], indent=2)}"

    duration = (time.monotonic() - start) * 1000
    audit.log_tool_call("vram-orchestrator", "optimize_vram", {}, "success", duration_ms=duration)
    return response
