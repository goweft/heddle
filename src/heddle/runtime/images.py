"""Image-digest resolution for sandboxed agents.

Logical image names referenced by sandbox_policy resolve to pinned
`image@sha256:...` references via images.yaml. The registry is the
single artefact under review when an image is refreshed.

ADR-004 §3 (supply-chain hardening).
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass(frozen=True)
class ImageRef:
    logical_name: str
    image: str
    digest: str
    refreshed: str

    @property
    def pinned_reference(self) -> str:
        return f"{self.image}@{self.digest}"


_DEFAULT_REGISTRY = Path(__file__).parent / "images.yaml"


def load_registry(path: Path | None = None) -> dict[str, ImageRef]:
    src = path or _DEFAULT_REGISTRY
    if not src.exists():
        return {}
    data = yaml.safe_load(src.read_text()) or {}
    refs: dict[str, ImageRef] = {}
    for logical_name, entry in data.items():
        refs[logical_name] = ImageRef(
            logical_name=logical_name,
            image=entry["image"],
            digest=entry["digest"],
            refreshed=entry.get("refreshed", ""),
        )
    return refs


def resolve(logical_name: str, registry: dict[str, ImageRef] | None = None) -> str:
    """Resolve a logical image name to a `repo:tag@sha256:...` reference.

    Unknown logical names pass through unchanged so unit tests and
    development can use raw tags without an entry in images.yaml.
    """
    reg = registry if registry is not None else load_registry()
    if logical_name in reg:
        return reg[logical_name].pinned_reference
    return logical_name
