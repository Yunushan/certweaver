from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .errors import ConfigurationError


@dataclass(frozen=True)
class Adapter:
    slug: str
    name: str
    category: str
    maturity: str
    license: str
    targets: tuple[str, ...]
    modes: tuple[str, ...]
    upstream: str
    notes: str


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def registry_path() -> Path:
    return project_root() / "config" / "pki-registry.yml"


def load_registry(path: Path | None = None) -> dict[str, Adapter]:
    source = path or registry_path()
    try:
        raw: dict[str, Any] = yaml.safe_load(source.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigurationError(f"Unable to load adapter registry {source}: {exc}") from exc

    entries = raw.get("adapters") if isinstance(raw, dict) else None
    if not isinstance(entries, list):
        raise ConfigurationError("Adapter registry must contain an 'adapters' list")

    adapters: dict[str, Adapter] = {}
    for item in entries:
        slug = item.get("slug")
        if not slug or slug in adapters:
            raise ConfigurationError(f"Invalid or duplicate adapter slug: {slug!r}")
        adapters[slug] = Adapter(
            slug=slug,
            name=item["name"],
            category=item["category"],
            maturity=item["maturity"],
            license=item["license"],
            targets=tuple(item.get("targets", [])),
            modes=tuple(item.get("modes", [])),
            upstream=item["upstream"],
            notes=item.get("notes", ""),
        )
    return adapters
