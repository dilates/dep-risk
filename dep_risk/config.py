from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        tomllib = None  # type: ignore[assignment]


DEFAULT_WEIGHTS: dict[str, float] = {
    "maintainer": 0.25,
    "activity": 0.15,
    "install_script": 0.30,
    "typosquat": 0.20,
    "version": 0.10,
    "github": 0.10,
    "entropy": 0.05,
}


@dataclass
class Config:
    exclude: list[str] = field(default_factory=list)
    min_risk: str = "low"
    include_dev: bool = False
    fail_on: str = "high"
    github_token: str = ""
    workers: int = 10
    weights: dict[str, float] = field(default_factory=lambda: dict(DEFAULT_WEIGHTS))
    no_cache: bool = False

    def __post_init__(self) -> None:
        if not self.github_token:
            self.github_token = os.environ.get("GITHUB_TOKEN", "")
        total = sum(self.weights.values())
        if abs(total - 1.0) > 0.01:
            factor = 1.0 / total if total > 0 else 1.0
            self.weights = {k: v * factor for k, v in self.weights.items()}


def load_config(path: Optional[Path] = None) -> Config:
    if path is None:
        candidates = [
            Path(".dep-risk.toml"),
            Path.home() / ".dep-risk.toml",
        ]
        for candidate in candidates:
            if candidate.exists():
                path = candidate
                break

    if path is None or not path.exists():
        return Config()

    if tomllib is None:
        return Config()

    try:
        with open(path, "rb") as f:
            raw = tomllib.load(f)
    except Exception:
        return Config()

    section = raw.get("dep-risk", {})
    weights_raw = section.get("weights", {})
    weights = {**DEFAULT_WEIGHTS, **weights_raw}

    return Config(
        exclude=section.get("exclude", []),
        min_risk=section.get("min_risk", "low"),
        include_dev=section.get("include_dev", False),
        fail_on=section.get("fail_on", "high"),
        github_token=section.get("github_token", ""),
        workers=section.get("workers", 10),
        weights=weights,
    )
