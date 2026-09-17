"""Shared fixtures.

Tests build the system through ``auditglass.build.assemble`` wherever they can, so a
test that passes is testing what the CLI actually runs rather than a parallel wiring
that happens to be more convenient.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from auditglass.config import Config, load_config
from auditglass.models import TimeWindow
from auditglass.policy.guard import PolicyGuard
from auditglass.policy.templates import RenderContext, TemplateRegistry

DEMO = Path(__file__).resolve().parent.parent / "src" / "auditglass" / "_demo"
BASE = datetime(2026, 3, 14, 2, 10, 0, tzinfo=UTC)


@pytest.fixture
def incident_window() -> TimeWindow:
    return TimeWindow(BASE, BASE + timedelta(minutes=20))


@pytest.fixture
def config(tmp_path: Path) -> Config:
    cfg = load_config(DEMO / "config.yaml")
    cfg.audit.run_root = tmp_path / "runs"
    return cfg


@pytest.fixture
def registry(config: Config) -> TemplateRegistry:
    return TemplateRegistry.load(list(config.template_files))


@pytest.fixture
def context(config: Config, incident_window: TimeWindow) -> RenderContext:
    return RenderContext(scope=config.scope_dict(), incident_window=incident_window)


@pytest.fixture
def guard(config: Config, registry: TemplateRegistry, context: RenderContext) -> PolicyGuard:
    return PolicyGuard(config.policy, registry, context)


@pytest.fixture
def alert() -> dict:
    return json.loads((DEMO / "alert.json").read_text(encoding="utf-8"))


@pytest.fixture
def window_params(incident_window: TimeWindow) -> dict:
    return incident_window.to_dict()
