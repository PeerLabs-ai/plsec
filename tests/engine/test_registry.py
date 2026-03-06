"""Tests for plsec.engine.registry — Engine registration and lookup."""

from __future__ import annotations

import pytest

from plsec.engine.base import Engine, EngineGroup
from plsec.engine.registry import EngineRegistry, build_default_registry
from plsec.engine.types import (
    AvailabilityResult,
    EngineStatus,
    Finding,
    Layer,
    Preset,
    ScanContext,
)

# ---------------------------------------------------------------------------
# Helpers — minimal concrete engines for testing
# ---------------------------------------------------------------------------


class _StubEngine(Engine):
    """Configurable stub engine for registry tests."""

    def __init__(
        self,
        engine_id: str,
        layer: Layer,
        display_name: str = "",
        presets: frozenset[Preset] | None = None,
    ):
        self._engine_id = engine_id
        self._layer = layer
        self._display_name = display_name or engine_id
        self._presets = presets

    @property
    def engine_id(self) -> str:
        return self._engine_id

    @property
    def layer(self) -> Layer:
        return self._layer

    @property
    def display_name(self) -> str:
        return self._display_name

    @property
    def presets(self) -> frozenset[Preset]:
        if self._presets is not None:
            return self._presets
        return frozenset(Preset)

    def check_available(self, ctx: ScanContext) -> AvailabilityResult:
        return AvailabilityResult(status=EngineStatus.AVAILABLE)

    def execute(self, ctx: ScanContext) -> list[Finding]:
        return []


# ---------------------------------------------------------------------------
# EngineRegistry construction
# ---------------------------------------------------------------------------


class TestEngineRegistryConstruction:
    def test_empty_registry(self) -> None:
        reg = EngineRegistry()
        assert reg.all_engines() == []

    def test_all_layers_have_groups(self) -> None:
        """Even an empty registry should return an EngineGroup for every layer."""
        reg = EngineRegistry()
        for layer in Layer:
            group = reg.group_for(layer)
            assert isinstance(group, EngineGroup)
            assert group.layer == layer


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


class TestRegistration:
    def test_register_single_engine(self) -> None:
        reg = EngineRegistry()
        engine = _StubEngine("s1", Layer.STATIC)
        reg.register(engine)
        assert reg.all_engines() == [engine]

    def test_register_places_in_correct_group(self) -> None:
        reg = EngineRegistry()
        engine = _StubEngine("s1", Layer.STATIC)
        reg.register(engine)

        group = reg.group_for(Layer.STATIC)
        assert engine in group.engines_for_preset(Preset.BALANCED)

    def test_register_multiple_same_layer(self) -> None:
        reg = EngineRegistry()
        e1 = _StubEngine("s1", Layer.STATIC)
        e2 = _StubEngine("s2", Layer.STATIC)
        reg.register(e1)
        reg.register(e2)

        group = reg.group_for(Layer.STATIC)
        engines = group.engines_for_preset(Preset.BALANCED)
        assert e1 in engines
        assert e2 in engines

    def test_register_multiple_layers(self) -> None:
        reg = EngineRegistry()
        e_static = _StubEngine("s1", Layer.STATIC)
        e_config = _StubEngine("c1", Layer.CONFIG)
        e_iso = _StubEngine("i1", Layer.ISOLATION)
        reg.register(e_static)
        reg.register(e_config)
        reg.register(e_iso)

        assert len(reg.all_engines()) == 3
        assert e_static in reg.group_for(Layer.STATIC).engines_for_preset(Preset.BALANCED)
        assert e_config in reg.group_for(Layer.CONFIG).engines_for_preset(Preset.BALANCED)
        assert e_iso in reg.group_for(Layer.ISOLATION).engines_for_preset(Preset.BALANCED)

    def test_register_duplicate_id_raises(self) -> None:
        reg = EngineRegistry()
        e1 = _StubEngine("same-id", Layer.STATIC)
        e2 = _StubEngine("same-id", Layer.CONFIG)
        reg.register(e1)
        with pytest.raises(ValueError, match="already registered"):
            reg.register(e2)

    def test_register_duplicate_id_same_layer_raises(self) -> None:
        reg = EngineRegistry()
        e1 = _StubEngine("same-id", Layer.STATIC)
        e2 = _StubEngine("same-id", Layer.STATIC)
        reg.register(e1)
        with pytest.raises(ValueError, match="already registered"):
            reg.register(e2)


# ---------------------------------------------------------------------------
# Lookup
# ---------------------------------------------------------------------------


class TestLookup:
    def test_group_for_returns_correct_layer(self) -> None:
        reg = EngineRegistry()
        for layer in Layer:
            assert reg.group_for(layer).layer == layer

    def test_group_for_nonexistent_layer_still_returns_group(self) -> None:
        """group_for should never raise, even with no engines registered."""
        reg = EngineRegistry()
        group = reg.group_for(Layer.AUDIT)
        assert isinstance(group, EngineGroup)
        assert group.engines_for_preset(Preset.BALANCED) == []

    def test_get_engine_by_id(self) -> None:
        reg = EngineRegistry()
        engine = _StubEngine("find-me", Layer.STATIC)
        reg.register(engine)
        assert reg.get(engine.engine_id) is engine

    def test_get_engine_missing_returns_none(self) -> None:
        reg = EngineRegistry()
        assert reg.get("nonexistent") is None

    def test_all_engines_ordering(self) -> None:
        """all_engines should return engines in registration order."""
        reg = EngineRegistry()
        engines = [
            _StubEngine("e1", Layer.STATIC),
            _StubEngine("e2", Layer.CONFIG),
            _StubEngine("e3", Layer.ISOLATION),
        ]
        for e in engines:
            reg.register(e)
        assert reg.all_engines() == engines


# ---------------------------------------------------------------------------
# Iteration
# ---------------------------------------------------------------------------


class TestIteration:
    def test_layers_with_engines(self) -> None:
        reg = EngineRegistry()
        reg.register(_StubEngine("s1", Layer.STATIC))
        reg.register(_StubEngine("c1", Layer.CONFIG))

        active = reg.layers_with_engines()
        assert Layer.STATIC in active
        assert Layer.CONFIG in active
        assert Layer.ISOLATION not in active

    def test_layers_with_engines_empty(self) -> None:
        reg = EngineRegistry()
        assert reg.layers_with_engines() == []

    def test_engine_count(self) -> None:
        reg = EngineRegistry()
        assert len(reg) == 0
        reg.register(_StubEngine("e1", Layer.STATIC))
        assert len(reg) == 1
        reg.register(_StubEngine("e2", Layer.CONFIG))
        assert len(reg) == 2

    def test_contains(self) -> None:
        reg = EngineRegistry()
        reg.register(_StubEngine("e1", Layer.STATIC))
        assert "e1" in reg
        assert "e2" not in reg

    def test_repr(self) -> None:
        reg = EngineRegistry()
        reg.register(_StubEngine("e1", Layer.STATIC))
        reg.register(_StubEngine("e2", Layer.CONFIG))
        r = repr(reg)
        assert "EngineRegistry" in r
        assert "2" in r


# ---------------------------------------------------------------------------
# Default registry factory
# ---------------------------------------------------------------------------


class TestBuildDefaultRegistry:
    def test_returns_registry(self) -> None:
        reg = build_default_registry()
        assert isinstance(reg, EngineRegistry)

    def test_has_engines(self) -> None:
        """Default registry should have at least one engine registered."""
        reg = build_default_registry()
        assert len(reg) > 0

    def test_has_trivy_secrets(self) -> None:
        """TrivySecretEngine should be in the default registry."""
        reg = build_default_registry()
        assert "trivy-secrets" in reg

    def test_has_container_isolation(self) -> None:
        """ContainerIsolationEngine should be in the default registry."""
        reg = build_default_registry()
        assert "container-isolation" in reg

    def test_static_layer_has_engines(self) -> None:
        reg = build_default_registry()
        group = reg.group_for(Layer.STATIC)
        assert len(group.engines_for_preset(Preset.BALANCED)) > 0

    def test_isolation_layer_has_engines_for_strict(self) -> None:
        """ContainerIsolationEngine is only enabled for strict/paranoid."""
        reg = build_default_registry()
        group = reg.group_for(Layer.ISOLATION)
        assert len(group.engines_for_preset(Preset.STRICT)) > 0
