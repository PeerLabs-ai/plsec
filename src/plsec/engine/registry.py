"""
plsec.engine.registry — Engine registration and lookup.

The registry is the central catalog of all available engines. It:
- Stores engine instances indexed by engine_id
- Groups engines by Layer (one EngineGroup per layer)
- Provides lookup by ID and by layer
- Enforces unique engine_id across the entire registry

The orchestrator uses the registry to discover which engines exist
and to get the EngineGroup for each layer during the scan walk.
"""

from __future__ import annotations

import logging

from plsec.engine.base import Engine, EngineGroup
from plsec.engine.types import Layer

logger = logging.getLogger(__name__)


class EngineRegistry:
    """Central catalog of all registered engines.

    Usage:

        registry = EngineRegistry()
        registry.register(TrivySecretEngine())
        registry.register(ContainerIsolationEngine())

        group = registry.group_for(Layer.STATIC)
        result = group.execute(ctx)
    """

    def __init__(self) -> None:
        self._engines: dict[str, Engine] = {}
        self._groups: dict[Layer, EngineGroup] = {layer: EngineGroup(layer) for layer in Layer}

    def register(self, engine: Engine) -> None:
        """Register an engine.

        Raises ValueError if an engine with the same engine_id is
        already registered (regardless of layer).
        """
        if engine.engine_id in self._engines:
            raise ValueError(f"Engine {engine.engine_id!r} already registered")
        self._engines[engine.engine_id] = engine
        self._groups[engine.layer].register(engine)
        logger.debug(
            "Registered engine %s in layer %s",
            engine.engine_id,
            engine.layer.name,
        )

    def group_for(self, layer: Layer) -> EngineGroup:
        """Return the EngineGroup for a layer.

        Always returns a group, even if no engines are registered
        for that layer (returns an empty group).
        """
        return self._groups[layer]

    def get(self, engine_id: str) -> Engine | None:
        """Look up an engine by ID. Returns None if not found."""
        return self._engines.get(engine_id)

    def all_engines(self) -> list[Engine]:
        """Return all registered engines in registration order."""
        return list(self._engines.values())

    def layers_with_engines(self) -> list[Layer]:
        """Return layers that have at least one engine registered (any preset)."""
        engines_by_layer: dict[Layer, int] = {}
        for engine in self._engines.values():
            engines_by_layer[engine.layer] = engines_by_layer.get(engine.layer, 0) + 1
        return [layer for layer in Layer if engines_by_layer.get(layer, 0) > 0]

    def __len__(self) -> int:
        return len(self._engines)

    def __contains__(self, engine_id: str) -> bool:
        return engine_id in self._engines

    def __repr__(self) -> str:
        return f"<EngineRegistry engines={len(self._engines)}>"


# ---------------------------------------------------------------------------
# Default registry factory
# ---------------------------------------------------------------------------


def build_default_registry() -> EngineRegistry:
    """Build a registry with all built-in engines.

    This is the standard construction path. The CLI calls this
    to get the full set of plsec engines.
    """
    from plsec.engine.bandit import BanditEngine
    from plsec.engine.container_isolation import ContainerIsolationEngine
    from plsec.engine.semgrep import SemgrepEngine
    from plsec.engine.trivy_misconfig import TrivyMisconfigEngine
    from plsec.engine.trivy_secrets import TrivySecretEngine

    registry = EngineRegistry()
    registry.register(TrivySecretEngine())
    registry.register(BanditEngine())
    registry.register(SemgrepEngine())
    registry.register(TrivyMisconfigEngine())
    registry.register(ContainerIsolationEngine())

    logger.info("Built default registry with %d engine(s)", len(registry))
    return registry
