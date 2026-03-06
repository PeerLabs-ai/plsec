"""
plsec.engine.orchestrator — Scan lifecycle coordinator.

The orchestrator is the single entry point for running a scan.
It owns the lifecycle:

    1. Build environment info (detect OS, tools, runtime)
    2. Resolve preset → engine plan
    3. Walk layers in order, forwarding findings
    4. Run correlation engine on complete finding set
    5. Apply policy (suppressions, severity floor)
    6. Compute verdict via strategy
    7. Return ScanResult with verdict attached

The orchestrator does not know about specific engines. It works
entirely through the Engine interface and the EngineRegistry.
"""

import logging
import platform
import shutil
from pathlib import Path
from typing import Any

from plsec.engine.base import ScanResult
from plsec.engine.correlation import CorrelationEngine, build_default_correlation_engine
from plsec.engine.policy import Policy
from plsec.engine.registry import EngineRegistry
from plsec.engine.types import (
    EnvironmentInfo,
    Layer,
    Preset,
    ScanContext,
)
from plsec.engine.verdict import (
    VerdictStrategy,
    strategy_for_preset,
)

logger = logging.getLogger(__name__)


# Tools the orchestrator knows how to look for
KNOWN_TOOLS = (
    "trivy",
    "bandit",
    "semgrep",
    "detect-secrets",
    "pip-audit",
    "podman",
    "docker",
    "pipelock",
)


class Orchestrator:
    """Coordinates the full scan lifecycle.

    Usage:

        registry = build_default_registry()
        policy = load_policy_from_yaml("plsec.yaml")
        orch = Orchestrator(registry, policy)
        result = orch.scan(Path("."), Preset.BALANCED)
        sys.exit(result.verdict.exit_code)
    """

    def __init__(
        self,
        registry: EngineRegistry,
        policy: Policy | None = None,
        correlation: CorrelationEngine | None = None,
        verdict_strategy: VerdictStrategy | None = None,
    ):
        self._registry = registry
        self._policy = policy or Policy()
        self._correlation = correlation or build_default_correlation_engine()
        self._verdict_strategy = verdict_strategy

    def scan(
        self,
        target: Path,
        preset: Preset,
        engine_configs: dict[str, dict[str, Any]] | None = None,
    ) -> ScanResult:
        """Execute a complete scan.

        Returns a ScanResult with a Verdict attached. The caller
        reads result.verdict for the exit code and rationale — no
        exit logic lives outside the verdict strategy.
        """
        logger.info("Starting scan: target=%s preset=%s", target, preset.value)

        # Resolve verdict strategy: explicit > preset-derived > default
        strategy = self._verdict_strategy or strategy_for_preset(preset.value)

        # 1. Environment detection
        env = self._detect_environment()
        logger.info(
            "Environment: os=%s tools=%s",
            env.os_name,
            sorted(env.available_tools),
        )

        # 2. Build context
        ctx = ScanContext(
            target_path=target.resolve(),
            preset=preset,
            environment=env,
            engine_configs=engine_configs or {},
        )

        # 3. Walk layers
        result = ScanResult()
        for layer in Layer:
            group = self._registry.group_for(layer)
            active_count = len(group.engines_for_preset(preset))

            if active_count == 0:
                logger.debug("Layer %s: no engines for preset %s", layer.name, preset.value)
                continue

            logger.info(
                "Executing layer %s (%d engine(s))",
                layer.name,
                active_count,
            )

            layer_result = group.execute(ctx)
            result.layer_results.append(layer_result)

            # Forward findings to downstream layers
            ctx.prior_findings.extend(layer_result.findings)

            logger.info(
                "Layer %s complete: %d finding(s), %d engine(s) ran, %d skipped",
                layer.name,
                len(layer_result.unsuppressed_findings),
                layer_result.engines_ran,
                layer_result.engines_skipped,
            )

        # 4. Correlation
        all_findings = result.all_findings
        correlation_findings = self._correlation.correlate(all_findings)
        result.correlation_findings = correlation_findings

        if correlation_findings:
            logger.info(
                "Correlation produced %d synthetic finding(s)",
                len(correlation_findings),
            )

        # 5. Policy evaluation
        combined = all_findings + correlation_findings
        result.evaluated_findings = self._policy.evaluate(combined)

        # 6. Verdict
        result.verdict = strategy.evaluate(
            findings=result.evaluated_findings,
            engines_ran=result.engines_ran,
            engines_skipped=result.engines_skipped,
        )

        logger.info(
            "Scan complete: verdict=%s exit_code=%d rationale=%r",
            result.verdict.status,
            result.verdict.exit_code,
            result.verdict.rationale,
        )

        return result

    def _detect_environment(self) -> EnvironmentInfo:
        """Detect OS, Python version, and available tools."""
        available = frozenset(tool for tool in KNOWN_TOOLS if shutil.which(tool))

        container_runtime = None
        container_version = None
        for rt in ("podman", "docker"):
            if rt in available:
                container_runtime = rt
                break

        return EnvironmentInfo(
            os_name=platform.system().lower(),
            os_version=platform.release(),
            python_version=platform.python_version(),
            container_runtime=container_runtime,
            container_runtime_version=container_version,
            available_tools=available,
        )


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def build_orchestrator(
    registry: EngineRegistry,
    policy: Policy | None = None,
    verdict_strategy: VerdictStrategy | None = None,
) -> Orchestrator:
    """Build an orchestrator with default correlation rules.

    This is the intended construction path. The CLI layer calls this
    after loading configuration and building the registry.
    """
    return Orchestrator(
        registry=registry,
        policy=policy,
        correlation=build_default_correlation_engine(),
        verdict_strategy=verdict_strategy,
    )
