"""
plsec.engine.engines.container_isolation — Container isolation check.

This engine is structurally different from detection engines like
TrivySecretEngine. It doesn't scan artifacts for vulnerabilities.
Instead, it checks whether a security *control* is in place.

The finding semantics are:
- "You have this control" → no findings (clean)
- "You lack this control" → finding of category MISSING_CONTROL

This pattern applies to Layers 3 (ISOLATION), 4 (RUNTIME), and
5 (AUDIT) — they verify infrastructure posture rather than
scanning code.
"""

import logging
import subprocess

from plsec.engine.base import Engine
from plsec.engine.types import (
    AvailabilityResult,
    EngineStatus,
    Finding,
    FindingCategory,
    Layer,
    Preset,
    ScanContext,
    Severity,
)

logger = logging.getLogger(__name__)


class ContainerIsolationEngine(Engine):
    """Check whether container isolation is available and configured.

    This engine checks:
    1. Is a container runtime (podman/docker) installed?
    2. Is it running / accessible?
    3. Does the project have a container configuration?

    It does NOT start containers or modify the environment.
    It reports what's present and what's missing.
    """

    @property
    def engine_id(self) -> str:
        return "container-isolation"

    @property
    def layer(self) -> Layer:
        return Layer.ISOLATION

    @property
    def display_name(self) -> str:
        return "Container Isolation Check"

    @property
    def presets(self) -> frozenset[Preset]:
        return frozenset({Preset.STRICT, Preset.PARANOID})

    @property
    def dependencies(self) -> list[str]:
        # Not a hard dependency — the engine runs even without a
        # runtime; it just reports the gap.
        return []

    def check_available(self, ctx: ScanContext) -> AvailabilityResult:
        # This engine is always "available" — it checks for controls,
        # it doesn't require external tools to run.
        return AvailabilityResult(
            status=EngineStatus.AVAILABLE,
            message="Control check engine (no external dependencies)",
        )

    def execute(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        runtime = ctx.environment.container_runtime
        if runtime is None:
            findings.append(
                Finding(
                    engine_id=self.engine_id,
                    layer=self.layer,
                    severity=Severity.HIGH,
                    category=FindingCategory.MISSING_CONTROL,
                    title="No container runtime available",
                    description=(
                        "Neither Podman nor Docker was found. Agent "
                        "commands execute directly on the host without "
                        "filesystem or process isolation."
                    ),
                    remediation="Install Podman (preferred) or Docker: brew install podman",
                )
            )
            return findings

        # Runtime exists — check whether it's accessible
        if not self._runtime_accessible(runtime):
            findings.append(
                Finding(
                    engine_id=self.engine_id,
                    layer=self.layer,
                    severity=Severity.MEDIUM,
                    category=FindingCategory.MISSING_CONTROL,
                    title=f"Container runtime ({runtime}) not responsive",
                    description=(
                        f"{runtime} is installed but not responding. "
                        "The Podman/Docker daemon may not be running."
                    ),
                    remediation=f"Start the {runtime} service and verify with: {runtime} info",
                )
            )

        # Check for project-level container configuration
        container_files = [
            "Dockerfile",
            "Containerfile",
            "compose.yaml",
            "compose.yml",
            "docker-compose.yaml",
            "docker-compose.yml",
        ]
        has_config = any((ctx.target_path / f).exists() for f in container_files)

        if not has_config:
            findings.append(
                Finding(
                    engine_id=self.engine_id,
                    layer=self.layer,
                    severity=Severity.LOW,
                    category=FindingCategory.MISCONFIG,
                    title="No container configuration in project",
                    description=(
                        "A container runtime is available but the project "
                        "has no Dockerfile, Containerfile, or compose file. "
                        "Agent isolation requires a container definition."
                    ),
                    remediation=(
                        "Run plsec init --preset strict to generate container configuration"
                    ),
                )
            )

        return findings

    @staticmethod
    def _runtime_accessible(runtime: str) -> bool:
        """Quick check: can we talk to the container runtime?"""
        try:
            result = subprocess.run(
                [runtime, "info"],
                capture_output=True,
                timeout=10,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, OSError):
            return False
