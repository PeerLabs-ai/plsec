"""
plsec.engine.agent_constraint -- Agent constraint file validation.

This engine validates that AI coding agent configuration files
(CLAUDE.md, opencode.json) are deployed in the project and match the
active security preset.

Like ContainerIsolationEngine, this is a pure-Python validation engine
that does not invoke external tools. It inspects files directly.

Validation layers:
1. Existence -- is the config file present?
2. Structure -- does it have the required sections?
3. Preset mode -- does it match the expected security level?

Finding semantics:
- MISSING_CONTROL: config file does not exist
- POLICY_VIOLATION: config exists but lacks required sections
- MISCONFIG: config exists but doesn't match the preset mode
"""

import json
import logging
from pathlib import Path

from plsec.core.agents import AGENTS, AgentSpec, security_mode
from plsec.engine.base import Engine
from plsec.engine.types import (
    AvailabilityResult,
    EngineStatus,
    Finding,
    FindingCategory,
    Layer,
    Location,
    Preset,
    ScanContext,
    Severity,
)

logger = logging.getLogger(__name__)


class AgentConstraintEngine(Engine):
    """Validate agent constraint files are deployed and match the preset.

    Checks each known agent (claude, opencode) for:
    1. Config file existence
    2. Required structural sections
    3. Preset-appropriate security mode
    """

    @property
    def engine_id(self) -> str:
        return "agent-constraint"

    @property
    def layer(self) -> Layer:
        return Layer.CONFIG

    @property
    def display_name(self) -> str:
        return "Agent Constraint Validator"

    @property
    def presets(self) -> frozenset[Preset]:
        return frozenset({Preset.BALANCED, Preset.STRICT, Preset.PARANOID})

    @property
    def dependencies(self) -> list[str]:
        return []

    def check_available(self, ctx: ScanContext) -> AvailabilityResult:
        return AvailabilityResult(
            status=EngineStatus.AVAILABLE,
            message="Constraint validator (no external dependencies)",
        )

    def execute(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        for spec in AGENTS.values():
            config_path = ctx.target_path / spec.config_filename
            location = Location(file_path=config_path)

            # Layer 1: existence check
            if not config_path.exists():
                findings.append(
                    Finding(
                        engine_id=self.engine_id,
                        layer=self.layer,
                        severity=Severity.HIGH,
                        category=FindingCategory.MISSING_CONTROL,
                        title=f"Missing {spec.config_filename}",
                        description=(
                            f"Agent constraint file {spec.config_filename} "
                            f"not found in project root. {spec.display_name} "
                            f"will run without security constraints."
                        ),
                        location=location,
                        remediation=(f"Run plsec init to generate {spec.config_filename}"),
                    )
                )
                continue

            # Layer 2: structural validation
            structure_ok = self._check_structure(spec, config_path, location, findings)
            if not structure_ok:
                continue

            # Layer 3: preset-mode validation
            self._check_preset_mode(spec, config_path, ctx.preset, location, findings)

        return findings

    def _check_structure(
        self,
        spec: AgentSpec,
        config_path: Path,
        location: Location,
        findings: list[Finding],
    ) -> bool:
        """Validate structural requirements. Returns True if structure is OK."""
        if spec.validate is None:
            return True

        ok, warnings = spec.validate(config_path)

        if not ok:
            findings.append(
                Finding(
                    engine_id=self.engine_id,
                    layer=self.layer,
                    severity=Severity.MEDIUM,
                    category=FindingCategory.POLICY_VIOLATION,
                    title=(f"Invalid {spec.config_filename} structure"),
                    description="; ".join(warnings),
                    location=location,
                    remediation=(f"Run plsec init --force to regenerate {spec.config_filename}"),
                )
            )
            return False

        for warning in warnings:
            findings.append(
                Finding(
                    engine_id=self.engine_id,
                    layer=self.layer,
                    severity=Severity.MEDIUM,
                    category=FindingCategory.POLICY_VIOLATION,
                    title=(f"Incomplete {spec.config_filename} structure"),
                    description=warning,
                    location=location,
                    remediation=(f"Add the missing section to {spec.config_filename}"),
                )
            )

        return len(warnings) == 0

    def _check_preset_mode(
        self,
        spec: AgentSpec,
        config_path: Path,
        preset: Preset,
        location: Location,
        findings: list[Finding],
    ) -> None:
        """Validate the config matches the preset's security mode.

        Strict configs at a balanced preset are acceptable (stricter is
        fine). Balanced configs at a strict/paranoid preset are not.
        """
        mode = security_mode(preset.value)

        # Only flag when the preset demands strict but the config is balanced
        if mode != "strict":
            return

        if spec.config_filename.endswith(".md"):
            self._check_claude_md_mode(spec, config_path, location, findings)
        elif spec.config_filename.endswith(".json"):
            self._check_opencode_json_mode(spec, config_path, location, findings)

    def _check_claude_md_mode(
        self,
        spec: AgentSpec,
        config_path: Path,
        location: Location,
        findings: list[Finding],
    ) -> None:
        """Check CLAUDE.md has strict-mode markers."""
        try:
            content = config_path.read_text()
        except OSError:
            return

        # Strict CLAUDE.md should reference "Strict" in the title
        # and have "Project Boundaries" section
        strict_markers = [
            "Strict Security Configuration",
            "Project Boundaries",
        ]
        missing = [m for m in strict_markers if m not in content]

        if missing:
            findings.append(
                Finding(
                    engine_id=self.engine_id,
                    layer=self.layer,
                    severity=Severity.MEDIUM,
                    category=FindingCategory.MISCONFIG,
                    title=(f"Preset mismatch: {spec.config_filename}"),
                    description=(
                        f"{spec.config_filename} does not match "
                        f"strict security mode. Missing: "
                        f"{', '.join(missing)}"
                    ),
                    location=location,
                    remediation=(
                        f"Run plsec init --preset strict to regenerate {spec.config_filename}"
                    ),
                )
            )

    def _check_opencode_json_mode(
        self,
        spec: AgentSpec,
        config_path: Path,
        location: Location,
        findings: list[Finding],
    ) -> None:
        """Check opencode.json has strict-mode default-deny."""
        try:
            data = json.loads(config_path.read_text())
        except (OSError, json.JSONDecodeError):
            return

        perm = data.get("permission", {})
        default_perm = perm.get("*")

        # Strict mode requires default deny
        if default_perm != "deny":
            findings.append(
                Finding(
                    engine_id=self.engine_id,
                    layer=self.layer,
                    severity=Severity.MEDIUM,
                    category=FindingCategory.MISCONFIG,
                    title=(f"Preset mismatch: {spec.config_filename}"),
                    description=(
                        f"{spec.config_filename} default permission "
                        f'is "{default_perm}", expected "deny" for '
                        f"strict mode"
                    ),
                    location=location,
                    remediation=(
                        f"Run plsec init --preset strict to regenerate {spec.config_filename}"
                    ),
                )
            )
