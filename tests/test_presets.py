"""Tests for preset system."""

import pytest

from plsec.core.presets import (
    BALANCED_PRESET,
    DEFAULT_PRESET,
    MINIMAL_PRESET,
    PARANOID_PRESET,
    PRESETS,
    STRICT_PRESET,
    LayerPreset,
    Preset,
    ScannerPreset,
    get_preset,
    validate_preset_level,
)

# ---------------------------------------------------------------------------
# Dataclass structure tests
# ---------------------------------------------------------------------------


class TestScannerPreset:
    """Test ScannerPreset dataclass."""

    def test_has_required_fields(self):
        preset = ScannerPreset()
        assert hasattr(preset, "enabled_scanners")
        assert hasattr(preset, "skip_dirs")
        assert hasattr(preset, "skip_files")
        assert hasattr(preset, "severity_threshold")
        assert hasattr(preset, "suppress_rules")
        assert hasattr(preset, "timeout")
        assert hasattr(preset, "skip_when_no_files")

    def test_defaults_are_sensible(self):
        preset = ScannerPreset()
        assert preset.enabled_scanners == []
        assert preset.skip_dirs == []
        assert preset.skip_files == []
        assert preset.severity_threshold == "MEDIUM"
        assert preset.suppress_rules == []
        assert preset.timeout == 300
        assert preset.skip_when_no_files is True

    def test_custom_values(self):
        preset = ScannerPreset(
            enabled_scanners=["trivy-secrets"],
            skip_dirs=[".venv"],
            severity_threshold="HIGH",
            timeout=600,
        )
        assert preset.enabled_scanners == ["trivy-secrets"]
        assert preset.skip_dirs == [".venv"]
        assert preset.severity_threshold == "HIGH"
        assert preset.timeout == 600


class TestLayerPreset:
    """Test LayerPreset dataclass."""

    def test_has_required_fields(self):
        preset = LayerPreset()
        assert hasattr(preset, "runtime_wrappers")
        assert hasattr(preset, "pre_commit_hooks")
        assert hasattr(preset, "container_isolation")
        assert hasattr(preset, "network_proxy")
        assert hasattr(preset, "audit_logging")

    def test_defaults_match_balanced(self):
        preset = LayerPreset()
        assert preset.runtime_wrappers is True
        assert preset.pre_commit_hooks is True
        assert preset.container_isolation is False
        assert preset.network_proxy is False
        assert preset.audit_logging is True

    def test_custom_values(self):
        preset = LayerPreset(
            runtime_wrappers=False,
            container_isolation=True,
            network_proxy=True,
        )
        assert preset.runtime_wrappers is False
        assert preset.container_isolation is True
        assert preset.network_proxy is True


class TestPreset:
    """Test Preset dataclass."""

    def test_has_required_fields(self):
        preset = Preset(
            level="balanced",
            description="Test preset",
            scanner=ScannerPreset(),
            layers=LayerPreset(),
        )
        assert hasattr(preset, "level")
        assert hasattr(preset, "description")
        assert hasattr(preset, "scanner")
        assert hasattr(preset, "layers")

    def test_scanner_is_scanner_preset(self):
        preset = BALANCED_PRESET
        assert isinstance(preset.scanner, ScannerPreset)

    def test_layers_is_layer_preset(self):
        preset = BALANCED_PRESET
        assert isinstance(preset.layers, LayerPreset)


# ---------------------------------------------------------------------------
# Preset registry tests
# ---------------------------------------------------------------------------


class TestPresetRegistry:
    """Test PRESETS registry."""

    def test_contains_all_levels(self):
        assert "minimal" in PRESETS
        assert "balanced" in PRESETS
        assert "strict" in PRESETS
        assert "paranoid" in PRESETS

    def test_all_values_are_preset_objects(self):
        for level, preset in PRESETS.items():
            assert isinstance(preset, Preset)
            assert preset.level == level

    def test_keys_match_preset_levels(self):
        for level in PRESETS:
            assert PRESETS[level].level == level


class TestDefaultPreset:
    """Test default preset selection."""

    def test_default_is_balanced(self):
        assert DEFAULT_PRESET == "balanced"

    def test_default_preset_exists_in_registry(self):
        assert DEFAULT_PRESET in PRESETS


# ---------------------------------------------------------------------------
# Specific preset tests
# ---------------------------------------------------------------------------


class TestMinimalPreset:
    """Test minimal preset configuration."""

    def test_level_is_minimal(self):
        assert MINIMAL_PRESET.level == "minimal"

    def test_has_description(self):
        assert len(MINIMAL_PRESET.description) > 0
        assert "secret" in MINIMAL_PRESET.description.lower()

    def test_enables_only_secret_scanner(self):
        assert MINIMAL_PRESET.scanner.enabled_scanners == ["trivy-secrets"]

    def test_skips_common_build_dirs(self):
        skip_dirs = MINIMAL_PRESET.scanner.skip_dirs
        assert ".venv" in skip_dirs
        assert "node_modules" in skip_dirs
        assert "build" in skip_dirs

    def test_severity_is_high(self):
        assert MINIMAL_PRESET.scanner.severity_threshold == "HIGH"

    def test_disables_hooks_and_isolation(self):
        assert MINIMAL_PRESET.layers.pre_commit_hooks is False
        assert MINIMAL_PRESET.layers.container_isolation is False
        assert MINIMAL_PRESET.layers.network_proxy is False

    def test_disables_audit_logging(self):
        assert MINIMAL_PRESET.layers.audit_logging is False

    def test_enables_runtime_wrappers(self):
        # Even minimal preset should have basic wrapper monitoring
        assert MINIMAL_PRESET.layers.runtime_wrappers is True


class TestBalancedPreset:
    """Test balanced preset configuration."""

    def test_level_is_balanced(self):
        assert BALANCED_PRESET.level == "balanced"

    def test_has_description(self):
        assert len(BALANCED_PRESET.description) > 0

    def test_enables_all_main_scanners(self):
        scanners = BALANCED_PRESET.scanner.enabled_scanners
        assert "trivy-secrets" in scanners
        assert "trivy-misconfig" in scanners
        assert "bandit" in scanners
        assert "semgrep" in scanners

    def test_skips_standard_dirs(self):
        skip_dirs = BALANCED_PRESET.scanner.skip_dirs
        assert ".venv" in skip_dirs
        assert "node_modules" in skip_dirs
        assert "__pycache__" in skip_dirs

    def test_severity_is_medium(self):
        assert BALANCED_PRESET.scanner.severity_threshold == "MEDIUM"

    def test_enables_wrappers_and_hooks(self):
        assert BALANCED_PRESET.layers.runtime_wrappers is True
        assert BALANCED_PRESET.layers.pre_commit_hooks is True
        assert BALANCED_PRESET.layers.audit_logging is True

    def test_disables_isolation_and_proxy(self):
        assert BALANCED_PRESET.layers.container_isolation is False
        assert BALANCED_PRESET.layers.network_proxy is False


class TestStrictPreset:
    """Test strict preset configuration."""

    def test_level_is_strict(self):
        assert STRICT_PRESET.level == "strict"

    def test_has_description(self):
        assert len(STRICT_PRESET.description) > 0
        assert "container" in STRICT_PRESET.description.lower()

    def test_enables_all_scanners(self):
        scanners = STRICT_PRESET.scanner.enabled_scanners
        assert "trivy-secrets" in scanners
        assert "trivy-misconfig" in scanners
        assert "bandit" in scanners
        assert "semgrep" in scanners

    def test_skips_fewer_dirs_than_balanced(self):
        strict_skip = STRICT_PRESET.scanner.skip_dirs
        balanced_skip = BALANCED_PRESET.scanner.skip_dirs
        # Strict should skip fewer directories (scan more aggressively)
        assert len(strict_skip) < len(balanced_skip)

    def test_skips_no_files(self):
        # Strict scans all file types
        assert STRICT_PRESET.scanner.skip_files == []

    def test_severity_is_low(self):
        assert STRICT_PRESET.scanner.severity_threshold == "LOW"

    def test_enables_container_isolation(self):
        assert STRICT_PRESET.layers.container_isolation is True

    def test_disables_network_proxy(self):
        # Strict has isolation but not network proxy
        assert STRICT_PRESET.layers.network_proxy is False

    def test_has_longer_timeout_than_balanced(self):
        assert STRICT_PRESET.scanner.timeout > BALANCED_PRESET.scanner.timeout


class TestParanoidPreset:
    """Test paranoid preset configuration."""

    def test_level_is_paranoid(self):
        assert PARANOID_PRESET.level == "paranoid"

    def test_has_description(self):
        assert len(PARANOID_PRESET.description) > 0
        assert "maximum" in PARANOID_PRESET.description.lower()

    def test_enables_all_scanners(self):
        scanners = PARANOID_PRESET.scanner.enabled_scanners
        assert "trivy-secrets" in scanners
        assert "trivy-misconfig" in scanners
        assert "bandit" in scanners
        assert "semgrep" in scanners

    def test_skips_no_directories(self):
        # Paranoid scans everything, even .venv
        assert PARANOID_PRESET.scanner.skip_dirs == []

    def test_skips_no_files(self):
        assert PARANOID_PRESET.scanner.skip_files == []

    def test_severity_is_low(self):
        assert PARANOID_PRESET.scanner.severity_threshold == "LOW"

    def test_enables_all_layers(self):
        assert PARANOID_PRESET.layers.runtime_wrappers is True
        assert PARANOID_PRESET.layers.pre_commit_hooks is True
        assert PARANOID_PRESET.layers.container_isolation is True
        assert PARANOID_PRESET.layers.network_proxy is True
        assert PARANOID_PRESET.layers.audit_logging is True

    def test_has_longest_timeout(self):
        assert PARANOID_PRESET.scanner.timeout >= STRICT_PRESET.scanner.timeout
        assert PARANOID_PRESET.scanner.timeout >= BALANCED_PRESET.scanner.timeout
        assert PARANOID_PRESET.scanner.timeout >= MINIMAL_PRESET.scanner.timeout

    def test_does_not_skip_when_no_files(self):
        # Paranoid runs all scanners regardless
        assert PARANOID_PRESET.scanner.skip_when_no_files is False


# ---------------------------------------------------------------------------
# Preset comparison tests
# ---------------------------------------------------------------------------


class TestPresetProgression:
    """Test that presets form a logical progression from minimal to paranoid."""

    def test_skip_dirs_decrease_from_minimal_to_paranoid(self):
        minimal = len(MINIMAL_PRESET.scanner.skip_dirs)
        balanced = len(BALANCED_PRESET.scanner.skip_dirs)
        strict = len(STRICT_PRESET.scanner.skip_dirs)
        paranoid = len(PARANOID_PRESET.scanner.skip_dirs)

        assert minimal >= balanced  # Minimal may skip more (fewer scans needed)
        assert balanced > strict
        assert strict > paranoid
        assert paranoid == 0  # Paranoid scans everything

    def test_severity_threshold_progression(self):
        # Map severity to numeric values for comparison
        severity_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}

        minimal_severity = severity_order[MINIMAL_PRESET.scanner.severity_threshold]
        balanced_severity = severity_order[BALANCED_PRESET.scanner.severity_threshold]
        strict_severity = severity_order[STRICT_PRESET.scanner.severity_threshold]
        paranoid_severity = severity_order[PARANOID_PRESET.scanner.severity_threshold]

        # Higher number = higher threshold = fewer findings
        assert minimal_severity >= balanced_severity
        assert balanced_severity >= strict_severity
        assert strict_severity >= paranoid_severity

    def test_layer_enablement_increases(self):
        # Count enabled layers for each preset
        def count_enabled(preset: Preset) -> int:
            layers = preset.layers
            return sum(
                [
                    layers.runtime_wrappers,
                    layers.pre_commit_hooks,
                    layers.container_isolation,
                    layers.network_proxy,
                    layers.audit_logging,
                ]
            )

        minimal_count = count_enabled(MINIMAL_PRESET)
        balanced_count = count_enabled(BALANCED_PRESET)
        strict_count = count_enabled(STRICT_PRESET)
        paranoid_count = count_enabled(PARANOID_PRESET)

        assert minimal_count <= balanced_count
        assert balanced_count <= strict_count
        assert strict_count <= paranoid_count
        assert paranoid_count == 5  # All layers enabled


# ---------------------------------------------------------------------------
# Helper function tests
# ---------------------------------------------------------------------------


class TestGetPreset:
    """Test get_preset() helper function."""

    def test_returns_minimal_when_requested(self):
        preset = get_preset("minimal")
        assert preset == MINIMAL_PRESET

    def test_returns_balanced_when_requested(self):
        preset = get_preset("balanced")
        assert preset == BALANCED_PRESET

    def test_returns_strict_when_requested(self):
        preset = get_preset("strict")
        assert preset == STRICT_PRESET

    def test_returns_paranoid_when_requested(self):
        preset = get_preset("paranoid")
        assert preset == PARANOID_PRESET

    def test_returns_default_when_none(self):
        preset = get_preset(None)
        assert preset == BALANCED_PRESET

    def test_raises_key_error_for_invalid_level(self):
        with pytest.raises(KeyError):
            get_preset("invalid")  # type: ignore[arg-type]


class TestValidatePresetLevel:
    """Test validate_preset_level() helper function."""

    def test_accepts_minimal(self):
        assert validate_preset_level("minimal") == "minimal"

    def test_accepts_balanced(self):
        assert validate_preset_level("balanced") == "balanced"

    def test_accepts_strict(self):
        assert validate_preset_level("strict") == "strict"

    def test_accepts_paranoid(self):
        assert validate_preset_level("paranoid") == "paranoid"

    def test_rejects_invalid_level(self):
        with pytest.raises(ValueError, match="Invalid preset level"):
            validate_preset_level("invalid")

    def test_error_message_lists_valid_levels(self):
        # Error message lists levels alphabetically
        with pytest.raises(ValueError, match="balanced.*minimal.*paranoid.*strict"):
            validate_preset_level("bogus")

    def test_rejects_empty_string(self):
        with pytest.raises(ValueError):
            validate_preset_level("")

    def test_rejects_wrong_case(self):
        with pytest.raises(ValueError):
            validate_preset_level("BALANCED")
