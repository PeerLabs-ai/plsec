# Writing Custom Engines

This guide explains how to add a new security engine to plsec.
An engine wraps an external tool (or implements detection logic
directly) behind the `Engine` interface so the orchestrator can
run it, collect findings, and compute a verdict.

## The Engine contract

Every engine extends `plsec.engine.base.Engine` and implements
five properties and two methods:

```python
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


class MyEngine(Engine):
    # --- Identity (3 required properties) ---

    @property
    def engine_id(self) -> str:
        """Unique identifier. Convention: tool-name or tool-purpose."""
        return "my-tool"

    @property
    def layer(self) -> Layer:
        """Which security layer this engine belongs to.

        Layers (in execution order):
          Layer.STATIC  (1) - code analysis, secret scanning
          Layer.CONFIG  (2) - misconfiguration detection
          Layer.ISOLATION (3) - container, sandbox checks
          Layer.RUNTIME (4) - network, egress controls
          Layer.AUDIT   (5) - logging, observability
        """
        return Layer.STATIC

    @property
    def display_name(self) -> str:
        """Human-readable name for reports."""
        return "My Security Tool"

    # --- Optional overrides ---

    @property
    def presets(self) -> frozenset[Preset]:
        """Which presets enable this engine.

        Default: all presets. Override to restrict.
        """
        return frozenset({Preset.STRICT, Preset.PARANOID})

    @property
    def dependencies(self) -> list[str]:
        """External tool names required. Used by plsec doctor."""
        return ["my-tool"]

    # --- Behaviour (2 required methods) ---

    def check_available(self, ctx: ScanContext) -> AvailabilityResult:
        """Check if this engine can run.

        Called before execute(). Should be fast -- check tool
        existence, not full functionality.
        """
        if "my-tool" not in ctx.environment.available_tools:
            return AvailabilityResult(
                status=EngineStatus.UNAVAILABLE,
                message="my-tool not found in PATH",
            )
        return AvailabilityResult(status=EngineStatus.AVAILABLE)

    def execute(self, ctx: ScanContext) -> list[Finding]:
        """Run detection and return findings.

        Precondition: check_available() returned AVAILABLE.

        MUST NOT raise exceptions. Tool failures are reported
        as findings with category MISSING_CONTROL.
        """
        ...
```

## The Finding model

Engines produce `Finding` objects -- the universal intermediate
representation. Every finding has:

| Field         | Type              | Required | Description                                  |
|---------------|-------------------|----------|----------------------------------------------|
| `engine_id`   | `str`             | yes      | Must match `self.engine_id`                  |
| `layer`       | `Layer`           | yes      | Must match `self.layer`                      |
| `severity`    | `Severity`        | yes      | INFO, LOW, MEDIUM, HIGH, CRITICAL            |
| `category`    | `FindingCategory` | yes      | What kind of thing was found                 |
| `title`       | `str`             | yes      | Short description                            |
| `description` | `str`             | yes      | Detailed description or matched text         |
| `location`    | `Location`        | no       | File path, line numbers, container, endpoint |
| `evidence`    | `dict`            | no       | Tool-specific metadata                       |
| `remediation` | `str`             | no       | How to fix                                   |

Findings are **frozen dataclasses**. Their `id` is a deterministic
content hash -- the same finding always produces the same ID.

### Finding categories

```
LEAKED_CREDENTIAL  - secrets, API keys, tokens
VULNERABILITY      - known CVEs, dependency vulnerabilities
MISCONFIG          - misconfigured tools, insecure defaults
CODE_ISSUE         - code quality issues with security impact
POLICY_VIOLATION   - violated organizational policy
MISSING_CONTROL    - a security control could not execute
INTEGRITY          - file tampering, unexpected changes
```

### Creating findings

```python
Finding(
    engine_id=self.engine_id,
    layer=self.layer,
    severity=Severity.HIGH,
    category=FindingCategory.CODE_ISSUE,
    title="SQL injection risk",
    description="Unsanitized user input in query",
    location=Location(
        file_path=Path("src/db.py"),
        line_start=42,
        line_end=42,
    ),
    evidence={"rule_id": "B608", "cwe": "CWE-89"},
    remediation="Use parameterized queries.",
)
```

## Error handling

Engines must **never raise exceptions** from `execute()`. When the
underlying tool fails, return a finding of category
`MISSING_CONTROL`:

```python
def execute(self, ctx: ScanContext) -> list[Finding]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return [self._tool_failure("tool timed out")]
    except FileNotFoundError:
        return [self._tool_failure("binary not found")]
    except OSError as e:
        return [self._tool_failure(str(e))]

    # Parse output...

def _tool_failure(self, message: str) -> Finding:
    return Finding(
        engine_id=self.engine_id,
        layer=self.layer,
        severity=Severity.MEDIUM,
        category=FindingCategory.MISSING_CONTROL,
        title=f"{self.display_name} unavailable",
        description=f"{self.display_name} failed: {message}",
        remediation=f"Ensure {self.dependencies[0]} is installed.",
    )
```

The orchestrator and correlation engine use `MISSING_CONTROL`
findings to reason about coverage gaps (e.g., "secret found but
scanner X couldn't run").

## Engine configuration

Engines receive per-engine configuration via `ScanContext`:

```python
def execute(self, ctx: ScanContext) -> list[Finding]:
    config = ctx.config_for(self.engine_id)
    timeout = config.get("timeout", 300)
    extra_args = config.get("extra_args", [])
```

Configuration is passed from `plsec.yaml` under the engine's ID:

```yaml
engines:
  my-tool:
    timeout: 60
    extra_args: ["--strict"]
```

## Registration

Add your engine to `build_default_registry()` in
`src/plsec/engine/registry.py`:

```python
from plsec.engine.my_tool import MyEngine

def build_default_registry() -> EngineRegistry:
    registry = EngineRegistry()
    registry.register(TrivySecretEngine())
    registry.register(BanditEngine())
    registry.register(MyEngine())        # <-- add here
    ...
    return registry
```

The registry enforces unique engine IDs. Registration order does
not matter -- engines are grouped by layer and executed in layer
order.

## Testing

Test engines with mocked subprocess calls:

```python
from unittest.mock import patch
from plsec.engine.my_tool import MyEngine
from plsec.engine.types import (
    EngineStatus, EnvironmentInfo, FindingCategory,
    Layer, Preset, ScanContext, Severity,
)

def _make_ctx(available_tools=frozenset({"my-tool"})):
    return ScanContext(
        target_path=Path("/var/project"),
        preset=Preset.BALANCED,
        environment=EnvironmentInfo(
            os_name="darwin",
            os_version="23.0.0",
            python_version="3.12.0",
            available_tools=available_tools,
        ),
        engine_configs={},
    )


class TestMyEngine:
    def test_engine_id(self):
        assert MyEngine().engine_id == "my-tool"

    def test_available(self):
        result = MyEngine().check_available(_make_ctx())
        assert result.status == EngineStatus.AVAILABLE

    def test_unavailable(self):
        result = MyEngine().check_available(
            _make_ctx(available_tools=frozenset())
        )
        assert result.status == EngineStatus.UNAVAILABLE

    @patch("plsec.engine.my_tool.subprocess.run")
    def test_clean_scan(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        findings = MyEngine().execute(_make_ctx())
        assert findings == []

    @patch("plsec.engine.my_tool.subprocess.run")
    def test_finding_produced(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1,
            stdout='{"results": [{"issue": "bad"}]}',
            stderr=""
        )
        findings = MyEngine().execute(_make_ctx())
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
```

Run tests:

```bash
uv run pytest tests/engine/test_my_tool.py -v
```

## Complete example

See `src/plsec/engine/trivy_secrets.py` for a production example
that demonstrates:

- Subprocess invocation with timeout
- JSON output parsing
- Severity mapping
- Location extraction
- Evidence metadata
- Tool failure handling
- Engine configuration (secret_config, custom timeout)

## Architecture notes

- Engines are **stateless**. All state flows through `ScanContext`.
- The **orchestrator** walks layers in order, forwarding findings
  from earlier layers to later ones via `ctx.prior_findings`.
- **Policy** is applied after detection, not during. Engines
  produce raw findings; the policy evaluator filters/suppresses.
- **Verdict strategies** decide pass/fail. Engines never determine
  exit codes.
- The **correlation engine** produces synthetic findings from
  cross-layer patterns (e.g., secret + no egress = CRITICAL).
  It is not an Engine subclass.
