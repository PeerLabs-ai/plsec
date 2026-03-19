# plsec Tool Registry Design

## Status

PROPOSED

## Problem

Tool metadata is fragmented across five independent systems with no shared
source of truth:

| System | Location | What it knows | Used by |
|--------|----------|---------------|---------|
| Tool dataclass | `core/tools.py` | name, command, install_hint (brew-only) | `doctor` command only |
| Engine check_available() | Each `engine/*.py` | tool binary name, install hint (hardcoded) | Scan pipeline |
| Orchestrator KNOWN_TOOLS | `engine/orchestrator.py` | tool binary names (flat tuple) | Environment detection |
| Preset TOML scanners | `configs/presets/*.toml` | scanner IDs per layer | Shell scripts |
| Shell templates | `configs/_template_files/*.bash` | `command -v` checks, install hints | Bootstrap/wrappers |

Consequences:

- **DRY violations**: The same tool is enumerated 3-5 times across the codebase.
  Adding a tool (e.g., pip-audit) requires touching 5+ files.
- **Platform-blind install hints**: `brew install trivy` is shown on Linux
  (issue #6). No OS detection anywhere in the Python hint paths.
- **Dead code**: `Engine.dependencies` is declared in the base class but never
  consumed by the orchestrator or registry.
- **Mutable state**: The `Tool` dataclass is mutated in-place by `ToolChecker`,
  contaminating module-level globals.
- **Disconnected systems**: The `doctor` command and the scan pipeline use
  completely independent availability-checking mechanisms.

## Design Principles

1. **Single source of truth** -- one `ToolSpec` per tool, one `TOOLS` registry.
2. **Immutable metadata** -- `ToolSpec` is a frozen dataclass. Availability is
   checked separately and returned, never mutated in place.
3. **Platform-aware** -- install hints keyed by OS (`darwin`, `linux`, fallback).
4. **Engine binding by ID** -- engines reference `TOOLS` by tool ID, not
   hardcoded strings.
5. **Follow the AGENTS pattern** -- dataclass spec, dict registry, helper
   functions. This pattern is proven by `core/agents.py` and `core/processes.py`.

## ToolSpec

```python
@dataclass(frozen=True)
class ToolSpec:
    """Everything plsec needs to know about an external tool."""

    id: str                                  # "trivy", "bandit", etc.
    display_name: str                        # "Trivy"
    command: str                             # binary name for shutil.which
    install_hints: dict[str, str]            # {"darwin": "brew install trivy",
                                             #  "linux": "sudo apt install trivy"}
    required: bool = False                   # required for plsec to function
    min_version: str | None = None           # semver minimum
    version_flag: str = "--version"          # how to query version
    version_parser: Callable[[str], str | None] | None = None
    url: str | None = None                   # project URL (fallback hint)
```

## TOOLS Registry

```python
TOOLS: dict[str, ToolSpec] = {
    "trivy": ToolSpec(
        id="trivy",
        display_name="Trivy",
        command="trivy",
        install_hints={
            "darwin": "brew install trivy",
            "linux": "sudo apt install trivy",
        },
        required=True,
        min_version="0.50.0",
        version_flag="version",
        url="https://aquasecurity.github.io/trivy/",
    ),
    "bandit": ToolSpec(
        id="bandit",
        display_name="Bandit",
        command="bandit",
        install_hints={
            "darwin": "pip install bandit",
            "linux": "pip install bandit",
        },
    ),
    "semgrep": ToolSpec(
        id="semgrep",
        display_name="Semgrep",
        command="semgrep",
        install_hints={
            "darwin": "pip install semgrep",
            "linux": "pip install semgrep",
        },
    ),
    "detect-secrets": ToolSpec(
        id="detect-secrets",
        display_name="detect-secrets",
        command="detect-secrets",
        install_hints={
            "darwin": "pip install detect-secrets",
            "linux": "pip install detect-secrets",
        },
    ),
    "pip-audit": ToolSpec(
        id="pip-audit",
        display_name="pip-audit",
        command="pip-audit",
        install_hints={
            "darwin": "pip install pip-audit",
            "linux": "pip install pip-audit",
        },
        url="https://github.com/pypa/pip-audit",
    ),
    "podman": ToolSpec(
        id="podman",
        display_name="Podman",
        command="podman",
        install_hints={
            "darwin": "brew install podman",
            "linux": "sudo apt install podman",
        },
    ),
    "docker": ToolSpec(
        id="docker",
        display_name="Docker",
        command="docker",
        install_hints={
            "darwin": "brew install --cask docker",
            "linux": "sudo apt install docker.io",
        },
    ),
    "pipelock": ToolSpec(
        id="pipelock",
        display_name="Pipelock",
        command="pipelock",
        install_hints={
            "darwin": "go install github.com/luckyPipewrench/pipelock/cmd/pipelock@latest",
            "linux": "go install github.com/luckyPipewrench/pipelock/cmd/pipelock@latest",
        },
        url="https://github.com/luckyPipewrench/pipelock",
    ),
}
```

## Helper Functions

```python
def resolve_install_hint(tool_id: str) -> str:
    """Return the install hint for the current platform."""
    spec = TOOLS[tool_id]
    system = platform.system().lower()
    hint = spec.install_hints.get(system)
    if hint:
        return hint
    if spec.url:
        return f"See {spec.url}"
    return f"Install {spec.display_name}"


def check_tool_available(tool_id: str) -> tuple[bool, str | None]:
    """Check if a tool is installed. Returns (available, version_or_none)."""
    spec = TOOLS[tool_id]
    path = shutil.which(spec.command)
    if path is None:
        return False, None
    # version extraction via spec.version_flag + spec.version_parser
    ...
    return True, version


def available_tools() -> frozenset[str]:
    """Return the set of tool IDs that are currently installed."""
    return frozenset(
        tool_id for tool_id in TOOLS
        if shutil.which(TOOLS[tool_id].command) is not None
    )
```

## Integration Points

### Engine base class

Engines declare tool dependencies by ID. The base class provides default
`check_available()` and `_tool_failure()` implementations:

```python
class Engine(abc.ABC):
    @property
    def dependencies(self) -> list[str]:
        """Tool IDs from the TOOLS registry. Default: empty."""
        return []

    def check_available(self, ctx: ScanContext) -> AvailabilityResult:
        """Default: check all dependencies are in available_tools."""
        for tool_id in self.dependencies:
            if tool_id not in ctx.environment.available_tools:
                return AvailabilityResult(
                    status=EngineStatus.UNAVAILABLE,
                    message=f"{tool_id} not found: {resolve_install_hint(tool_id)}",
                )
        return AvailabilityResult(status=EngineStatus.AVAILABLE)
```

Engines only override `check_available()` for non-standard logic (e.g.,
`ContainerIsolationEngine` checks runtime accessibility, not just binary
presence).

### Orchestrator

The `KNOWN_TOOLS` tuple is replaced by the `TOOLS` registry:

```python
# Before
KNOWN_TOOLS = ("trivy", "bandit", "semgrep", ...)
available = frozenset(t for t in KNOWN_TOOLS if shutil.which(t))

# After
from plsec.core.tools import available_tools
available = available_tools()
```

### Doctor command and health checks

`ToolChecker` with mutable `Tool` objects is replaced by `TOOLS` registry
with `check_tool_available()`:

```python
for tool_id, spec in TOOLS.items():
    ok, version = check_tool_available(tool_id)
    if not ok:
        hint = resolve_install_hint(tool_id)
        # render with correct platform-specific hint
```

### Shell template boundary

Bash scripts (`skeleton.bash`, wrapper scripts) maintain their own
`command -v` checks and install hints. This is an acknowledged boundary --
bash cannot import Python registries.

Bootstrap is a quick-start solution. The long-term path is for
`bootstrap.sh` to install the full plsec toolchain to `~/.peerlabs/`,
which then provides the Python-based tool management. See
`DESIGN-BOOTSTRAP-INSTALL-FLOW.md` (planned) for this design.

## Preset and Engine Convergence

### Current state: two parallel systems

The preset TOML files list scanner IDs:

```toml
[layers.static]
scanners = ["trivy-secrets", "bandit", "semgrep"]
```

Meanwhile, each Python engine class hardcodes a `presets` frozenset:

```python
class BanditEngine(Engine):
    @property
    def presets(self) -> frozenset[Preset]:
        return frozenset({Preset.MINIMAL, Preset.BALANCED, ...})
```

These two systems are disconnected. The TOML scanner lists are consumed
by shell scripts. The Python `Engine.presets` is consumed by the engine
pipeline. Neither reads from the other.

### Proposed resolution

**TOML preset files are the source of truth** for which engines run at
each security level.

**Engines are layer-scoped, not preset-scoped.** An engine declares which
layer it operates in (`STATIC`, `CONFIG`, `ISOLATION`, `RUNTIME`, `AUDIT`).
It does not declare which presets include it. The `Engine.presets` frozenset
is removed.

**The TOML schema evolves** to support per-layer engine lists:

```toml
[layers.static]
enabled = true
engines = ["trivy-secrets", "trivy-vuln", "bandit", "semgrep"]
severity_threshold = "MEDIUM"
timeout = 300

[layers.config]
enabled = true
engines = ["trivy-misconfig", "agent-constraint"]

[layers.isolation]
enabled = true
engines = ["container-isolation"]
runtime = "podman"

[layers.runtime]
wrappers = true
hooks = true

[layers.audit]
enabled = true
log_dir = "~/.peerlabs/plsec/logs"
integrity = true
```

**The Planner resolves what runs.** Given:

- A preset (TOML config) declaring desired engines per layer
- A `ToolRegistry` declaring what tools are available
- An `EngineRegistry` declaring what engines exist and which layer each
  belongs to

The Planner produces a `ScanPlan`: run these engines, in this layer order,
with this configuration. Missing tools degrade gracefully -- the plan
records what was skipped and why.

**Users can create custom presets** by composing engines from any layer.
This is defense in depth -- the layers are the organizing principle, and
users stitch together their security posture from available engines.

### Provenance and attestation (future)

Preset configuration files are trust-but-verify. Future work includes:

- Validating preset contents against known build versions
- Checking engine IDs in TOML match registered engines
- Attestation of configuration file integrity

## Migration Plan

### Phase 1-2: ToolRegistry + engine wiring (single implementation issue)

- Create `ToolSpec`, `TOOLS` dict, helper functions in `core/tools.py`
- Wire into engine base class (default `check_available()` and
  `_tool_failure()`)
- Wire into `doctor` command and `health.py`
- Eliminate per-engine hardcoded tool strings and install hints
- Fix issue #6 (Linux install hints)

### Phase 3: Orchestrator integration

- Replace `KNOWN_TOOLS` tuple with `available_tools()` from `TOOLS`
- `_detect_environment()` uses `ToolRegistry`

### Phase 4: Preset convergence

- Update TOML schema to per-layer engine lists
- Remove `Engine.presets` frozenset
- Implement Planner that resolves TOML + engines + tools into `ScanPlan`
- Load preset configuration at runtime

## References

- [DESIGN-PLSEC-ENGINE.md](DESIGN-PLSEC-ENGINE.md) -- Engine architecture
  and Planning Layer evolution
- [DESIGN-BOOTSTRAP-INSTALL-FLOW.md](DESIGN-BOOTSTRAP-INSTALL-FLOW.md) --
  Bootstrap to full toolchain install (planned)
- [Issue #6](https://github.com/PeerLabs-ai/plsec/issues/6) -- Linux
  install hints
- [Issue #11](https://github.com/PeerLabs-ai/plsec/issues/11) -- Tracking
  issue for this design
