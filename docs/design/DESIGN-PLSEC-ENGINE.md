# plsec Engine Architecture Design

**Status**: Draft / Interface Design
**Date**: 2026-03-04
**Context**: Evolving plsec from subprocess wrappers to a proper engine
abstraction

## Problem

The v0 plsec prototype wraps external tools (Trivy, Bandit, Semgrep,
detect-secrets) via `subprocess.run()`, returning `tuple[bool, str]`.
This works for a CLI proof-of-concept but has structural limitations:

- No shared intermediate representation between scanners
- No way to compose findings across layers
- No correlation (a secret found statically can’t inform runtime policy)
- No formal policy/rules separation from detection mechanism
- No engine lifecycle management (init, configure, execute, teardown)
- Preset logic lives in CLI layer, not engine layer
- Adding a new scanner requires modifying control flow, not just registering a
  plugin

The 5-layer security model (STATIC, CONFIG, ISOLATION, RUNTIME, AUDIT)
and 4 presets (minimal, balanced, strict, paranoid) are sound. What’s
missing is the engine abstraction underneath.

## Design Principles

1. **Engine as coordination layer, tools as adapters.**
   plsec is not a scanner. It orchestrates scanners. Each external tool
   (Trivy, Bandit, etc.) is an adapter behind a common engine interface.
1. **Policy/mechanism separation.**
   “What to check” (rules, thresholds, patterns) is distinct from
   “how to check” (scanner invocation, parsing, normalization).
   Policy is declarative. Mechanism is imperative.
1. **Findings as typed intermediate representation.**
   All engines produce `Finding` objects. The correlation engine
   and reporting layer consume `Finding` objects. No scanner-specific
   output format leaks past the adapter boundary.
1. **Layer as engine group, not just a label.**
   Each of the 5 layers is an `EngineGroup` containing one or more
   engines. The orchestrator walks layers in order, feeding prior
   findings forward (defense-in-depth: each layer can see what
   earlier layers found).
1. **Presets determine execution mode, not just scan scope.**
   The four presets (minimal → paranoid) control how the agent runs,
   not just what gets scanned. At strict/paranoid, the agent runs
   inside a container automatically. The preset is the single knob
   the user turns; everything else follows from it.
1. **Graceful degradation by default.**
   Missing tools degrade to a skip, not an error. The engine reports
   what it could not check, so the operator knows the gap.

## Architecture Overview

```
plsec.yaml (Policy + Configuration)
     │
     ▼
┌──────────────────────────────────────────────────────┐
│                  Orchestrator                        │
│  Resolves preset → engine plan → walks layers        │
│  Feeds prior findings to downstream layers           │
└──────────┬───────────────────────────────────────────┘
           │
     ┌─────┴─────────────────────────────────┐
     │         Engine Registry               │
     │  Maps engine IDs → Engine instances   │
     │  Handles availability checks          │
     └─────┬─────────────────────────────────┘
           │
     ┌─────┴──────────────────────────────────────────────┐
     │              Layer Pipeline                        │
     │                                                    │
     │  Layer 1: STATIC  (detection)                      │
     │    ├── SecretScanEngine (Trivy secrets)            │
     │    ├── CodeAnalysisEngine (Bandit, Semgrep)        │
     │    └── DependencyEngine (pip-audit, Trivy vuln)    │
     │                                                    │
     │  Layer 2: CONFIG  (detection + validation)         │
     │    ├── MisconfigEngine (Trivy misconfig)           │
     │    ├── AgentConstraintEngine (CLAUDE.md, etc.)     │
     │    └── DenyPatternEngine (file/cmd deny lists)     │
     │                                                    │
     │  Layer 3: ISOLATION  (harness validation)          │
     │    ├── ContainerHarnessEngine (validate harness)   │
     │    └── SandboxEngine (macOS sandbox check)         │
     │                                                    │
     │  Layer 4: RUNTIME  (runtime control validation)    │
     │    ├── EgressProxyEngine (Pipelock)                │
     │    └── DLPEngine (response scanning)               │
     │                                                    │
     │  Layer 5: AUDIT  (audit infrastructure validation) │
     │    ├── AuditLogEngine (structured logging)         │
     │    └── IntegrityEngine (workspace hashing)         │
     └────────────────────────────────────────────────────┘
           │
           ▼
     ┌─────────────────────────────────────────-─────┐
     │           Correlation Engine                  │
     │  Cross-layer finding dedup, severity uplift,  │
     │  pattern detection (e.g., secret + no egress  │
     │  control = critical)                          │
     └──────────────┬───────────────────────────-────┘
                    │
                    ▼
     ┌───────────────────────────────────────────-───┐
     │              Report / Alert                   │
     │  Console table, JSON, SARIF, CI exit codes    │
     └────────────────────────────────────────────-──┘
```

## Key Abstractions

### Finding

The intermediate representation flowing between all engines.

```
Finding:
    id:           str               # Unique, deterministic
    engine_id:    str               # Which engine produced it
    layer:        Layer             # Which security layer
    severity:     Severity          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    category:     FindingCategory   # SECRET / VULNERABILITY / MISCONFIG / POLICY / INTEGRITY
    title:        str               # Human-readable summary
    description:  str               # Detail
    location:     Location | None   # File, line, container, network endpoint
    evidence:     dict              # Engine-specific evidence payload
    remediation:  str | None        # What to do about it
    suppressed:   bool              # Suppressed by policy/baseline
    metadata:     dict              # Arbitrary k/v for correlation
```

### Engine (abstract)

The unit of detection. Each engine:

- Declares what it needs (dependencies, configuration)
- Reports whether it can run (availability check)
- Accepts a scan context and produces findings
- Is stateless across invocations (all state in context)

```
Engine:
    engine_id:     str
    layer:         Layer
    display_name:  str

    configure(config)         # Receive engine-specific config
    check_available() → AvailabilityResult
    execute(context) → list[Finding]
```

### EngineGroup (Layer)

Groups engines belonging to a single security layer.
Handles parallel or sequential execution within the layer.

### Orchestrator

Walks the layer pipeline, manages the scan lifecycle:

1. Load policy (plsec.yaml + preset resolution)
1. Build engine plan (which engines, which order)
1. Check availability (report gaps)
1. Execute layers in order, forwarding findings
1. Run correlation
1. Produce report

### ScanContext

Immutable context passed to every engine:

```
ScanContext:
    target_path:    Path            # What we're scanning
    config:         PlsecConfig     # Resolved configuration
    preset:         Preset          # Active preset
    prior_findings: list[Finding]   # From earlier layers
    environment:    EnvironmentInfo # OS, tools available, etc.
```

### Policy

Declarative rules applied after detection:

```
Policy:
    suppressions:   list[Suppression]     # Baseline, accepted risks
    severity_floor: Severity              # Ignore below this level
    fail_on:        Severity              # Exit 1 if any finding >= this
    correlations:   list[CorrelationRule] # Cross-finding rules
```

### Tool Registry

External tool metadata (binary names, install hints, version requirements)
is managed by a centralized Tool Registry. See
[DESIGN-TOOL-REGISTRY.md](DESIGN-TOOL-REGISTRY.md) for the full design.

Engines declare tool dependencies by ID:

```python
class TrivySecretEngine(Engine):
    @property
    def dependencies(self) -> list[str]:
        return ["trivy"]  # references TOOLS["trivy"]
```

The Engine base class provides default `check_available()` and
`_tool_failure()` implementations that consult the Tool Registry.
Engines only override for non-standard availability logic (e.g.,
`ContainerIsolationEngine` checks runtime accessibility beyond binary
presence).

## Planning Layer

The current orchestrator implicitly constructs a scan plan from the preset
and available engines. As plsec evolves, this becomes explicit.

### Architectural layers

```
Registry Layer (current)
    ToolRegistry    -- what tools are available
    EngineRegistry  -- what engines exist
    AgentRegistry   -- what agents we manage

Planning Layer (next)
    ScanPlan        -- which engines to run, in what order, with what config
    InstallPlan     -- what needs to be installed/configured
    RemediationPlan -- what to do about findings

Optimization Layer (future)
    Heuristics      -- skip redundant scans, parallelize independent engines
    Caching         -- don't re-scan unchanged files
    Prioritization  -- run fast engines first, expensive ones only if needed

Execution Layer (partially exists)
    Orchestrator    -- executes the plan
    Findings        -- universal IR
    Verdict         -- outcome strategies

Feedback Layer (future)
    Logging         -- structured audit trail
    Refinement      -- adjust plans based on results
    Learning        -- adapt heuristics over time
```

### Design principles

- Engines are **layer-scoped**, not preset-scoped. An engine declares
  which security layer it operates in. It does not declare which presets
  include it.
- Presets are **user-configurable compositions** of engines across layers.
  Preset TOML files are the source of truth for engine composition. Users
  can create custom presets.
- The **Planner** resolves what runs: preset config (TOML) + engine
  capabilities (registry) + tool availability (tool registry) = ScanPlan.
- A Plan is a function of what's available (registries) and what's desired
  (presets). The Registry Layer must be solid before Plans can be generated.

### Preset authority

Preset TOML files declare per-layer engine lists:

```toml
[layers.static]
engines = ["trivy-secrets", "trivy-vuln", "bandit", "semgrep"]

[layers.config]
engines = ["trivy-misconfig", "agent-constraint"]

[layers.isolation]
engines = ["container-isolation"]
```

Engine configuration is loaded from TOML at runtime. The Python
`Engine.presets` frozenset (current implementation) will be replaced
by this configuration-driven approach. See DESIGN-TOOL-REGISTRY.md
for the migration plan.

## Preset → Engine Mapping

Engines fall into two categories:

- **Detection engines** (Layers 1-2): Scan artifacts for vulnerabilities,
  secrets, misconfigurations. Produce findings of category SECRET,
  VULNERABILITY, MISCONFIG.
- **Control validation engines** (Layers 3-5): Verify that security
  controls are in place. Produce findings of category MISSING_CONTROL
  when infrastructure is absent. At strict/paranoid, plsec *provides*
  these controls (container harness, egress proxy) and the engines
  validate that they are correctly configured.

| Engine                  | Type       | minimal | balanced | strict | paranoid |
|-------------------------|------------|---------|----------|--------|----------|
| SecretScanEngine        | detection  | x       | x        | x      | x        |
| CodeAnalysisEngine      | detection  |         | x        | x      | x        |
| DependencyEngine        | detection  |         | x        | x      | x        |
| MisconfigEngine         | detection  |         | x        | x      | x        |
| AgentConstraintEngine   | detection  |         | x        | x      | x        |
| DenyPatternEngine       | detection  |         |          | x      | x        |
| ContainerHarnessEngine  | control    |         |          | x      | x        |
| SandboxEngine           | control    |         |          | x      | x        |
| EgressProxyEngine       | control    |         |          | x      | x        |
| DLPEngine               | control    |         |          |        | x        |
| AuditLogEngine          | control    |         | x        | x      | x        |
| IntegrityEngine         | control    |         |          |        | x        |

### Preset → execution mode

The preset determines not just which engines scan, but how the agent
is executed. See the roadmap (v0.2.0) for full details.

| Preset   | Agent execution | Network       | Key difference            |
|----------|-----------------|---------------|---------------------------|
| minimal  | Host            | Unrestricted  | Secrets scan only         |
| balanced | Host            | Unrestricted  | Full static + config scan |
| strict   | Container       | Restricted    | Isolated execution        |
| paranoid | Container       | Egress proxy  | Full control + DLP        |

At strict/paranoid, `plsec run` (and the wrapper scripts that delegate
to it) automatically start the agent inside a container. The container
harness engine then validates that the harness is correctly configured.
The user does not need to opt in to containers -- the preset implies
the execution mode.

## Resolved Design Decisions

1. **Correlation Engine is a separate abstraction.** It has a different
   lifecycle (runs after all layers, consumes the full finding set)
   and a different interface (`correlate(findings)` not `execute(ctx)`).
   Implemented as `CorrelationEngine` with `CorrelationRule` instances.

2. **Engine plugin discovery: explicit registration.** The registry
   uses `build_default_registry()` with explicit `register()` calls.
   Entry points are a future consideration if third-party engines
   are needed.

3. **Tool metadata management: centralized Tool Registry.** Follows the
   AGENTS pattern. One frozen `ToolSpec` per tool, one `TOOLS` dict,
   helper functions for OS-aware install hints and availability checking.
   Engines reference tools by ID. See
   [DESIGN-TOOL-REGISTRY.md](DESIGN-TOOL-REGISTRY.md).

4. **Preset TOML files are the source of truth** for engine composition.
   Engines are layer-scoped, not preset-scoped. The Planner resolves
   TOML config + engine capabilities + tool availability into a ScanPlan.
   See the Planning Layer section above.

5. **Layers 3-5 use the Engine interface with control semantics.**
   They implement `execute(ctx)` but produce MISSING_CONTROL findings
   rather than vulnerability findings. At strict/paranoid, plsec
   provides the infrastructure (container harness, proxy) and these
   engines validate it. At balanced, the engines are either skipped
   (not in preset) or report gaps as informational.

## Open Questions

1. **Async execution within layers?**
   Layer 1 engines (secret scan, code analysis, dependency scan) are
   independent and could run concurrently. Worth the complexity now
   or later?

2. **Finding deduplication strategy.**
   Same secret found by Trivy and detect-secrets. Deduplicate by
   location? By content hash? Engine priority?

3. **ScanPlan representation.**
   What does a ScanPlan object look like? Ordered list of
   (engine, config) pairs? DAG of dependencies? How does it handle
   partial execution (some engines unavailable)?

4. **Container harness design.** Several sub-questions:
   - Agent binary provisioning: baked into image or mounted from host?
   - Container lifecycle: per-session (fresh) or long-lived with exec?
   - Image management: pre-built, built by `plsec init`, pulled from
     registry?
   - File access: bind mount vs volume vs copy for project directory?
   - Network policy: Podman `--network=none` / custom bridge (strict)
     vs Pipelock egress proxy (paranoid)?

## Non-Goals (for this design phase)

- GUI / web interface
- Daemon mode / continuous monitoring
- Remote scanning
- Multi-project orchestration
- Signature authoring tools
