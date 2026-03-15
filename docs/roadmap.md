# Roadmap

## Current Release (v0.1.x)

Focus: Fix scan infrastructure, bridge CLI/bootstrap gap, wrapper
logging, `plsec-status` health checks.

See [PROJECT.md](../PROJECT.md) for active TODOs and in-progress work.

### Milestone 1: Fix Scan Infrastructure

Fix blocking bugs that prevent reliable scanning:
- Trivy `trivy-secret.yaml` RE2-incompatible regex (FATAL error on all
  secret scans). The `openai-legacy` rule uses `(?!...)` negative
  lookahead which Go's regexp (RE2) does not support.
- Bandit scanning `.venv/` (all findings are false positives from
  third-party packages). Need `--exclude .venv,...` in command builder.
- Add `make scan` target for dogfooding `plsec scan` on own codebase.

### Milestone 2: Enhanced Wrapper Logging

Upgrade wrapper templates from 3-line session bookends to full audit:
- **Tier 1**: Git branch/commit at session start, session duration,
  security preset, whether agent configs were deployed
- **Tier 2**: `CLAUDE_CODE_SHELL_PREFIX` audit logging for Claude Code.
  Logs every command the LLM executes during a session. This is the
  single most impactful enhancement for audit visibility.
- **Tier 3** (future): OTEL integration for structured telemetry.
  Enable `CLAUDE_CODE_ENABLE_TELEMETRY=1` and configure OTEL exporters
  to write to local files or a lightweight collector.

### Milestone 3: Bridge CLI/Bootstrap Gap (DONE)

`plsec install` now deploys wrapper scripts (`claude-wrapper.sh`,
`opencode-wrapper.sh`, `plsec-audit.sh`) and injects shell aliases
(`claude-safe`, `opencode-safe`, `plsec-logs`) into the shell RC file.
`plsec uninstall` removes the alias block. Health checks I-8/I-9/I-10
verify wrapper scripts are present and executable. `--no-aliases` flag
to opt out of RC file modification.

Users can now get full plsec functionality from the CLI alone, without
needing to run bootstrap.sh first. Bootstrap remains available as a
quick-start for environments without Python.

### Milestone 4: plsec-status Phase 1 (Bash Health Checks)

Design: [plsec-status-design.md](plsec-status-design.md)

Single command, one-shot execution, colored terminal output. Ships inside
`bootstrap.sh` with zero additional dependencies. Answers: "Is plsec
installed, configured, and active in this environment?"

**Health check categories:**
- **Installation** - plsec directory, configs, tool binaries, wrapper scripts
- **Configuration** - security mode, agent type, pre-commit hooks, project configs
- **Activity** - wrapper logs, session counts, last scan (depends on Milestone 2)
- **Findings** - secrets detected, hook blocks

**Output modes:**
- Default: colored terminal with graduated disclosure (quick glance + details)
- `--json`: machine-readable for future TUI and CI integration
- `--quiet`: exit code only (0=OK, 1=WARN, 2=FAIL)

**Deliverables:**
- `templates/bootstrap/plsec-status.sh` template
- Skeleton integration and shell alias
- BATS unit + integration tests

### Milestone 5: Scan Result Persistence

Both `plsec scan` (Python CLI) and `wrapper-scan.sh` (bootstrap) must
write scan results to `~/.peerlabs/plsec/logs/` so that `plsec-status`
can report on findings (F-1, F-2 checks). Options:
- `wrapper-scan.sh`: tee output to `logs/scan-YYYYMMDD.log`
- `plsec scan`: write JSON summary to `logs/scan-latest.json`

### Milestone 6: plsec-status Phase 2 (Watch Mode)

`plsec-status --watch [--interval N]` for continuous refresh. Same check
functions as Phase 1, adds timestamp, delta indicators, and log tail.
Minimal extension over Phase 1.

### Milestone 7: Agent Data Monitoring Foundation

Design: [DESIGN-AGENT-MONITORING.md](DESIGN-AGENT-MONITORING.md)

Enable plsec to read and monitor agent operational data (sessions, tool
calls, token usage, errors, file changes) from local agent data stores.

**Phase 1 -- Foundation:**
- Add `data_dir` field to `AgentSpec` registry
- Create `compatibility.yaml` version compatibility registry
- Implement `core/compatibility.py` -- version checking, cache management
- Add `plsec doctor` checks D-1 through D-4 (adapter health, auth exposure)

**Phase 2 -- Adapters:**
- Define `AgentDataAdapter` protocol
- Implement `OpenCodeAdapter` (SQLite queries)
- Implement `ClaudeCodeAdapter` (JSONL parsing)
- Integrate into `plsec status` activity checks

**Supported agents at launch:**
- OpenCode v1.1.0+ (SQLite + JSON dual-write)
- Claude Code v2.0.0+ (JSONL sessions, stats-cache.json)

Other agents (Gemini CLI, Codex, CoPilot, ollama) will follow as their
data formats are analyzed.

### Milestone 8: `plsec monitor` Command

```
plsec monitor                  # Auto-detect, show all agents
plsec monitor opencode         # OpenCode only
plsec monitor --audit          # Security audit focus (bash commands)
plsec monitor --tokens         # Token usage breakdown
plsec monitor --json           # Machine-readable output
```

Summary view, audit view, token view, error view. Security audit
cross-reference between agent bash command records and plsec wrapper
audit logs (defense-in-depth: two independent command execution data
sources).

### Milestone 9: Dependency Scanning

Add dependency vulnerability scanning to the engine pipeline, starting
with Python (pip-audit). Dependency scanning is language-specific --
each language ecosystem has its own audit tool and output format.

**Python (pip-audit):**
- Implement `PipAuditEngine` in `engine/pip_audit.py`
- pip-audit JSON output is a top-level list (not a dict). Either extend
  `extract_json()` to accept lists or handle parsing internally.
- Key flags: `--format json --progress-spinner off --desc on --aliases on`
- Exit codes: 0 = no vulnerabilities, 1 = vulnerabilities found
- No severity levels in output -- all findings map to a fixed severity
- pip-audit is already in `KNOWN_TOOLS` in `orchestrator.py`

**Design consideration:** DependencyEngine must be language-specific.
A family of engines (PipAuditEngine, CargoAuditEngine, NpmAuditEngine)
rather than a single polymorphic engine. Each has different output
formats, severity models, and invocation patterns. Language detection
via `ProjectDetector` determines which engine(s) to register.

**Future dependency engines** (blocked on language support):
- `cargo audit` for Rust (v0.3+)
- `npm audit` / `yarn audit` / `pnpm audit` for JS/TS (v0.3)
- `govulncheck` for Go (future)

## v0.2.0 - Managed Agent Execution

`plsec run` command: managed execution of AI coding agents with full
plsec security wrapping. This is the convergence point between bootstrap
and CLI capabilities.

### Core principle: preset determines execution mode

The security preset controls *how* the agent runs, not just *what* gets
scanned. At strict/paranoid, the agent runs inside a container
automatically -- container isolation is the default execution mode, not
an opt-in flag.

| Preset   | Execution mode                                      |
|----------|-----------------------------------------------------|
| minimal  | Host execution, wrapper logging only                |
| balanced | Host execution, full audit logging                  |
| strict   | Container execution, network policies, audit        |
| paranoid | Container execution, egress proxy, DLP, full audit  |

This means `claude-safe` and `opencode-safe` at strict/paranoid start
the agent inside a container with the appropriate security policies.
The user doesn't need to know about containers -- the preset handles it.

### `plsec run` Command

    plsec run claude [-- <args>]
    plsec run opencode [-- <args>]
    plsec run --no-container claude [-- <args>]   # override: force host

**What it does:**
1. Pre-flight checks (plsec configured? agent configs deployed?)
2. Resolve preset from `plsec.yaml` / CLI flag / project config
3. If preset requires isolation: build/start container with policies
4. Environment setup (`CLAUDE_CODE_SHELL_PREFIX`, OTEL exporters)
5. Execute agent (inside container or on host, per preset)
6. Post-flight: session summary, scan results, duration

At strict/paranoid, step 3 creates the container with:
- Project directory mounted (read-write by default, configurable)
- Network policy (egress proxy at paranoid, restricted bridge at strict)
- Agent binary/package available inside the container
- plsec configs deployed inside the container
- Audit log volume for persistence across sessions

The `--no-container` flag is an escape hatch for strict/paranoid when
container execution is not possible (CI environments, remote SSH, etc.).
It downgrades execution mode and logs a warning.

**Container runtime:**
- **Default: Podman** (prominently communicated to user)
- User-configurable via `plsec.yaml`
- Docker as fallback
- macOS sandbox as lightweight alternative (no full container)

### Wrapper script evolution

Today `claude-safe` / `opencode-safe` are standalone bash scripts that
wrap agent invocations with logging bookends. The end state:

1. **v0.1.x (now)**: Wrapper scripts do logging, call agent directly
2. **v0.2.0**: Wrapper scripts delegate to `plsec run`, which handles
   preset resolution, container lifecycle, and audit. The wrapper
   becomes a thin shell around `plsec run <agent>`.
3. **Post v0.2.0**: Wrapper scripts may be replaced entirely by
   `plsec run` aliases. The wrappers exist during the transition period
   for backward compatibility.

### Open design questions

These must be resolved during implementation:

1. **Agent binary provisioning**: Does the container image include the
   agent binary, or is it mounted from the host? Baked-in is more
   isolated but harder to keep current. Host-mounted is simpler but
   leaks the host filesystem into the container.
2. **Network policy mechanism**: Pipelock egress proxy (paranoid) vs
   Podman `--network=none` or custom bridge with firewall rules (strict).
   These are different levels of control with different complexity.
3. **Container image management**: Pre-built images? `plsec init` builds
   them? Pulled from a registry? Image-per-agent or shared base?
4. **Session persistence**: Container per-session (fresh each time) or
   long-lived container with exec? Fresh is safer but slower.
5. **File sync**: Bind mount vs volume vs copy. Bind mounts are fast but
   expose the host filesystem structure. Volumes are isolated but need
   explicit sync.

### MCP Server Harness

`plsec create --mcp-server` generates a sample MCP server project with
plsec security baked in at every level:
- Logging of all tool invocations
- Secret scanning of inputs/outputs
- Permission enforcement matching the project's security preset
- Audit trail compatible with `plsec-status` reporting

This serves as a reference implementation and template for building
secure MCP servers that interoperate with plsec-managed agents.

### Additional Harnesses

Extend harness support beyond Claude Code and OpenCode. Each new harness
requires:
- `AgentSpec` registry entry with config filename, templates, and validator
- Wrapper script template (`wrapper-<agent>.sh`)
- Bootstrap integration (agent detection, config generation)
- Compatibility entry in `compatibility.yaml`

**Gemini CLI** is the highest-priority addition. Google's Gemini CLI is
gaining traction as an AI coding assistant and shares the same threat
model as Claude Code and OpenCode (filesystem access, shell execution,
network egress). Requirements:
- Determine config format and location (likely JSON or YAML)
- Analyze Gemini CLI's permission model and map to plsec deny patterns
- Implement `GEMINI_SHELL_PREFIX` equivalent if available (audit logging)
- Add to `plsec run` command for managed execution
- Data adapter for monitoring (data store format TBD)

**Other candidates** (lower priority, tracked in Future Considerations):
Codex (OpenAI), CoPilot (GitHub), ollama-based agents, Cursor.

## v0.3 - JS/TS Ecosystem Support

Extend plsec to cover JavaScript and TypeScript projects. The Node ecosystem
has a significantly different attack surface from Python with multiple
vectors for compromise.

### Vulnerability vectors to address

- **postinstall scripts**: `npm install` / `yarn add` / `pnpm install` can
  execute arbitrary code via package lifecycle scripts
- **Transitive dependencies**: `node_modules/` contains massive dependency
  trees with deep transitive exposure
- **Registry credentials**: `.npmrc` / `.yarnrc` store auth tokens for
  private registries
- **Build tool configs**: webpack, vite, esbuild configs can execute code
  at build time
- **Multiple package managers**: npm, yarn, pnpm, bun - each with different
  lockfile formats and security characteristics
- **Dynamic code execution**: `eval()`, `new Function()`, dynamic `require()`
- **Environment files**: `.env` files are ubiquitous in Node projects (dotenv)

### Work required

- Extend `ProjectDetector` to understand package.json, lockfiles, framework
  detection (React, Next.js, Express, Fastify, etc.)
- Add Node-specific secret patterns to Trivy config templates
- Extend `create` and `secure` command templates for JS/TS projects
- Integrate `npm audit` / `yarn audit` / `pnpm audit` into `plsec scan`
- Add ESLint security plugin integration (eslint-plugin-security)
- Add `.npmrc` / `.yarnrc` as denied file patterns in CLAUDE.md and
  opencode.json templates
- Extend preset system to handle Node-specific layer configuration
- Support multiple package manager detection and lockfile analysis

### Scope considerations

- Node ecosystem moves fast - need to decide which package managers to
  support at launch vs add incrementally
- Framework-specific security patterns (e.g., Next.js server actions,
  Express middleware chains) may warrant sub-presets
- Monorepo support (Turborepo, Nx) adds additional complexity

## v0.4 - TUI Dashboard (plsec-status Phase 3)

Interactive terminal dashboard built on the data contracts established in
Phases 1-2. See [plsec-status-design.md](plsec-status-design.md) Appendix A
for initial sketch.

The `--json` output from `plsec-status` serves as the data contract between
the bash layer and the Python TUI. If structured logs (JSON lines) are
implemented before the TUI, it can stream logs directly rather than parsing
text.

### Proposed capabilities

**Project dashboard:**
- List all projects with plsec configured on the machine
- Show security posture per project (preset, enabled layers, last scan)
- Quick actions (run scan, check integrity, view config)

**Log viewer:**
- Parse and display structured audit logs
- Filter by project, severity, time range
- Highlight security events (blocked operations, secret detections)

**Container status:**
- Show Docker / Podman container status for isolated projects
- Display container health, resource usage, network policy
- Start / stop / restart isolation containers
- View container logs alongside plsec audit logs

**Proxy monitoring:**
- Pipelock proxy status across deployments
- Live egress traffic view (allowed / blocked / flagged)
- DLP alert stream

### Technology

- Build with [Textual](https://textual.textualize.io/) for the TUI framework
- Use textual.pilot for testing (per AGENTS.md guidelines)
- Structured log format must be defined and stabilized before this work begins
  (depends on audit layer maturity)
- Community contribution target: good candidate for community ownership once
  Phase 1-2 data contracts are stable

### Prerequisites

- `plsec-status` Phases 1-2 complete with stable `--json` schema
- Audit logging layer (Layer 5) stable with defined log schema
- Container isolation layer (Layer 3) must support status queries
- Pipelock proxy integration must expose status/metrics

## Future Considerations

- **Security posture review**: Revisit plsec's own security posture as the
  tool matures. plsec is a security tool -- it should be held to a higher
  standard than the projects it protects. Areas to evaluate:
  - **Systems language rewrite**: Evaluate rewriting core scanning and
    orchestration in Rust. Python is productive for rapid development but
    a security tool benefits from memory safety guarantees, absence of
    runtime injection vectors, and static binary distribution (no
    virtualenv, no pip, no supply chain exposure through PyPI). Rust's
    type system and ownership model make entire classes of bugs
    impossible. The engine architecture (Engine trait, Finding struct,
    Orchestrator) maps cleanly to Rust idioms.
  - **Dependency minimisation**: Audit and reduce the Python dependency
    tree. Every transitive dependency is attack surface. Evaluate which
    dependencies can be replaced with stdlib or vendored code.
  - **Binary distribution**: Ship plsec as a single static binary rather
    than a pip-installed Python package. Eliminates virtualenv management,
    pip supply chain risk, and Python version compatibility issues.
  - **Input validation hardening**: Systematic review of all external
    input boundaries (YAML config parsing, JSON tool output, filesystem
    paths, CLI arguments) for injection, path traversal, and resource
    exhaustion vulnerabilities.
  - See `docs/secure-tool-handling.md` for current defensive patterns.
- **Agent monitoring for additional agents**: Extend agent data adapters
  to Gemini CLI, Codex (OpenAI), CoPilot (GitHub), ollama, and other
  agents as they mature. Requires data source analysis for each agent's
  local storage format. Harness support (configs, wrappers) is a
  prerequisite -- see [Additional Harnesses](#additional-harnesses) in
  v0.2.0. Community contributions welcome -- submit PRs adding validated
  versions to `compatibility.yaml`.
  See [DESIGN-AGENT-MONITORING.md](DESIGN-AGENT-MONITORING.md).
- **MCP server securing**: Monitor, audit, and enforce security policies
  on third-party MCP servers that agents connect to. Includes permission
  auditing, traffic monitoring, and policy enforcement integrated with
  `plsec.yaml` security presets.
- **ACP support**: Agent Communication Protocol integration for cross-agent
  security coordination. Protocol is still in its infancy -- track
  development and plan integration when the spec stabilizes.
- **Local server security parameters**: Rich set of controls for securing
  local development servers (ports, bindings, TLS, auth). Important for
  MCP servers running locally and for dev server security in general.
- **Signature database**: Ship with modified sqlite/duckdb instance for
  pattern storage, secret signatures, known-bad hashes. Enables offline
  scanning and faster pattern matching.
- **Single metadata source**: Converge bootstrap and CLI wrapper generation
  to use the same registry metadata. Bootstrap templates and Python CLI
  both generated from `AgentSpec`, `ScannerSpec`, etc. Aspiration -- plan
  for it now, implement when CLI subsumes bootstrap functionality.
- **OTEL integration**: Tier 3 telemetry via OpenTelemetry. Structured
  logging for TUI consumption, metrics export, distributed tracing of
  agent sessions.
- **User tool selection**: Allow users to choose between equivalent tools
  (e.g., mypy vs ty, black vs ruff format). Currently plsec ships opinionated
  defaults. See PROJECT.md Outstanding Items.
- **Additional language ecosystems**: Go, Rust, Java/Kotlin, Ruby --
  each with their own dependency and security tooling landscape.
  See [SUPPORTED-CONFIGS.md](../SUPPORTED-CONFIGS.md) for current matrix.
- **Windows support**: The Python CLI runs on Windows (platform detection
  returns `"windows"` in `EnvironmentInfo`) but has zero test coverage and
  no CI. Bootstrap is bash-only and will not work on Windows without WSL.
  Windows support requires: PowerShell wrapper scripts, Windows-native
  paths in config deployment, CI matrix expansion, and WSL detection/bridge.
  Low priority -- most AI coding assistant usage is on macOS and Linux.
- **CI/CD integration**: GitHub Actions, GitLab CI templates for running
  plsec scans in pipelines.
- **Team/org features**: Shared security policies, centralized dashboards,
  compliance reporting.
- **Security disclosure process**: Improve vulnerability disclosure beyond
  email-only. Evaluate GitHub Security Advisories, a bug bounty program,
  and PGP-encrypted reporting. Current process documented in SECURITY.md.
