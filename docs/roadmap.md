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

### Milestone 3: Bridge CLI/Bootstrap Gap

Make `plsec init` generate wrapper scripts and shell aliases, matching
bootstrap.sh capabilities. Uses existing `AgentSpec.wrapper_template`
field (exists in the agent registry but is currently unused by any CLI
command).

After this milestone, users can get full plsec functionality from the
CLI alone, without needing to run bootstrap.sh first. Bootstrap remains
available as a quick-start for environments without Python.

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

## v0.2.0 - Managed Agent Execution

`plsec run` command: managed execution of AI coding agents with full
plsec security wrapping. This is the convergence point between bootstrap
and CLI capabilities.

### `plsec run` Command

    plsec run claude [-- <args>]
    plsec run opencode [-- <args>]
    plsec run --container claude [-- <args>]

**What it does:**
1. Pre-flight checks (plsec configured? agent configs deployed?)
2. Environment setup (`CLAUDE_CODE_SHELL_PREFIX`, OTEL exporters)
3. Container mode (optional): Podman/Docker with project mounted,
   network policies, agent running inside isolated environment
4. Execute agent with all plsec security wrappers
5. Post-flight: session summary, scan results, duration

**Container runtime:**
- **Default: Podman** (prominently communicated to user)
- User-configurable via `plsec.yaml`
- Docker and macOS sandbox as fallback options

### MCP Server Harness

`plsec create --mcp-server` generates a sample MCP server project with
plsec security baked in at every level:
- Logging of all tool invocations
- Secret scanning of inputs/outputs
- Permission enforcement matching the project's security preset
- Audit trail compatible with `plsec-status` reporting

This serves as a reference implementation and template for building
secure MCP servers that interoperate with plsec-managed agents.

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
- **Container-based execution**: Full Podman/Docker/macOS sandbox
  integration via `plsec run --container`. Network policies, filesystem
  isolation, resource limits. Prerequisite: Layer 3 (isolation) design.
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
- **Additional language ecosystems**: Go, Rust, Java/Kotlin, Ruby -
  each with their own dependency and security tooling landscape.
- **CI/CD integration**: GitHub Actions, GitLab CI templates for running
  plsec scans in pipelines.
- **Team/org features**: Shared security policies, centralized dashboards,
  compliance reporting.
