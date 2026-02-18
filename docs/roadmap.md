# Roadmap

## Current Release (v0.1.x)

Focus: Python CLI foundation, bootstrap script, core security layers,
`plsec-status` health checks.

See [PROJECT.md](../PROJECT.md) for active TODOs and in-progress work.

### plsec-status Phase 1: Bash Health Checks

Design: [plsec-status-design.md](plsec-status-design.md)

Single command, one-shot execution, colored terminal output. Ships inside
`bootstrap.sh` with zero additional dependencies. Answers: "Is plsec
installed, configured, and active in this environment?"

**Health check categories:**
- **Installation** - plsec directory, configs, tool binaries, wrapper scripts
- **Configuration** - security mode, agent type, pre-commit hooks, project configs
- **Activity** - wrapper logs, session counts, last scan
- **Findings** - secrets detected, hook blocks

**Output modes:**
- Default: colored terminal with graduated disclosure (quick glance + details)
- `--json`: machine-readable for future TUI and CI integration
- `--quiet`: exit code only (0=OK, 1=WARN, 2=FAIL)

**Deliverables:**
- `templates/bootstrap/plsec-status.sh` template
- Skeleton integration and shell alias
- BATS unit + integration tests

### plsec-status Phase 2: Watch Mode

`plsec-status --watch [--interval N]` for continuous refresh. Same check
functions as Phase 1, adds timestamp, delta indicators, and log tail.
Minimal extension over Phase 1.

## v0.2 - JS/TS Ecosystem Support

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

## v0.3 - TUI Dashboard (plsec-status Phase 3)

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

- **User tool selection**: Allow users to choose between equivalent tools
  (e.g., mypy vs ty, black vs ruff format). Currently plsec ships opinionated
  defaults. See PROJECT.md Outstanding Items.
- **Additional language ecosystems**: Go, Rust, Java/Kotlin, Ruby -
  each with their own dependency and security tooling landscape.
- **CI/CD integration**: GitHub Actions, GitLab CI templates for running
  plsec scans in pipelines.
- **Team/org features**: Shared security policies, centralized dashboards,
  compliance reporting.
