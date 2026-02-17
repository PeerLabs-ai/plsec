# Roadmap

## Current Release (v0.1.x)

Focus: Python CLI foundation, bootstrap script, core security layers.

See [PROJECT.md](../PROJECT.md) for active TODOs and in-progress work.

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

## v0.3 - TUI Status and Monitoring

Add `plsec status` and/or `plsec monitor` commands providing a terminal UI
for real-time visibility into security posture across projects.

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

### Prerequisites

- Audit logging layer (Layer 5) must be stable with a defined log schema
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
