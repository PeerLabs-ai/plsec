# Supported Configurations

Tested and supported combinations of operating system, language, harness,
and security tooling.

## Compatibility Matrix

| Operating System | Language | Harness     | Model | Tooling | Bootstrap | plsec CLI |
|------------------|----------|-------------|-------|---------|-----------|-----------|
| macOS            | Python   | Claude Code | Any   | Python  | Yes       | Yes       |
| macOS            | Python   | OpenCode    | Any   | Python  | Yes       | Yes       |
| Linux            | Python   | Claude Code | Any   | Python  | Yes       | Yes       |
| Linux            | Python   | OpenCode    | Any   | Python  | Yes       | Yes       |

**Column definitions:**

- **Operating System** -- Host OS. macOS and Linux (Debian/Ubuntu) are
  tested in CI. Windows is not supported.
- **Language** -- Programming language of the project being secured.
  Determines which scanners and dependency auditors apply.
- **Harness** -- The AI coding assistant. Each harness has its own config
  format (CLAUDE.md, opencode.json), wrapper script, and data adapter.
- **Model** -- The LLM powering the harness. plsec is model-agnostic --
  it wraps the harness, not the model. "Any" means plsec imposes no
  constraint on model selection.
- **Tooling** -- References a tooling profile below. Determines which
  security scanners run for that language.
- **Bootstrap** -- Supported by the zero-dependency bootstrap script
  (`build/bootstrap.sh`). Provides agent configs, wrapper scripts, shell
  aliases, and Trivy secret scanning.
- **plsec CLI** -- Supported by the full Python CLI. Provides the
  complete engine pipeline (5 engines), policy evaluation, correlation,
  verdict strategies, integrity monitoring, and proxy management.

## Tooling Profiles

### Python

| Tool           | Engine               | Layer     | Purpose                          | Required |
|----------------|----------------------|-----------|----------------------------------|----------|
| Trivy          | `trivy-secrets`      | STATIC    | Secret scanning in source files  | Yes      |
| Trivy          | `trivy-vuln`         | STATIC    | Dependency vulnerability scanning | No       |
| Bandit         | `bandit`             | STATIC    | Python security analysis (SAST)  | No       |
| Semgrep        | `semgrep`            | STATIC    | Multi-language pattern matching   | No       |
| Trivy          | `trivy-misconfig`    | CONFIG    | Dockerfile/IaC misconfiguration  | No       |
| Podman/Docker  | `container-isolation`| ISOLATION | Container runtime check          | No       |
| Pipelock       | --                   | RUNTIME   | Egress proxy                     | No       |

Only Trivy is required. Other tools are detected automatically and used
when available. Run `plsec doctor` to check which tools are installed.

## Notes

**Bootstrap vs plsec CLI**: Both paths deploy the same agent configs and
wrapper scripts. The key difference is scanning depth. Bootstrap wraps
Trivy for secret scanning only. The plsec CLI runs the full engine
pipeline: 5 scanner engines (Trivy secrets, Trivy dependency, Bandit,
Semgrep, Trivy misconfig) plus the container isolation check, with policy
evaluation,
cross-layer correlation, and preset-aware verdict strategies.

**Presets**: The security preset determines which engines run and how
findings are evaluated. See the README for preset definitions.

| Preset   | Bootstrap modes    | plsec CLI |
|----------|--------------------|-----------|
| minimal  | default            | Yes       |
| balanced | default            | Yes       |
| strict   | `--strict`         | Yes       |
| paranoid | `--strict`         | Yes       |

Bootstrap maps its two modes (default, `--strict`) to the four-level
preset system. The plsec CLI supports all four presets natively.

## Planned

Support for additional configurations is tracked in the
[roadmap](docs/roadmap.md). Key items:

| Configuration          | Roadmap reference                                                     |
|------------------------|-----------------------------------------------------------------------|
| Python dependency audit (pip-audit) | [v0.1.x Milestone 9](docs/roadmap.md#milestone-9-dependency-scanning) |
| Gemini CLI harness     | [v0.2.0 Additional harnesses](docs/roadmap.md#additional-harnesses)   |
| JS/TS language support | [v0.3](docs/roadmap.md#v03---jsts-ecosystem-support)                  |
| Go, Rust, Java/Kotlin  | [Future Considerations](docs/roadmap.md#future-considerations)        |
| Windows                | [Future Considerations](docs/roadmap.md#future-considerations)        |
