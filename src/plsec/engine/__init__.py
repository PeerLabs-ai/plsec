"""plsec.engine -- Security engine architecture.

The engine package provides the core abstractions for plsec's
defense-in-depth scanning pipeline:

- **types** -- shared vocabulary (Finding, Layer, Severity, ScanContext)
- **base** -- Engine ABC, EngineGroup, result containers
- **registry** -- central engine registration
- **policy** -- declarative finding filtering (suppressions, severity floor)
- **verdict** -- scan outcome interpretation (pass/warn/fail/error)
- **correlation** -- cross-layer finding correlation
- **orchestrator** -- scan lifecycle coordinator
"""
