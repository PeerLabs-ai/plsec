# Chore: Test Suite Refactor

**Status:** Proposed. Not started.
**Precursor PR:** `fix/plsec-audit-unblock` (unblocks CI by deleting spurious blocking tests; this chore replaces them with the right shape).

---

## Why

The existing test suite has two structural problems that became visible while
fixing the `plsec-audit.sh` heredoc regression (commit `3d7cd02`):

1. **Performative tests.** Many "tests" are substring-greps against template
   source files (e.g. `grep 'exec "$@"' plsec-audit.sh`). They couple to
   implementation, do not catch real bugs, and create churn during refactors
   without adding coverage.

2. **Categories conflated.** Unit, integration, end-to-end, and regression
   tests live in the same directories and gate merge identically. There is
   no advisory tier. Regression tests built in response to specific bugs
   never get retired even when later property/contract tests would subsume
   them.

The audit-script regression demonstrates both:

- The placeholder bug (`PLSEC_DIR="@@PLSEC_DIR@@"` deployed unsubstituted)
  silently broke audit logging in every Claude session. Every grep-pattern
  test in `tests/bats/unit/test_wrapper_logging.bats` (L190/195/200) and
  `tests/test_templates.py::TestPlsecAuditSh` would have passed because they
  substring-match the source. They never invoke the script.
- The "execution" tests that did invoke the script asserted on weak signals
  (wrapped `echo` reached stdout; marker string appeared somewhere in the
  log file). They pass for the wrong reason — `exec` passes stdout through
  whether logging works or not, and the marker would also appear in the
  `argv=…` diagnostic from the `*)` failure branch.

Green-for-the-wrong-reason is worse than red.

---

## Test categories

Each category has a distinct purpose, location, and blocking semantics.

| Category    | Purpose                                                                                   | Scope                                  | Gate     | Location               |
|-------------|-------------------------------------------------------------------------------------------|----------------------------------------|----------|------------------------|
| Unit        | Verify a function/class contract in isolation                                             | Single function/method                 | Blocking | `tests/unit/`          |
| Integration | Verify subsystem composition (engines + orchestrator, install pipeline minus the CLI)     | Multiple units, fake externals         | Blocking | `tests/integration/`   |
| E2E         | Verify the full system from CLI/bootstrap input to artifacts/exit-code output             | Whole product, real externals          | Blocking | `tests/e2e/`           |
| Regression  | Guard a specific historical bug. References the bug. Retires when subsumed                | Whatever reproduces the bug            | Blocking | `tests/regression/`    |
| Advisory    | Style, pattern preferences, performative checks worth tracking but not gating merge       | Anything                               | Warning  | `tests/advisory/` or a separate harness target |

Mixing categories destroys lifecycle independence. A regression test mixed
into the integration suite never gets retired; a performative check that
gates CI burns merge time on implementation-detail churn.

---

## Performative vs. invariant — criteria for the audit

A test is **performative** if any of the following hold:

- It substring-greps a source file without executing the system. (The
  source can change shape while preserving behavior; the test breaks for
  no benefit. And the source can be broken while passing the grep — the
  test gives false confidence.)
- It asserts on filenames, file existence, or pattern-matched file paths
  unless the filename or path *is* the contract.
- It runs the system but asserts on a weak signal that passes even when
  the underlying behavior is broken (e.g. wrapped command output, log
  file existence without content validation, exit code without
  side-effect verification).
- It tests a "we usually do X" stylistic preference rather than a
  documented contract.

A test is **invariant** if it:

- Exercises the system with realistic inputs (including boundary and
  error cases).
- Asserts on observable outcomes — exit code propagation, side-effect
  correctness, parseable output that round-trips.
- Would fail when the contract is violated, even if implementation
  details change shape.
- Would pass when the implementation is refactored while preserving
  behavior.

---

## Audit deliverable

A single report file (`docs/test-audit-report.md` or similar) with three
sections:

### 1. Per-file categorical assessment

For each test file in `tests/`, one row:

| File | Current category | Should be | Invariant or performative? | Recommended action |
|------|-----------------|-----------|----------------------------|--------------------|

Recommended actions are one of:
`keep` — already invariant, in the right category.
`move-to-X` — invariant, wrong category.
`split` — file mixes categories; needs to be broken up.
`rewrite-as-X` — invariant content exists but the assertions need
  to be replaced with behavior tests.
`move-to-regression` — guards a specific historical bug.
`demote-to-advisory` — useful warning, shouldn't gate merge.
`delete` — performative and not worth replacing.

### 2. Structural recommendations

- Proposed directory layout (and any sub-structure within each category).
- What each category gates in CI.
- Where the advisory tier lives in the harness (new Make target?
  separate CI job that produces warnings without failing? GitHub Actions
  annotation?).
- Convention for regression tests referencing the bug they guard (e.g.
  a docstring header citing commit SHA + dated incident summary).
- Migration plan: which files move first, how to avoid breaking CI
  during the move.

### 3. Worked example

Rewrite `tests/bats/unit/test_wrapper_logging.bats` and
`tests/test_templates.py::TestPlsecAuditSh` in the new shape:

- **Calling-shape coverage.** Invoke the audit wrapper with realistic
  Claude-like payloads (single shell-source blob containing heredocs,
  pipes, `&&`/`||`, quotes, redirects). Assert: command actually ran,
  exit code propagated, exactly one log line appeared per invocation,
  log line is parseable into `{timestamp, pid, cwd, cmd}` and the parsed
  `cmd` round-trips to the input.
- **Contract enforcement at boundaries.** `argc=0` → exit 0, log entry
  has `event=no-command`. `argc>1` → exit 64, stderr has the
  diagnostic, log entry has `error=unexpected-argv`. Driven from the
  documented contract in the script header, not from what string the
  source currently contains.
- **Substitution completeness as a release gate** (`tests/regression/`).
  Post-install scan: any `@@*@@` pattern anywhere in
  `~/.peerlabs/plsec/**/*` → fail. Catches the 2026-06-09 bug and any
  future template variable added without a substitution rule.

---

## Method

- Sequential, single-pass reading of the suite for the per-file
  assessment (consistent judgment matters more than throughput; ~37
  files is small enough not to need parallelism).
- Criteria from the "performative vs. invariant" section above applied
  up front, before any verdicts are recorded. Criteria are codified in
  the report so they can be argued with before the audit acts on them.
- File-level verdicts in the first pass. Test-level classification
  deferred to whichever files get prioritized for rewriting, to avoid
  the audit ballooning before it produces anything actionable.

---

## Scope

- **In scope:** everything under `tests/` (Python and BATS), the
  `make scan` golden-comparison harness if it gates merge, the
  `test-assembler-escaping.sh` script, the bootstrap golden fixtures.
- **Out of scope:** rewriting tests. The audit produces verdicts and a
  migration plan. Rewrites land in follow-up PRs sized one category at
  a time.
- **Out of scope:** changing the test harness (Make targets, CI jobs)
  beyond what's needed to introduce the advisory tier. Larger harness
  changes wait for the migration to settle.

---

## Open questions for the audit

These need to be answered as part of producing the report, not before:

- How should regression tests reference the bug they guard? (Commit
  SHA in a docstring header? Issue link? Dated incident note?)
- Where exactly does the advisory tier run? (`make lint-tests`? A
  separate CI job? Inline as `pytest --warnings-only`?)
- What is the migration path that keeps CI green during the move? (Move
  one category at a time? Symlinks during transition? A
  `tests/_pending/` holding pen?)

---

## Non-goals

- This chore does not introduce new testing frameworks.
- It does not change what plsec does. It changes what we assert about
  what plsec does.
- It does not delete tests wholesale to "get green." Spurious
  blocking tests were already deleted in the precursor PR
  (`fix/plsec-audit-unblock`). The remaining performative-but-passing
  tests are triaged here, not bulk-deleted.
