# Secure Tool Handling

Guidelines for defensive subprocess output handling in plsec engines.

plsec is a security tool. Every engine wraps an external binary
(trivy, bandit, semgrep, etc.) and parses its output. These binaries
are not under our control. Their output format, exit codes, and
failure modes can change between versions, differ across platforms,
or be manipulated in supply-chain scenarios.

**Principle: never trust tool output. Parse defensively, fail visibly,
degrade gracefully.**


## The Three Output States

When an engine runs a subprocess, the result falls into one of
three states. The engine must distinguish all three -- conflating
any two is a bug.

| State        | Meaning                                     | Engine response               |
|--------------|---------------------------------------------|-------------------------------|
| **Clean**    | Tool ran, found nothing                     | Return `[]` (no findings)     |
| **Degraded** | Tool output is non-standard but recoverable | Extract data, log warning     |
| **Failed**   | Tool crashed or produced unusable output    | Return `tool_failure` finding |

### How to distinguish

```
stdout has parseable JSON?
  YES --> parse it (Clean or Degraded, depending on whether extraction was needed)
  NO  --> check returncode and stderr
            returncode == 0 and no stderr --> Clean (genuine empty scan)
            otherwise                     --> Failed (tool error)
```

**Never treat empty stdout as "clean" without checking returncode.**
A crashed tool with no output is not a clean scan -- it is a gap
in coverage that must be visible in the scan report.


## The `extract_json` Pattern

All engines that parse JSON subprocess output must use the shared
`extract_json()` function from `plsec.engine.base`. This function
implements layered recovery:

1. **Empty check** -- whitespace-only stdout returns `None`
2. **Fast path** -- `json.loads(stdout)` on clean output
3. **Recovery** -- find the first `{` and parse from there
   (handles progress bars, status messages, ANSI prefixes)
4. **Type guard** -- only returns `dict` or `None`, never
   `list`, `str`, or other JSON scalars
5. **Forensic logging** -- on failure, logs the first 200 chars
   of stdout for post-mortem analysis

### Calling pattern

```python
data = extract_json(result.stdout, self.engine_id)
if data is not None:
    return self._parse_results(data)

# No usable output -- determine why
if result.returncode == 0 and not result.stderr.strip():
    return []  # Genuine clean scan

# Tool failure -- include stderr for diagnostics
stderr_hint = result.stderr.strip()[:200] if result.stderr else "no stderr"
return [self._tool_failure(
    f"exited with code {result.returncode}. {stderr_hint}"
)]
```

This pattern makes three guarantees:

1. Recoverable output is never discarded
2. Tool failures are never silent
3. Diagnostic context is always available


## Why This Matters for Security Tools

### False negatives are worse than false positives

A conventional CLI tool that misparses output might show a confusing
error. A security tool that misparses output might report "no findings"
when the scanner actually crashed before completing. The user deploys
with a false sense of security.

### Supply chain considerations

The external tools plsec wraps are themselves attack surfaces. A
compromised scanner binary could:

- Output crafted JSON designed to exploit the parser
- Output nothing (to hide findings)
- Output non-JSON to trigger error paths that skip scanning

Defensive parsing limits the blast radius. The type guard
(only accepting `dict`) prevents injection of unexpected data
structures. The returncode check prevents silent scan gaps.

### Defence in depth

The quiet flags (`-q`, `--quiet`) on tool commands are the first
layer -- they prevent known noise (progress bars, status messages)
from contaminating stdout. The `extract_json` recovery is the
second layer -- it handles cases the quiet flag doesn't cover.
Returncode checking is the third layer -- it catches cases where
neither stdout nor quiet flags tell the full story.

Each layer operates independently. Removing any one layer does not
compromise the others.


## Adding a New Engine

When writing a new engine that wraps a subprocess:

1. Use `--quiet` / `-q` or equivalent flag if the tool supports it
2. Use `extract_json()` for JSON parsing -- do not call `json.loads` directly
3. Check `result.returncode` when `extract_json()` returns `None`
4. Include `result.stderr` context in `_tool_failure` findings
5. Document the tool's exit code semantics in the engine docstring
6. Test with empty stdout, non-JSON stdout, and prefixed JSON stdout

See `docs/writing-engines.md` for the full engine development guide.
