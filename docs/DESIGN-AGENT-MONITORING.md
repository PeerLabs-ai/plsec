# Design: Agent Data Monitoring and Compatibility Registry

**Status:** PROPOSED
**Version:** 0.1
**Date:** 2026-02-23
**Author:** Graham Toppin / Claude

---

## Problem Statement

AI coding agents store rich operational data locally -- session histories,
tool call audit trails, token usage, file change records, and error logs.
This data is invaluable for security monitoring, cost tracking, and health
assessment. However:

1. **No published data format specifications.** Neither OpenCode nor Claude
   Code document their internal storage formats as stable APIs.
2. **Formats evolve across versions.** OpenCode has had 3 schema migrations
   across v1.1.x-1.2.x. Claude Code's stats-cache has a `"version": 2`
   field implying prior formats.
3. **No existing tooling.** No established ecosystem builds on top of these
   data stores for monitoring or auditing purposes.
4. **Security-relevant data is siloed.** Each agent stores bash command
   execution records independently, but there is no cross-referencing or
   unified audit view.

plsec must consume these data sources for monitoring, auditing, and health
checking -- but must do so defensively, with version-aware adapters and
automated compatibility validation.

## Design Goals

1. **Resilient to format changes** -- per-agent adapters with schema
   validation, not brittle direct access
2. **Version-pinned compatibility** -- explicit registry of tested versions,
   with warnings for untested and failures for incompatible
3. **Community-maintainable** -- compatibility lists published in the repo,
   updatable via PRs as users validate new agent versions
4. **Progressively useful** -- health checks first, then monitoring, then
   full audit trail cross-referencing

## Agent Data Source Inventory

### OpenCode (`~/.local/share/opencode/`)

| Component | Format | Contents |
|-----------|--------|----------|
| `opencode.db` | SQLite 3 (Drizzle ORM) | Sessions, messages, parts, todos, permissions, projects |
| `storage/session_diff/` | JSON per session | Full file diffs (before/after, additions/deletions) |
| `storage/message/` | JSON per message | Message metadata (role, model, agent, timestamps) |
| `storage/part/` | JSON per part | Tool calls, text, patches, token usage, step lifecycle |
| `snapshot/` | Bare git repos | Content-addressable workspace snapshots per step |
| `log/` | Structured text | Service logs with timestamps, durations, errors |
| `tool-output/` | Plain text | Full output of truncated tool calls |
| `auth.json` | JSON | OAuth tokens per provider (security concern) |

**Key tables in `opencode.db`:**

| Table | Records (observed) | Monitoring value |
|-------|-------------------|-----------------|
| `session` | 46 | Session metadata, project tracking, change summaries |
| `message` | 4,328 | API errors, model selection, role tracking |
| `part` | 16,662 | Tool calls (4,670), token usage (3,922 step-finish), patches (1,278) |
| `project` | 3+ | Project registration, worktree paths |
| `todo` | 22 | Task tracking per session |
| `permission` | 0 | Per-project permission rules (future) |

**Part type distribution:**

| Type | Count | Security relevance |
|------|-------|--------------------|
| `tool` | 4,670 | **HIGH** -- every tool call with full input/output (bash commands especially) |
| `step-finish` | 3,922 | Token breakdown (input/output/reasoning/cache), cost tracking |
| `text` | 2,826 | Assistant output |
| `patch` | 1,278 | File modifications with diffs |
| `step-start` | 3,926 | Git snapshot references |
| `reasoning` | 38 | Extended thinking blocks |
| `compaction` | 30 | Context window pressure events |

**Tool usage distribution (all sessions):**

| Tool | Calls | Notes |
|------|-------|-------|
| `read` | 1,499 | File reading |
| `edit` | 1,130 | File editing |
| `bash` | 837 | **Command execution -- primary audit target** |
| `todowrite` | 480 | Task management |
| `grep` | 267 | Code search |
| `write` | 225 | File creation |
| `glob` | 134 | File discovery |
| `task` | 40 | Subagent launches |

### Claude Code (`~/.claude/`)

| Component | Format | Contents |
|-----------|--------|----------|
| `projects/{path-hash}/*.jsonl` | JSONL per session | Complete message history with tool calls, thinking |
| `stats-cache.json` | JSON (versioned) | Aggregated daily metrics: messages, sessions, tools, tokens, cost |
| `debug/*.txt` | Text | Per-session debug logs |
| `history.jsonl` | JSONL | Command history |
| `todos/` | JSON | Task tracking |
| `file-history/` | JSON snapshots | File state tracking per message |
| `shell-snapshots/` | Snapshots | Shell state tracking |

**JSONL message structure:**

Each line is a JSON object with:
- `sessionId`, `version` (Claude Code version), `gitBranch`, `cwd`
- `message.role` ("user" / "assistant")
- `message.content[]` -- array of blocks: `text`, `tool_use`, `tool_result`, `thinking`
- `uuid`, `parentUuid` -- message chain for conversation threading
- `thinkingMetadata` -- extended thinking configuration

**`stats-cache.json` structure:**

```json
{
  "version": 2,
  "dailyActivity": [{ "date": "...", "messageCount": N, "sessionCount": N, "toolCallCount": N }],
  "dailyModelTokens": [{ "date": "...", "tokensByModel": { "model-id": N } }],
  "modelUsage": { "model-id": { "inputTokens": N, "outputTokens": N, "cacheReadInputTokens": N, ... } },
  "totalSessions": N,
  "totalMessages": N,
  "longestSession": { "sessionId": "...", "duration": N, "messageCount": N }
}
```

### Comparison

| Capability | OpenCode | Claude Code |
|-----------|----------|-------------|
| Storage format | SQLite + JSON (dual-write) | JSONL files |
| Tool call audit | SQLite `part` table (`type=tool`) | JSONL `content[].type = "tool_use"` |
| Token tracking | Per-step in `step-finish` parts | Aggregated in `stats-cache.json` |
| File changes | `session_diff/` JSON + git snapshots | `file-history/` snapshots |
| Error logging | Structured logs + message error data | Debug logs |
| Aggregated stats | Must compute from raw data | Pre-computed in `stats-cache.json` |
| Query interface | SQL (easy) | File parsing (JSONL) |
| Version tracking | Stored per session | Stored per message |

### Other Agents (Future)

The following agents are on the plsec roadmap but do not yet have
data source analysis:

| Agent | Data location (expected) | Status |
|-------|-------------------------|--------|
| Gemini CLI | TBD | Roadmap (v0.3+) |
| Codex (OpenAI) | TBD | Roadmap (v0.3+) |
| CoPilot (GitHub) | TBD | Roadmap (v0.3+) |
| ollama (local) | TBD | Roadmap (v0.3+) |

When adding support for new agents, the same adapter + compatibility
registry pattern applies. Community contributions for data source
analysis of additional agents are welcome.

## Architecture

### Core Concept: AgentDataAdapter + Compatibility Registry

```
src/plsec/core/
├── agents.py              # Existing AgentSpec (add data_dir field)
├── adapters/              # NEW: Agent data adapters
│   ├── __init__.py        # AgentDataAdapter protocol, shared types
│   ├── opencode.py        # OpenCode SQLite adapter
│   └── claude.py          # Claude Code JSONL adapter
└── compatibility.py       # NEW: Version compatibility checking
```

### AgentSpec Extension

Add a `data_dir` field to `AgentSpec` pointing to the agent's local
data directory:

```python
@dataclass
class AgentSpec:
    # ... existing fields ...

    # Local data storage directory (e.g., ~/.local/share/opencode/)
    # None if the agent does not store queryable local data
    data_dir: Path | None = None
```

Registry entries:

```python
AGENTS = {
    "claude": AgentSpec(
        # ... existing fields ...
        data_dir=Path.home() / ".claude",
    ),
    "opencode": AgentSpec(
        # ... existing fields ...
        data_dir=Path.home() / ".local" / "share" / "opencode",
    ),
}
```

### AgentDataAdapter Protocol

```python
from dataclasses import dataclass
from typing import Protocol

@dataclass
class SessionSummary:
    """Lightweight session metadata."""
    session_id: str
    title: str
    directory: str
    agent_version: str
    time_created: int          # Unix timestamp ms
    time_updated: int
    message_count: int
    tool_call_count: int
    file_changes: int          # additions + deletions
    total_tokens: int

@dataclass
class ToolCall:
    """A single tool invocation record."""
    tool: str                  # "bash", "read", "edit", etc.
    input_summary: str         # Truncated input (first 200 chars)
    status: str                # "completed", "error"
    timestamp: int

@dataclass
class TokenUsage:
    """Aggregated token usage for a session or time period."""
    input_tokens: int
    output_tokens: int
    cache_read_tokens: int
    cache_write_tokens: int
    reasoning_tokens: int

@dataclass
class ErrorRecord:
    """An error event from the agent."""
    error_type: str            # "APIError", "timeout", etc.
    message: str
    timestamp: int
    is_retryable: bool

@dataclass
class SchemaValidation:
    """Result of validating an agent's data format."""
    agent_id: str
    agent_version: str
    expected_version: str | None
    compatible: bool
    details: list[str]         # Specific findings


class AgentDataAdapter(Protocol):
    """Protocol for reading agent operational data."""

    def detect(self) -> bool:
        """Is this agent's data store present on disk?"""
        ...

    def version(self) -> str | None:
        """Agent version that last wrote to the data store."""
        ...

    def validate_schema(self) -> SchemaValidation:
        """Check whether the data format matches our adapter's expectations."""
        ...

    def sessions(self, project_dir: Path | None = None) -> list[SessionSummary]:
        """List sessions, optionally filtered to a project directory."""
        ...

    def tool_calls(self, session_id: str) -> list[ToolCall]:
        """Get tool call audit trail for a session."""
        ...

    def bash_commands(self, session_id: str) -> list[ToolCall]:
        """Get bash/shell commands only (security audit focus)."""
        ...

    def token_usage(self, session_id: str | None = None) -> TokenUsage:
        """Token usage for a session (or total if session_id is None)."""
        ...

    def errors(self, since_timestamp: int | None = None) -> list[ErrorRecord]:
        """Error records, optionally filtered by time."""
        ...
```

### Compatibility Registry

A YAML file in the repo tracks which agent versions have been validated:

**`compatibility.yaml`** (repo root):

```yaml
# Agent data format compatibility registry.
# Community-maintained: submit PRs to add validated versions.
# URL: https://raw.githubusercontent.com/peerlabs/plsec/main/compatibility.yaml

schema_version: 1

adapters:
  opencode:
    data_dir: "~/.local/share/opencode"
    format: "sqlite"
    validated:
      - version: "1.2.10"
        schema_hash: "<sha256 of .schema output>"
        date: "2026-02-23"
        status: "compatible"
        notes: "9 tables, 3 drizzle migrations"
      - version: "1.1.63"
        schema_hash: "<sha256>"
        date: "2026-02-23"
        status: "compatible"
    untested_range: ">=1.3.0"
    known_incompatible: []
    min_supported: "1.1.0"

  claude-code:
    data_dir: "~/.claude"
    format: "jsonl"
    validated:
      - version: "2.1.39"
        format_version: 2
        date: "2026-02-23"
        status: "compatible"
        notes: "stats-cache.json v2, JSONL sessions"
    untested_range: ">=2.2.0"
    known_incompatible: []
    min_supported: "2.0.0"
```

**Local cache** (`~/.peerlabs/plsec/cache/`):

```json
{
  "opencode": {
    "version": "1.2.10",
    "schema_hash": "abc123",
    "validated_at": "2026-02-23T15:30:00Z",
    "result": "compatible"
  }
}
```

### Validation Flow

```
plsec doctor / plsec status / plsec monitor
    |
    v
  Is agent data dir present?
    |-- No -> SKIP (agent not installed)
    |-- Yes:
        |
        v
      Read agent version from data store
        |
        v
      Check local cache -- version + schema hash match?
        |-- Yes, compatible -> OK (use cached result)
        |-- Yes, incompatible -> FAIL
        |-- No (cache miss or version changed):
            |
            v
          Check compatibility.yaml
            |-- Version in validated list -> validate schema hash -> cache result
            |-- Version in untested_range -> WARN "untested version"
            |-- Version in known_incompatible -> FAIL
            |-- Version below min_supported -> FAIL "upgrade required"
```

## Integration Points

### 1. `plsec doctor` -- New Health Checks

| Check | ID | Description |
|-------|----|-------------|
| OpenCode data adapter | D-1 | OpenCode data detected and adapter compatible |
| Claude Code data adapter | D-2 | Claude Code data detected and adapter compatible |
| Agent version untested | D-3 | WARN if agent version not in validated list |
| Auth token exposure | D-4 | WARN if plaintext auth tokens found (e.g., `auth.json`) |

### 2. `plsec status` -- Agent Activity Checks

| Check | Category | Description |
|-------|----------|-------------|
| Active session | Activity | Is an agent session currently running? |
| Token budget | Activity | Token usage in current session / today |
| Error rate | Activity | API errors in recent sessions |
| Last scan | Activity | When was the last security scan? |

### 3. `plsec monitor [agent]` -- Dedicated Command

```
plsec monitor                  # Auto-detect, show all agents
plsec monitor opencode         # OpenCode only
plsec monitor claude           # Claude Code only
plsec monitor --sessions 5     # Last 5 sessions summary
plsec monitor --audit          # Security audit focus (bash commands)
plsec monitor --tokens         # Token usage breakdown
plsec monitor --errors         # Error dashboard
plsec monitor --json           # Machine-readable output
```

**Default output** (auto-detect, summary):

```
plsec monitor - Agent Activity Summary

OpenCode v1.2.10 (compatible)
  Sessions: 46 total, last active 2h ago
  Today: 3 sessions, 12,450 tokens, 0 errors
  Tool calls: 837 bash, 1,130 edits, 1,499 reads
  File changes: +412 -198 across 23 files

Claude Code v2.1.39 (compatible)
  Sessions: 6 total, last active 9d ago
  Lifetime: 497 messages, 93 tool calls
  Token usage: 27,529 output, 15.6M cache reads

[OK] All agent data adapters compatible
```

**Audit output** (`--audit`):

```
plsec monitor --audit

OpenCode Bash Commands (last session)
  2026-02-23 15:24  make ci
  2026-02-23 15:20  source .venv/bin/activate && pytest --co -q
  2026-02-23 15:18  ls -la /Users/.../opencode/tool-output/
  ...

Cross-reference with plsec audit log:
  ~/.peerlabs/plsec/logs/claude-audit-20260223.log
  23 entries, 23 matches (100% coverage)
```

### 4. Security Audit Cross-Reference

For agents where plsec also captures command execution via wrapper
audit logs (`CLAUDE_CODE_SHELL_PREFIX`), the monitor command can
cross-reference the two independent data sources:

- **Agent database** records what the agent says it executed
- **plsec audit log** records what actually ran on the system

Any discrepancy is a security finding. This provides defense-in-depth
for command execution auditing.

For OpenCode, the SQLite `part` table (`type=tool`, `tool=bash`)
provides the equivalent of `CLAUDE_CODE_SHELL_PREFIX` natively,
without needing a shell prefix wrapper. plsec can query both sources.

## Implementation Plan

### Phase 1: Foundation (v0.1.x)

1. Add `data_dir` field to `AgentSpec`
2. Create `compatibility.yaml` with current validated versions
3. Implement `core/compatibility.py` -- version checking, cache management
4. Add doctor checks D-1 through D-4
5. Tests for compatibility checking logic

### Phase 2: Adapters (v0.1.x)

1. Define `AgentDataAdapter` protocol in `core/adapters/__init__.py`
2. Implement `OpenCodeAdapter` -- SQLite queries for sessions, tools, tokens
3. Implement `ClaudeCodeAdapter` -- JSONL parsing for sessions, tools, stats
4. Integrate adapters into `plsec status` activity checks
5. Tests with fixture data (not live agent databases)

### Phase 3: Monitor Command (v0.2.x)

1. `src/plsec/commands/monitor.py` -- `plsec monitor` command
2. Summary view (default), audit view, token view, error view
3. JSON output for TUI consumption
4. Security audit cross-reference with wrapper logs

### Phase 4: Community + Ecosystem (ongoing)

1. Publish `compatibility.yaml` at a stable URL
2. Document how to validate and submit new agent versions
3. `plsec doctor --update-compat` to fetch latest compatibility list
4. Extend to additional agents as data source analysis is completed

## Testing Strategy

### Compatibility tests (automated, run on plsec CI)

For each supported agent version:

1. **Schema validation**: hash the agent's database schema (OpenCode)
   or file format markers (Claude Code) and compare against expected
2. **Query smoke tests**: run each adapter method against fixture data
   that represents the expected format
3. **Regression detection**: if a new agent version changes the format,
   CI fails with a clear message to update `compatibility.yaml`

### Release validation (manual / community)

When a new agent version is released:

1. Install the new version
2. Run `plsec doctor` -- should report "untested version" warning
3. Run adapter smoke tests against the live data
4. If compatible: submit PR adding the version to `compatibility.yaml`
5. If incompatible: file an issue, update adapter, add to `known_incompatible`

### Fixture data

Test fixtures are synthetic -- not copies of real agent databases.
This avoids shipping user data and ensures tests are deterministic.
Fixtures cover:

- Normal operation (sessions, tool calls, tokens)
- Edge cases (empty database, missing tables, schema drift)
- Error conditions (corrupt data, version mismatch)

## Security Considerations

1. **Auth token exposure**: Both agents store OAuth tokens in plaintext
   files (`~/.local/share/opencode/auth.json`, `~/.claude/` session data).
   plsec should WARN about this in doctor checks but NEVER read or log
   the token values.

2. **Read-only access**: Adapters must NEVER write to agent data stores.
   All queries are read-only. Use `?mode=ro` for SQLite connections.

3. **Sensitive data in tool output**: Bash command outputs may contain
   secrets, credentials, or private data. The monitor command should
   truncate outputs and never log full tool results to plsec's own logs.

4. **Data directory permissions**: plsec should check and WARN if agent
   data directories have overly permissive file permissions (world-readable).

## Open Questions

1. **Should `plsec monitor --watch` exist?** Continuous monitoring mode
   would be useful but may conflict with `plsec status --watch`. Consider
   making `plsec status` the unified watch view and `plsec monitor` the
   detailed per-agent analysis.

2. **Should adapters support remote agent data?** (e.g., agents running
   in containers or on remote machines). Defer to `plsec run --container`
   design in v0.2.0.

3. **Token cost calculation**: OpenCode stores per-step token counts but
   not costs. Claude Code stores cost in `stats-cache.json`. Should plsec
   compute costs from token counts using published pricing, or only report
   what the agent provides?

4. **Data retention policy**: Should `plsec monitor` respect any data
   retention limits? Agent databases can grow large over time.
