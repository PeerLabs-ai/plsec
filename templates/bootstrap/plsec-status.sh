#!/bin/bash
# plsec-status.sh - Health status for plsec installation
#
# Answers: "Is plsec installed, configured, and active in this environment?"
#
# Design: docs/plsec-status-design.md
# Exit codes: 0 = OK (warnings acceptable), 1 = failures present
#
# Usage:
#   plsec-status               # Human-readable colored output
#   plsec-status --json        # Machine-readable JSON
#   plsec-status --quiet       # Exit code only (for CI)
#   plsec-status --project .   # Check specific project directory

PLSEC_DIR="@@PLSEC_DIR@@"
PLSEC_VERSION="${PLSEC_VERSION:-unknown}"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Staleness thresholds (seconds)
STALE_WARN_SECONDS=$((24 * 60 * 60))   # 24 hours
STALE_FAIL_SECONDS=$((7 * 24 * 60 * 60))  # 7 days

# Expected subdirectories
EXPECTED_SUBDIRS="configs logs manifests trivy trivy/policies"

# Expected scanner config files (relative to PLSEC_DIR)
EXPECTED_SCANNER_CONFIGS="trivy/trivy-secret.yaml trivy/trivy.yaml configs/pre-commit"

# ---------------------------------------------------------------------------
# Color support
# ---------------------------------------------------------------------------

if [[ -t 1 ]]; then
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    RED='\033[0;31m'
    GREY='\033[0;90m'
    BOLD='\033[1m'
    RESET='\033[0m'
else
    GREEN='' YELLOW='' RED='' GREY='' BOLD='' RESET=''
fi

# ---------------------------------------------------------------------------
# Global state (accumulated by check functions)
# ---------------------------------------------------------------------------

declare -a VERDICTS=()
declare -a CHECK_IDS=()
declare -a CHECK_NAMES=()
declare -a CHECK_CATEGORIES=()
declare -a CHECK_DETAILS=()

WARNING_COUNT=0
ERROR_COUNT=0

# ---------------------------------------------------------------------------
# Result recording
# ---------------------------------------------------------------------------

# Record a check result.
# Usage: record_check "I-1" "installation" "plsec directory" "ok" "~/.peerlabs/plsec"
record_check() {
    local id="$1" category="$2" name="$3" verdict="$4" detail="${5:-}"

    CHECK_IDS+=("$id")
    CHECK_CATEGORIES+=("$category")
    CHECK_NAMES+=("$name")
    VERDICTS+=("$verdict")
    CHECK_DETAILS+=("$detail")

    case "$verdict" in
        warn) WARNING_COUNT=$((WARNING_COUNT + 1)) ;;
        fail) ERROR_COUNT=$((ERROR_COUNT + 1)) ;;
    esac
}

# ---------------------------------------------------------------------------
# Verdict helpers
# ---------------------------------------------------------------------------

# Compute overall verdict from the VERDICTS array.
# ok = no failures. fail = any failure. Warnings are acceptable.
compute_overall() {
    local v
    for v in "${VERDICTS[@]}"; do
        if [[ "$v" == "fail" ]]; then
            echo "fail"
            return
        fi
    done
    echo "ok"
}

# Format a verdict string for display.
format_verdict() {
    local verdict="$1"
    case "$verdict" in
        ok)   printf "${GREEN}%-4s${RESET}" "OK" ;;
        warn) printf "${YELLOW}%-4s${RESET}" "WARN" ;;
        fail) printf "${RED}%-4s${RESET}" "FAIL" ;;
        skip) printf "${GREY}%-4s${RESET}" "SKIP" ;;
        *)    printf "%-4s" "????" ;;
    esac
}

# ---------------------------------------------------------------------------
# Installation checks
# ---------------------------------------------------------------------------

# I-1: Check PLSEC_DIR exists
check_plsec_dir() {
    if [[ -d "$PLSEC_DIR" ]]; then
        record_check "I-1" "installation" "plsec directory" "ok" "$PLSEC_DIR"
        echo "ok"
    else
        record_check "I-1" "installation" "plsec directory" "fail" "$PLSEC_DIR"
        echo "fail"
    fi
}

# I-1 (sub): Check expected subdirectories
check_subdirs() {
    local missing=0
    local subdir
    for subdir in $EXPECTED_SUBDIRS; do
        if [[ ! -d "${PLSEC_DIR}/${subdir}" ]]; then
            missing=$((missing + 1))
        fi
    done

    if [[ $missing -eq 0 ]]; then
        record_check "I-1" "installation" "subdirectories" "ok" "all present"
        echo "ok"
    else
        record_check "I-1" "installation" "subdirectories" "warn" "${missing} missing"
        echo "warn"
    fi
}

# I-2, I-3: Check agent config file in configs/
# Usage: check_agent_config "CLAUDE.md"
check_agent_config() {
    local filename="$1"
    local config_path="${PLSEC_DIR}/configs/${filename}"

    if [[ -f "$config_path" ]]; then
        if [[ ! -s "$config_path" ]]; then
            record_check "I-agent" "installation" "${filename} config" "warn" "empty file"
            echo "warn"
        else
            record_check "I-agent" "installation" "${filename} config" "ok" "$config_path"
            echo "ok"
        fi
    else
        record_check "I-agent" "installation" "${filename} config" "fail" "missing"
        echo "fail"
    fi
}

# I-4 through I-11: Check a tool binary
# Usage: check_tool "trivy" "required"
check_tool() {
    local tool_name="$1"
    local requirement="${2:-required}"  # "required" or "optional"

    if command -v "$tool_name" &> /dev/null; then
        local tool_path
        tool_path=$(command -v "$tool_name")
        record_check "I-tool" "installation" "$tool_name" "ok" "$tool_path"
        echo "ok"
    else
        if [[ "$requirement" == "required" ]]; then
            record_check "I-tool" "installation" "$tool_name" "fail" "not found"
            echo "fail"
        else
            record_check "I-tool" "installation" "$tool_name" "warn" "not found (optional)"
            echo "warn"
        fi
    fi
}

# I-5, I-6: Check scanner config file
# Usage: check_scanner_config "trivy/trivy-secret.yaml" "Trivy secret rules"
check_scanner_config() {
    local rel_path="$1"
    local description="$2"
    local full_path="${PLSEC_DIR}/${rel_path}"

    if [[ -f "$full_path" ]]; then
        record_check "I-scanner" "installation" "$description" "ok" "$full_path"
        echo "ok"
    else
        record_check "I-scanner" "installation" "$description" "warn" "${rel_path} missing"
        echo "warn"
    fi
}

# I-7: Check wrapper script exists and is executable
# Usage: check_wrapper_script "claude-wrapper.sh" "Claude Code wrapper"
check_wrapper_script() {
    local filename="$1"
    local description="$2"
    local full_path="${PLSEC_DIR}/${filename}"

    if [[ -f "$full_path" ]]; then
        if [[ -x "$full_path" ]]; then
            record_check "I-7" "installation" "$description" "ok" "$full_path"
            echo "ok"
        else
            record_check "I-7" "installation" "$description" "warn" "not executable"
            echo "warn"
        fi
    else
        record_check "I-7" "installation" "$description" "fail" "missing"
        echo "fail"
    fi
}

# ---------------------------------------------------------------------------
# Configuration checks
# ---------------------------------------------------------------------------

# C-1: Detect security mode from CLAUDE.md content
detect_security_mode() {
    local claude_md="${PLSEC_DIR}/configs/CLAUDE.md"
    if [[ ! -f "$claude_md" ]]; then
        echo "unknown"
        return
    fi
    if grep -q "RESTRICTED" "$claude_md" 2>/dev/null; then
        echo "strict"
    elif grep -q "Security Constraints" "$claude_md" 2>/dev/null; then
        echo "balanced"
    else
        echo "unknown"
    fi
}

# C-2: Detect which agents are configured
detect_agents() {
    local agents=()
    if [[ -f "${PLSEC_DIR}/configs/CLAUDE.md" ]]; then
        agents+=("claude")
    fi
    if [[ -f "${PLSEC_DIR}/configs/opencode.json" ]]; then
        agents+=("opencode")
    fi

    if [[ ${#agents[@]} -eq 0 ]]; then
        echo "none"
    else
        echo "${agents[*]}"
    fi
}

# C-3: Check pre-commit hook in project
# Usage: check_precommit_hook "/path/to/project"
check_precommit_hook() {
    local project_path="$1"
    local hook_path="${project_path}/.git/hooks/pre-commit"

    if [[ ! -d "${project_path}/.git" ]]; then
        record_check "C-3" "configuration" "pre-commit hook" "fail" "not a git repo"
        echo "fail"
        return
    fi

    if [[ ! -f "$hook_path" ]]; then
        record_check "C-3" "configuration" "pre-commit hook" "fail" "hook missing"
        echo "fail"
        return
    fi

    if grep -q "plsec\|trivy" "$hook_path" 2>/dev/null; then
        record_check "C-3" "configuration" "pre-commit hook" "ok" "references plsec"
        echo "ok"
    else
        record_check "C-3" "configuration" "pre-commit hook" "warn" "no plsec reference"
        echo "warn"
    fi
}

# C-4, C-5: Check project-level config file
# Usage: check_project_config "/path/to/project" "CLAUDE.md"
check_project_config() {
    local project_path="$1"
    local filename="$2"
    local project_config="${project_path}/${filename}"
    local template_config="${PLSEC_DIR}/configs/${filename}"

    if [[ ! -f "$project_config" ]]; then
        record_check "C-project" "configuration" "${filename} (project)" "fail" "not found"
        echo "fail"
        return
    fi

    if [[ -f "$template_config" ]] && diff -q "$project_config" "$template_config" > /dev/null 2>&1; then
        record_check "C-project" "configuration" "${filename} (project)" "ok" "matches template"
        echo "ok"
    else
        record_check "C-project" "configuration" "${filename} (project)" "warn" "differs from template"
        echo "warn"
    fi
}

# ---------------------------------------------------------------------------
# Activity checks
# ---------------------------------------------------------------------------

# A-1: Check wrapper log freshness
check_log_freshness() {
    local log_dir="${PLSEC_DIR}/logs"
    local newest_log=""
    local newest_age=""

    # Find the most recently modified .log file
    if [[ -d "$log_dir" ]]; then
        newest_log=$(find "$log_dir" -name "*.log" -type f -print 2>/dev/null | head -1)
    fi

    if [[ -z "$newest_log" ]]; then
        record_check "A-1" "activity" "wrapper logs" "fail" "no log files found"
        echo "fail"
        return
    fi

    # Get age of newest log in seconds
    local now
    now=$(date +%s)
    local mod_time
    # macOS stat vs GNU stat
    if stat -f %m "$newest_log" > /dev/null 2>&1; then
        mod_time=$(stat -f %m "$newest_log")
    else
        mod_time=$(stat -c %Y "$newest_log")
    fi
    newest_age=$((now - mod_time))

    if [[ $newest_age -lt $STALE_WARN_SECONDS ]]; then
        record_check "A-1" "activity" "wrapper logs" "ok" "active within 24h"
        echo "ok"
    elif [[ $newest_age -lt $STALE_FAIL_SECONDS ]]; then
        record_check "A-1" "activity" "wrapper logs" "warn" "stale (>24h, <7d)"
        echo "warn"
    else
        record_check "A-1" "activity" "wrapper logs" "fail" "inactive (>7d)"
        echo "fail"
    fi
}

# A-2: Count sessions in today's logs
check_session_count() {
    local log_dir="${PLSEC_DIR}/logs"
    local today
    today=$(date +%Y%m%d)
    local count=0

    # Count "Session started" lines in today's log files
    if [[ -d "$log_dir" ]]; then
        local log_file
        for log_file in "${log_dir}/"*"-${today}.log"; do
            if [[ -f "$log_file" ]]; then
                local file_count
                file_count=$(grep -c "Session started" "$log_file" 2>/dev/null || echo 0)
                count=$((count + file_count))
            fi
        done
    fi

    if [[ $count -gt 0 ]]; then
        record_check "A-2" "activity" "sessions today" "ok" "${count} session(s)"
        echo "ok ${count}"
    elif [[ -d "$log_dir" ]] && find "$log_dir" -name "*.log" -type f | grep -q . 2>/dev/null; then
        # Logs exist but no sessions today
        record_check "A-2" "activity" "sessions today" "warn" "no sessions today"
        echo "warn 0"
    else
        record_check "A-2" "activity" "sessions today" "fail" "no session logs found"
        echo "fail 0"
    fi
}

# A-3: Check for recent scan evidence
check_last_scan() {
    local log_dir="${PLSEC_DIR}/logs"
    local today
    today=$(date +%Y%m%d)

    # Check for scan-YYYYMMDD.jsonl files or scan-latest.json
    if [[ -f "${log_dir}/scan-${today}.jsonl" ]]; then
        record_check "A-3" "activity" "last scan" "ok" "scan run today"
        echo "ok"
        return
    fi

    if [[ -f "${log_dir}/scan-latest.json" ]]; then
        # Scan data exists but not from today - check age
        local now
        now=$(date +%s)
        local mod_time
        if stat -f %m "${log_dir}/scan-latest.json" > /dev/null 2>&1; then
            mod_time=$(stat -f %m "${log_dir}/scan-latest.json")
        else
            mod_time=$(stat -c %Y "${log_dir}/scan-latest.json")
        fi
        local age=$((now - mod_time))

        if [[ $age -lt $STALE_WARN_SECONDS ]]; then
            record_check "A-3" "activity" "last scan" "ok" "within 24h"
            echo "ok"
        else
            record_check "A-3" "activity" "last scan" "warn" "last scan >24h ago"
            echo "warn"
        fi
        return
    fi

    # Check for any scan JSONL files
    if find "$log_dir" -name "scan-*.jsonl" -type f 2>/dev/null | grep -q .; then
        record_check "A-3" "activity" "last scan" "warn" "no recent scan"
        echo "warn"
        return
    fi

    record_check "A-3" "activity" "last scan" "fail" "no scan evidence"
    echo "fail"
}

# ---------------------------------------------------------------------------
# Findings checks
# ---------------------------------------------------------------------------

# F-1: Check secrets detection findings
check_secrets_findings() {
    local latest="${PLSEC_DIR}/logs/scan-latest.json"

    if [[ ! -f "$latest" ]]; then
        record_check "F-1" "findings" "secrets detected" "skip" "no scan data"
        echo "skip"
        return
    fi

    # Parse overall_passed field (simple grep, no jq dependency)
    if grep -q '"overall_passed": true' "$latest" 2>/dev/null || \
       grep -q '"overall_passed":true' "$latest" 2>/dev/null; then
        record_check "F-1" "findings" "secrets detected" "ok" "last scan clean"
        echo "ok"
    else
        record_check "F-1" "findings" "secrets detected" "fail" "findings in last scan"
        echo "fail"
    fi
}

# F-2: Check for pre-commit hook blocks
check_hook_blocks() {
    local log_dir="${PLSEC_DIR}/logs"

    if [[ ! -d "$log_dir" ]] || ! find "$log_dir" -name "*.log" -type f 2>/dev/null | grep -q .; then
        record_check "F-2" "findings" "hook blocks" "skip" "no logs"
        echo "skip"
        return
    fi

    # Look for hook rejection evidence in recent logs
    if grep -rq "ERROR.*secret\|hook.*blocked\|commit.*rejected" "${log_dir}/"*.log 2>/dev/null; then
        record_check "F-2" "findings" "hook blocks" "fail" "rejection detected"
        echo "fail"
    else
        record_check "F-2" "findings" "hook blocks" "ok" "no recent blocks"
        echo "ok"
    fi
}

# ---------------------------------------------------------------------------
# Delta computation (watch mode)
# ---------------------------------------------------------------------------

# Get the current session count from the accumulated CHECK arrays.
# Parses the detail string recorded by check_session_count() for A-2.
get_current_session_count() {
    local i
    for ((i = 0; i < ${#CHECK_IDS[@]}; i++)); do
        if [[ "${CHECK_IDS[$i]}" == "A-2" ]]; then
            local detail="${CHECK_DETAILS[$i]}"
            if [[ "$detail" =~ ([0-9]+) ]]; then
                echo "${BASH_REMATCH[1]}"
                return
            fi
        fi
    done
    echo "0"
}

# Compute session count delta from previous value.
# Returns "+N" when count increased, empty string otherwise.
compute_session_delta() {
    local prev="$1"
    local current
    current=$(get_current_session_count)

    if [[ $prev -eq 0 ]]; then
        echo ""
    elif [[ $current -gt $prev ]]; then
        echo "+$((current - prev))"
    else
        echo ""
    fi
}

# Get modification timestamp (epoch seconds) of scan-latest.json.
# Returns "0" when the file does not exist.
get_scan_timestamp() {
    local latest="${PLSEC_DIR}/logs/scan-latest.json"
    if [[ -f "$latest" ]]; then
        if stat -f %m "$latest" > /dev/null 2>&1; then
            stat -f %m "$latest"
        else
            stat -c %Y "$latest"
        fi
    else
        echo "0"
    fi
}

# Compute scan delta from previous timestamp.
# Returns "new scan" when the file has been updated, empty string otherwise.
compute_scan_delta() {
    local prev="$1"
    local current
    current=$(get_scan_timestamp)

    if [[ $prev -eq 0 ]] || [[ $current -eq 0 ]]; then
        echo ""
    elif [[ $current -gt $prev ]]; then
        echo "new scan"
    else
        echo ""
    fi
}

# ---------------------------------------------------------------------------
# Log tail (watch mode)
# ---------------------------------------------------------------------------

# Print the last N lines from the most recently modified log file.
# Silently returns if no log files exist.
print_log_tail() {
    local num_lines="$1"
    local log_dir="${PLSEC_DIR}/logs"

    local newest_log=""
    if [[ -d "$log_dir" ]]; then
        newest_log=$(ls -t "${log_dir}/"*.log 2>/dev/null | head -1)
    fi

    if [[ -z "$newest_log" ]] || [[ ! -f "$newest_log" ]]; then
        return
    fi

    local basename="${newest_log##*/}"
    printf "\n  ${BOLD}Recent Activity${RESET} (%s)\n" "$basename"

    tail -n "$num_lines" "$newest_log" 2>/dev/null | while IFS= read -r line; do
        printf "    ${GREY}%s${RESET}\n" "$line"
    done
}

# ---------------------------------------------------------------------------
# Human-readable output
# ---------------------------------------------------------------------------

print_header() {
    local mode
    mode=$(detect_security_mode)
    local agents
    agents=$(detect_agents)

    printf "\n${BOLD}plsec v%s [%s] [%s]${RESET}\n\n" "$PLSEC_VERSION" "$mode" "$agents"
}

print_section() {
    local section="$1"
    printf "\n  ${BOLD}%s${RESET}\n" "$section"
}

print_check_line() {
    local name="$1" verdict="$2" detail="$3"
    local verdict_str
    verdict_str=$(format_verdict "$verdict")
    if [[ -n "$detail" ]]; then
        printf "    %-25s %s  %s\n" "$name" "$verdict_str" "$detail"
    else
        printf "    %-25s %s\n" "$name" "$verdict_str"
    fi
}

print_summary() {
    local overall
    overall=$(compute_overall)
    local verdict_str
    verdict_str=$(format_verdict "$overall")

    printf "\n  Overall: %s" "$verdict_str"
    if [[ $WARNING_COUNT -gt 0 ]] || [[ $ERROR_COUNT -gt 0 ]]; then
        printf " ("
        local first=true
        if [[ $ERROR_COUNT -gt 0 ]]; then
            printf "%s" "${ERROR_COUNT} error(s)"
            first=false
        fi
        if [[ $WARNING_COUNT -gt 0 ]]; then
            if [[ $first == false ]]; then
                printf ", "
            fi
            printf "%s" "${WARNING_COUNT} warning(s)"
        fi
        printf ")"
    fi
    printf "\n\n"
}

# ---------------------------------------------------------------------------
# JSON output (pure bash, no jq dependency)
# ---------------------------------------------------------------------------

# Escape a string for JSON output (awk-based to avoid assembler escaping conflicts)
json_escape() {
    printf '%s' "$1" | awk '
    BEGIN { ORS="" }
    {
        gsub(/\\/, "\\\\")
        gsub(/"/, "\\\"")
        gsub(/\t/, "\\t")
        print
    }'
}

print_json() {
    local mode
    mode=$(detect_security_mode)
    local agents_str
    agents_str=$(detect_agents)
    local overall
    overall=$(compute_overall)
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    printf '{\n'
    printf '  "version": "%s",\n' "$(json_escape "$PLSEC_VERSION")"
    printf '  "mode": "%s",\n' "$(json_escape "$mode")"

    # Agents array
    printf '  "agents": ['
    local first=true
    local agent
    for agent in $agents_str; do
        if [[ "$agent" != "none" ]]; then
            if [[ "$first" == true ]]; then
                first=false
            else
                printf ', '
            fi
            printf '"%s"' "$(json_escape "$agent")"
        fi
    done
    printf '],\n'

    printf '  "overall": "%s",\n' "$overall"
    printf '  "warnings": %d,\n' "$WARNING_COUNT"
    printf '  "errors": %d,\n' "$ERROR_COUNT"
    printf '  "timestamp": "%s",\n' "$timestamp"

    # Checks array
    printf '  "checks": [\n'
    local i
    local count=${#CHECK_IDS[@]}
    for ((i = 0; i < count; i++)); do
        printf '    {\n'
        printf '      "id": "%s",\n' "$(json_escape "${CHECK_IDS[$i]}")"
        printf '      "category": "%s",\n' "$(json_escape "${CHECK_CATEGORIES[$i]}")"
        printf '      "name": "%s",\n' "$(json_escape "${CHECK_NAMES[$i]}")"
        printf '      "verdict": "%s",\n' "$(json_escape "${VERDICTS[$i]}")"
        printf '      "detail": "%s"\n' "$(json_escape "${CHECK_DETAILS[$i]}")"
        if [[ $((i + 1)) -lt $count ]]; then
            printf '    },\n'
        else
            printf '    }\n'
        fi
    done
    printf '  ]\n'
    printf '}\n'
}

# ---------------------------------------------------------------------------
# Run all checks
# ---------------------------------------------------------------------------

run_all_checks() {
    local project_path="$1"

    # -- Installation checks --
    # Note: check functions are called without subshells so record_check
    # can modify the global VERDICTS array. Stdout is discarded.
    check_plsec_dir > /dev/null
    if [[ ! -d "$PLSEC_DIR" ]]; then
        # If PLSEC_DIR doesn't exist, skip remaining checks
        return
    fi
    check_subdirs > /dev/null

    # Agent configs
    if [[ -f "${PLSEC_DIR}/configs/CLAUDE.md" ]] || true; then
        check_agent_config "CLAUDE.md" > /dev/null
    fi
    if [[ -f "${PLSEC_DIR}/configs/opencode.json" ]] || true; then
        check_agent_config "opencode.json" > /dev/null
    fi

    # Required tools
    check_tool "git" "required" > /dev/null
    check_tool "trivy" "required" > /dev/null

    # Scanner configs
    local cfg
    for cfg in $EXPECTED_SCANNER_CONFIGS; do
        local desc
        case "$cfg" in
            trivy/trivy-secret.yaml) desc="Trivy secret rules" ;;
            trivy/trivy.yaml)        desc="Trivy configuration" ;;
            configs/pre-commit)      desc="Pre-commit hook template" ;;
            *)                       desc="$cfg" ;;
        esac
        check_scanner_config "$cfg" "$desc" > /dev/null
    done

    # Wrapper scripts
    check_wrapper_script "claude-wrapper.sh" "Claude Code wrapper" > /dev/null
    check_wrapper_script "opencode-wrapper.sh" "OpenCode wrapper" > /dev/null

    # Optional tools
    check_tool "detect-secrets" "optional" > /dev/null
    check_tool "bandit" "optional" > /dev/null
    check_tool "semgrep" "optional" > /dev/null

    # -- Configuration checks --
    local mode
    mode=$(detect_security_mode)
    record_check "C-1" "configuration" "security mode" "ok" "$mode"

    local agents
    agents=$(detect_agents)
    if [[ "$agents" == "none" ]]; then
        record_check "C-2" "configuration" "agent type" "fail" "no agents configured"
    else
        record_check "C-2" "configuration" "agent type" "ok" "$agents"
    fi

    check_precommit_hook "$project_path" > /dev/null

    # Project-level config checks
    if [[ -f "${PLSEC_DIR}/configs/CLAUDE.md" ]]; then
        check_project_config "$project_path" "CLAUDE.md" > /dev/null
    fi
    if [[ -f "${PLSEC_DIR}/configs/opencode.json" ]]; then
        check_project_config "$project_path" "opencode.json" > /dev/null
    fi

    # -- Activity checks --
    check_log_freshness > /dev/null
    check_session_count > /dev/null
    check_last_scan > /dev/null

    # -- Findings checks --
    check_secrets_findings > /dev/null
    check_hook_blocks > /dev/null
}

# ---------------------------------------------------------------------------
# Human-readable display (reads from accumulated global arrays)
# ---------------------------------------------------------------------------

print_human_readable() {
    local project_path="$1"

    print_header

    local current_category=""
    local i
    local count=${#CHECK_IDS[@]}

    for ((i = 0; i < count; i++)); do
        local cat="${CHECK_CATEGORIES[$i]}"
        if [[ "$cat" != "$current_category" ]]; then
            current_category="$cat"
            local section_title
            case "$cat" in
                installation)  section_title="Installation" ;;
                configuration)
                    section_title="Configuration (project: ${project_path})"
                    ;;
                activity)      section_title="Activity" ;;
                findings)      section_title="Findings" ;;
                *)             section_title="$cat" ;;
            esac
            print_section "$section_title"
        fi
        print_check_line "${CHECK_NAMES[$i]}" "${VERDICTS[$i]}" "${CHECK_DETAILS[$i]}"
    done

    print_summary
}

# ---------------------------------------------------------------------------
# Watch mode
# ---------------------------------------------------------------------------

# Reset the global check arrays so run_all_checks() starts fresh.
reset_check_state() {
    VERDICTS=()
    CHECK_IDS=()
    CHECK_NAMES=()
    CHECK_CATEGORIES=()
    CHECK_DETAILS=()
    WARNING_COUNT=0
    ERROR_COUNT=0
}

# Print watch mode header with refresh timestamp and key hints.
print_watch_header() {
    local interval="$1"
    local timestamp
    timestamp=$(date -u +"%Y-%m-%d %H:%M:%S UTC")

    printf "${BOLD}plsec-status --watch${RESET} (every %ds, last: %s)\n" \
        "$interval" "$timestamp"
    printf "${GREY}[q]uit  [r]efresh  [p]ause${RESET}\n"
}

# Inject delta strings into the accumulated CHECK_DETAILS array.
# Modifies A-2 (session count) and A-3 (last scan) entries in-place
# so print_human_readable() renders them automatically.
inject_deltas() {
    local session_delta="$1"
    local scan_delta="$2"

    local i
    for ((i = 0; i < ${#CHECK_IDS[@]}; i++)); do
        if [[ "${CHECK_IDS[$i]}" == "A-2" ]] && [[ -n "$session_delta" ]]; then
            CHECK_DETAILS[$i]="${CHECK_DETAILS[$i]} (${session_delta})"
        fi
        if [[ "${CHECK_IDS[$i]}" == "A-3" ]] && [[ -n "$scan_delta" ]]; then
            CHECK_DETAILS[$i]="${CHECK_DETAILS[$i]} (${scan_delta})"
        fi
    done
}

# Continuous refresh loop.  Re-runs all checks on each iteration,
# computes deltas from the previous cycle, and tails the newest log.
# Exits on 'q' key or SIGINT/SIGTERM.
#
# Keyboard control requires a TTY on stdin.  When stdin is not a
# terminal (pipes, CI, BATS tests) the loop falls back to plain
# sleep and can only be stopped via SIGINT/SIGTERM.
run_watch() {
    local project_path="$1"
    local interval="$2"
    local tail_lines="$3"

    trap 'printf "\n"; exit 0' INT TERM

    # Detect whether stdin is a TTY for keyboard control
    local has_tty=false
    if [[ -t 0 ]]; then
        has_tty=true
    fi

    local prev_session_count=0
    local prev_scan_ts=0
    local paused=false
    local first_run=true

    while true; do
        if [[ "$paused" == false ]]; then
            clear

            reset_check_state
            run_all_checks "$project_path"

            # Compute deltas (skip on first iteration)
            local session_delta=""
            local scan_delta=""
            if [[ "$first_run" == false ]]; then
                session_delta=$(compute_session_delta "$prev_session_count")
                scan_delta=$(compute_scan_delta "$prev_scan_ts")
            fi

            # Snapshot current values for next iteration
            prev_session_count=$(get_current_session_count)
            prev_scan_ts=$(get_scan_timestamp)
            first_run=false

            # Render
            inject_deltas "$session_delta" "$scan_delta"
            print_watch_header "$interval"
            print_human_readable "$project_path"
            print_log_tail "$tail_lines"
        fi

        # Wait for next refresh.  With a TTY, listen for keypresses;
        # without one, fall back to plain sleep.
        if [[ "$has_tty" == true ]]; then
            local key=""
            if read -t "$interval" -n 1 -s key 2>/dev/null; then
                case "$key" in
                    q|Q) printf "\n"; exit 0 ;;
                    r|R) continue ;;
                    p|P)
                        if [[ "$paused" == false ]]; then
                            paused=true
                            printf "\n${YELLOW}[PAUSED]${RESET} press 'p' to resume\n"
                        else
                            paused=false
                        fi
                        ;;
                esac
            fi
        else
            sleep "$interval"
        fi
    done
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    local json_mode=false
    local quiet_mode=false
    local watch_mode=false
    local watch_interval=5
    local tail_lines=5
    local project_path=""

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --json)    json_mode=true; shift ;;
            --quiet)   quiet_mode=true; shift ;;
            --watch)   watch_mode=true; shift ;;
            --interval)
                shift
                if [[ $# -eq 0 ]] || ! [[ "$1" =~ ^[0-9]+$ ]] || [[ "$1" -eq 0 ]]; then
                    echo "ERROR: --interval requires a positive integer" >&2
                    exit 1
                fi
                watch_interval="$1"
                shift
                ;;
            --tail-lines)
                shift
                if [[ $# -eq 0 ]] || ! [[ "$1" =~ ^[0-9]+$ ]] || [[ "$1" -eq 0 ]]; then
                    echo "ERROR: --tail-lines requires a positive integer" >&2
                    exit 1
                fi
                tail_lines="$1"
                shift
                ;;
            --project)
                shift
                if [[ $# -eq 0 ]]; then
                    echo "ERROR: --project requires a path argument" >&2
                    exit 1
                fi
                project_path="$1"
                shift
                ;;
            --help|-h)
                echo "Usage: plsec-status [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --json          Machine-readable JSON output"
                echo "  --quiet         Exit code only (no output)"
                echo "  --watch         Continuous refresh mode"
                echo "  --interval N    Refresh interval in seconds (default: 5)"
                echo "  --tail-lines N  Log lines to show in watch mode (default: 5)"
                echo "  --project DIR   Check specific project directory"
                echo "  --help          Show this help message"
                echo ""
                echo "Watch mode keys: [q]uit, [r]efresh, [p]ause/resume"
                exit 0
                ;;
            *)
                echo "ERROR: Unknown option: $1" >&2
                exit 1
                ;;
        esac
    done

    # Validate flag combinations
    if $watch_mode && ($json_mode || $quiet_mode); then
        echo "ERROR: --watch is incompatible with --json and --quiet" >&2
        exit 1
    fi

    # Default project path to current directory
    if [[ -z "$project_path" ]]; then
        project_path="$(pwd)"
    fi

    # Watch mode: enter continuous loop (never returns)
    if $watch_mode; then
        run_watch "$project_path" "$watch_interval" "$tail_lines"
    fi

    # One-shot mode
    run_all_checks "$project_path"

    # Output
    if $json_mode; then
        print_json
    elif ! $quiet_mode; then
        print_human_readable "$project_path"
    fi

    # Exit code: 0 = ok (warnings acceptable), 1 = failures
    local overall
    overall=$(compute_overall)
    if [[ "$overall" == "fail" ]]; then
        exit 1
    fi
    exit 0
}

# Source guard: execute main only when run directly, not when sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
