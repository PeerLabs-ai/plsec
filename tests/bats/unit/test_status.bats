#!/usr/bin/env bats
# test_status.bats - Unit tests for plsec-status health check functions
#
# Tests individual check functions from plsec-status.sh in isolation
# using a synthetic plsec environment. Bootstrap deploys the status script;
# we source it to test each function independently.

setup() {
    load '../test_helper/bats-support/load'
    load '../test_helper/bats-assert/load'
    load '../test_helper/common'

    setup_fake_home

    # Run bootstrap to deploy all artifacts including plsec-status.sh
    "${BOOTSTRAP}" --agent both

    # Source the status script to get access to individual functions.
    # The source guard (BASH_SOURCE[0] == $0 check) prevents main()
    # from executing when sourced.
    source "${PLSEC_DIR}/plsec-status.sh"
}

teardown() {
    teardown_fake_home
}

# ===========================================================================
# I-1: Directory structure checks
# ===========================================================================

@test "check_plsec_dir returns ok when PLSEC_DIR exists" {
    run check_plsec_dir
    assert_success
    assert_output --partial "ok"
}

@test "check_plsec_dir returns fail when PLSEC_DIR missing" {
    local saved="$PLSEC_DIR"
    PLSEC_DIR="${BATS_TEST_TMPDIR}/nonexistent"
    run check_plsec_dir
    assert_output --partial "fail"
    PLSEC_DIR="$saved"
}

@test "check_subdirs returns ok when all subdirs exist" {
    run check_subdirs
    assert_success
    assert_output --partial "ok"
}

@test "check_subdirs returns warn when a subdir is missing" {
    rmdir "${PLSEC_DIR}/manifests"
    run check_subdirs
    assert_output --partial "warn"
}

# ===========================================================================
# I-2, I-3: Agent config checks
# ===========================================================================

@test "check_agent_config returns ok for existing CLAUDE.md" {
    run check_agent_config "CLAUDE.md"
    assert_success
    assert_output --partial "ok"
}

@test "check_agent_config returns fail for missing CLAUDE.md" {
    rm -f "${PLSEC_DIR}/configs/CLAUDE.md"
    run check_agent_config "CLAUDE.md"
    assert_output --partial "fail"
}

@test "check_agent_config returns warn for empty config" {
    : > "${PLSEC_DIR}/configs/CLAUDE.md"
    run check_agent_config "CLAUDE.md"
    assert_output --partial "warn"
}

@test "check_agent_config returns ok for existing opencode.json" {
    run check_agent_config "opencode.json"
    assert_success
    assert_output --partial "ok"
}

@test "check_agent_config returns fail for missing opencode.json" {
    rm -f "${PLSEC_DIR}/configs/opencode.json"
    run check_agent_config "opencode.json"
    assert_output --partial "fail"
}

# ===========================================================================
# I-4 through I-11: Tool checks
# ===========================================================================

@test "check_tool returns ok for git (should be installed)" {
    run check_tool "git" "required"
    assert_output --partial "ok"
}

@test "check_tool returns fail for missing required tool" {
    run check_tool "nonexistent-tool-xyz" "required"
    assert_output --partial "fail"
}

@test "check_tool returns warn for missing optional tool" {
    run check_tool "nonexistent-tool-xyz" "optional"
    assert_output --partial "warn"
}

# ===========================================================================
# I-5, I-6: Scanner config checks
# ===========================================================================

@test "check_scanner_config returns ok for trivy-secret.yaml" {
    run check_scanner_config "trivy/trivy-secret.yaml" "Trivy secret rules"
    assert_success
    assert_output --partial "ok"
}

@test "check_scanner_config returns warn for missing scanner config" {
    rm -f "${PLSEC_DIR}/trivy/trivy-secret.yaml"
    run check_scanner_config "trivy/trivy-secret.yaml" "Trivy secret rules"
    assert_output --partial "warn"
}

@test "check_scanner_config returns ok for trivy.yaml" {
    run check_scanner_config "trivy/trivy.yaml" "Trivy configuration"
    assert_success
    assert_output --partial "ok"
}

@test "check_scanner_config returns ok for pre-commit" {
    run check_scanner_config "configs/pre-commit" "Pre-commit hook template"
    assert_success
    assert_output --partial "ok"
}

# ===========================================================================
# I-7: Wrapper script checks
# ===========================================================================

@test "check_wrapper_script returns ok for executable claude-wrapper.sh" {
    run check_wrapper_script "claude-wrapper.sh" "Claude Code wrapper"
    assert_success
    assert_output --partial "ok"
}

@test "check_wrapper_script returns warn for non-executable wrapper" {
    chmod -x "${PLSEC_DIR}/claude-wrapper.sh"
    run check_wrapper_script "claude-wrapper.sh" "Claude Code wrapper"
    assert_output --partial "warn"
}

@test "check_wrapper_script returns fail for missing wrapper" {
    rm -f "${PLSEC_DIR}/claude-wrapper.sh"
    run check_wrapper_script "claude-wrapper.sh" "Claude Code wrapper"
    assert_output --partial "fail"
}

@test "check_wrapper_script returns ok for executable opencode-wrapper.sh" {
    run check_wrapper_script "opencode-wrapper.sh" "OpenCode wrapper"
    assert_success
    assert_output --partial "ok"
}

# ===========================================================================
# C-1: Security mode detection
# ===========================================================================

@test "detect_security_mode returns strict for strict CLAUDE.md" {
    # Re-run bootstrap in strict mode
    "${BOOTSTRAP}" --agent claude --strict
    source "${PLSEC_DIR}/plsec-status.sh"
    run detect_security_mode
    assert_output "strict"
}

@test "detect_security_mode returns balanced for balanced CLAUDE.md" {
    run detect_security_mode
    assert_output "balanced"
}

@test "detect_security_mode returns unknown when config missing" {
    rm -f "${PLSEC_DIR}/configs/CLAUDE.md"
    run detect_security_mode
    assert_output "unknown"
}

# ===========================================================================
# C-2: Agent type detection
# ===========================================================================

@test "detect_agents returns claude and opencode when both configs exist" {
    run detect_agents
    assert_output --partial "claude"
    assert_output --partial "opencode"
}

@test "detect_agents returns claude only when opencode.json missing" {
    rm -f "${PLSEC_DIR}/configs/opencode.json"
    run detect_agents
    assert_output --partial "claude"
    refute_output --partial "opencode"
}

@test "detect_agents returns opencode only when CLAUDE.md missing" {
    rm -f "${PLSEC_DIR}/configs/CLAUDE.md"
    run detect_agents
    assert_output --partial "opencode"
    refute_output --partial "claude"
}

@test "detect_agents returns none when no configs found" {
    rm -f "${PLSEC_DIR}/configs/CLAUDE.md" "${PLSEC_DIR}/configs/opencode.json"
    run detect_agents
    assert_output "none"
}

# ===========================================================================
# C-3: Pre-commit hook check (project level)
# ===========================================================================

@test "check_precommit_hook returns ok when hook references plsec" {
    local project="${BATS_TEST_TMPDIR}/project"
    mkdir -p "${project}/.git/hooks"
    printf '#!/bin/bash\n# plsec pre-commit hook\ntrivy fs .\n' > "${project}/.git/hooks/pre-commit"
    chmod +x "${project}/.git/hooks/pre-commit"
    run check_precommit_hook "$project"
    assert_output --partial "ok"
}

@test "check_precommit_hook returns warn when hook exists but no plsec reference" {
    local project="${BATS_TEST_TMPDIR}/project"
    mkdir -p "${project}/.git/hooks"
    printf '#!/bin/bash\necho "custom hook"\n' > "${project}/.git/hooks/pre-commit"
    chmod +x "${project}/.git/hooks/pre-commit"
    run check_precommit_hook "$project"
    assert_output --partial "warn"
}

@test "check_precommit_hook returns fail when not a git repo" {
    local project="${BATS_TEST_TMPDIR}/project"
    mkdir -p "${project}"
    run check_precommit_hook "$project"
    assert_output --partial "fail"
}

@test "check_precommit_hook returns fail when hook missing" {
    local project="${BATS_TEST_TMPDIR}/project"
    mkdir -p "${project}/.git/hooks"
    run check_precommit_hook "$project"
    assert_output --partial "fail"
}

# ===========================================================================
# C-4, C-5: Project config checks
# ===========================================================================

@test "check_project_config returns ok when project config matches template" {
    local project="${BATS_TEST_TMPDIR}/project"
    mkdir -p "$project"
    cp "${PLSEC_DIR}/configs/CLAUDE.md" "${project}/CLAUDE.md"
    run check_project_config "$project" "CLAUDE.md"
    assert_output --partial "ok"
}

@test "check_project_config returns warn when config differs from template" {
    local project="${BATS_TEST_TMPDIR}/project"
    mkdir -p "$project"
    echo "# Custom CLAUDE.md" > "${project}/CLAUDE.md"
    run check_project_config "$project" "CLAUDE.md"
    assert_output --partial "warn"
}

@test "check_project_config returns fail when project config missing" {
    local project="${BATS_TEST_TMPDIR}/project"
    mkdir -p "$project"
    run check_project_config "$project" "CLAUDE.md"
    assert_output --partial "fail"
}

# ===========================================================================
# A-1: Wrapper log freshness
# ===========================================================================

@test "check_log_freshness returns ok for recent log" {
    # Create a log file that is recent (just touched)
    touch "${PLSEC_DIR}/logs/claude-$(date +%Y%m%d).log"
    run check_log_freshness
    assert_output --partial "ok"
}

@test "check_log_freshness returns warn for stale log" {
    # Create a log file and backdate it to 3 days ago
    local log_file="${PLSEC_DIR}/logs/claude-test.log"
    touch -t "$(date -v-3d +%Y%m%d%H%M 2>/dev/null || date -d '3 days ago' +%Y%m%d%H%M)" "$log_file"
    run check_log_freshness
    assert_output --partial "warn"
}

@test "check_log_freshness returns fail when no logs exist" {
    rm -f "${PLSEC_DIR}/logs/"*.log
    run check_log_freshness
    assert_output --partial "fail"
}

# ===========================================================================
# A-2: Session count
# ===========================================================================

@test "check_session_count returns ok when sessions found today" {
    local today
    today=$(date +%Y%m%d)
    local log_file="${PLSEC_DIR}/logs/claude-${today}.log"
    printf '[%s] [12345] === Session started: /tmp/project ===\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$log_file"
    printf '[%s] [12345] === Session ended: exit code 0 ===\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$log_file"
    run check_session_count
    assert_output --partial "ok"
}

@test "check_session_count returns fail when no sessions in logs" {
    rm -f "${PLSEC_DIR}/logs/"*.log
    run check_session_count
    assert_output --partial "fail"
}

@test "check_session_count reports correct count" {
    local today
    today=$(date +%Y%m%d)
    local log_file="${PLSEC_DIR}/logs/claude-${today}.log"
    printf '[2026-02-24T10:00:00Z] [100] === Session started: /tmp/a ===\n' > "$log_file"
    printf '[2026-02-24T10:30:00Z] [100] === Session ended: exit code 0 ===\n' >> "$log_file"
    printf '[2026-02-24T11:00:00Z] [200] === Session started: /tmp/b ===\n' >> "$log_file"
    printf '[2026-02-24T11:30:00Z] [200] === Session ended: exit code 0 ===\n' >> "$log_file"
    run check_session_count
    assert_output --partial "2"
}

# ===========================================================================
# A-3: Last scan
# ===========================================================================

@test "check_last_scan returns ok when scan evidence found recently" {
    local today
    today=$(date +%Y%m%d)
    # Simulate scan log (scan-YYYYMMDD.jsonl is the persistence format)
    printf '{"scanner_id":"trivy-secrets","verdict":"pass"}\n' > "${PLSEC_DIR}/logs/scan-${today}.jsonl"
    run check_last_scan
    assert_output --partial "ok"
}

@test "check_last_scan returns fail when no scan evidence" {
    rm -f "${PLSEC_DIR}/logs/scan-"*.jsonl "${PLSEC_DIR}/logs/scan-latest.json"
    run check_last_scan
    assert_output --partial "fail"
}

# ===========================================================================
# F-1: Secrets detection findings
# ===========================================================================

@test "check_secrets_findings returns ok when last scan passed" {
    printf '{"overall_passed": true}' > "${PLSEC_DIR}/logs/scan-latest.json"
    run check_secrets_findings
    assert_output --partial "ok"
}

@test "check_secrets_findings returns fail when last scan failed" {
    printf '{"overall_passed": false}' > "${PLSEC_DIR}/logs/scan-latest.json"
    run check_secrets_findings
    assert_output --partial "fail"
}

@test "check_secrets_findings returns skip when no scan data" {
    rm -f "${PLSEC_DIR}/logs/scan-latest.json"
    run check_secrets_findings
    assert_output --partial "skip"
}

# ===========================================================================
# F-2: Hook block findings
# ===========================================================================

@test "check_hook_blocks returns ok when no rejections in logs" {
    local today
    today=$(date +%Y%m%d)
    local log_file="${PLSEC_DIR}/logs/claude-${today}.log"
    printf '[2026-02-24T10:00:00Z] [100] === Session started: /tmp/a ===\n' > "$log_file"
    run check_hook_blocks
    assert_output --partial "ok"
}

@test "check_hook_blocks returns skip when no logs" {
    rm -f "${PLSEC_DIR}/logs/"*.log
    run check_hook_blocks
    assert_output --partial "skip"
}

# ===========================================================================
# Verdict helpers
# ===========================================================================

@test "compute_overall returns ok when all checks ok" {
    VERDICTS=("ok" "ok" "ok")
    run compute_overall
    assert_output "ok"
}

@test "compute_overall returns ok when warnings present (warnings acceptable)" {
    VERDICTS=("ok" "warn" "ok")
    run compute_overall
    assert_output "ok"
}

@test "compute_overall returns fail when any check fails" {
    VERDICTS=("ok" "warn" "fail")
    run compute_overall
    assert_output "fail"
}

@test "compute_overall ignores skip verdicts" {
    VERDICTS=("ok" "skip" "ok")
    run compute_overall
    assert_output "ok"
}

# ===========================================================================
# Output formatting
# ===========================================================================

@test "format_verdict displays green for ok" {
    run format_verdict "ok"
    assert_output --partial "OK"
}

@test "format_verdict displays yellow for warn" {
    run format_verdict "warn"
    assert_output --partial "WARN"
}

@test "format_verdict displays red for fail" {
    run format_verdict "fail"
    assert_output --partial "FAIL"
}

@test "format_verdict displays grey for skip" {
    run format_verdict "skip"
    assert_output --partial "SKIP"
}

# ===========================================================================
# Script structure
# ===========================================================================

@test "plsec-status.sh passes bash syntax check" {
    run bash -n "${PLSEC_DIR}/plsec-status.sh"
    assert_success
}

@test "plsec-status.sh is executable" {
    assert [ -x "${PLSEC_DIR}/plsec-status.sh" ]
}

@test "plsec-status.sh has PLSEC_DIR baked in" {
    run grep "PLSEC_DIR=\"${PLSEC_DIR}\"" "${PLSEC_DIR}/plsec-status.sh"
    assert_success
}
