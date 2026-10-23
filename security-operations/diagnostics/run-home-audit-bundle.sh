#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2329  # The embedded helper defines globals and functions this script does not use.
# run-home-audit-bundle.sh - runs the eight home network audit scripts (A1-A8) in order on this
# Mac or Linux computer, saves all their JSON/CSV results in one timestamped folder, and keeps
# going if any single script fails. Optionally builds the HTML report (A9) at the end. The
# Windows version is Invoke-HomeAuditBundle.ps1.
#
# Usage:  bash run-home-audit-bundle.sh [--output DIR] [--passive] [--scan-lan] [--home-ssid NAME]
#                                       [--online] [--include-router-checklist]
#                                       [--approved-remote-tool LIST] [--all-users]
#                                       [--skip NAME[,NAME...]] [--timeout-minutes N]
#                                       [--technician NAME [--client NAME]]
#
# Options:
#   --output DIR                Parent folder for results. A sub-folder
#                               HomeAudit_<host>_<yyyyMMdd-HHmmss> is created in it.
#                               Default: ${TMPDIR:-/tmp}/msp-toolkit.
#   --passive                   Send nothing on the network: A2 reads the neighbor (ARP) table
#                               only, and A7 (router) is not run, because every A7 check talks
#                               to the router. Cannot be combined with --scan-lan or --online.
#   --scan-lan                  Let A4 also check other devices on the local subnet for risky
#                               open ports.
#   --home-ssid NAME            Name of the client's home Wi-Fi, passed to A3 (use when wired).
#   --online                    Let A6 ask the update servers now (slower) instead of using the
#                               last check.
#   --include-router-checklist  Ask the router checklist questions during the run (someone must
#                               be at the keyboard). A7 then has no time limit. Without it the
#                               checklist items are recorded as "Not verified".
#   --approved-remote-tool LIST Remote-access tools the MSP or client uses on purpose, passed to
#                               A8. REPLACES approved-remote-tools.txt for this run.
#   --all-users                 With sudo: include other users' browser profiles (A5) and, on
#                               macOS, every user's ~/Applications (A8).
#   --skip LIST                 Scripts to leave out, by name or ID (for example
#                               get-home-network-map or A2), comma separated.
#   --timeout-minutes N         Per-script time limit, 2-60 (default 15).
#   --technician NAME           Build the HTML report (A9) into the results folder at the end.
#                               Needs PowerShell 7 (pwsh); without it, the command to run on
#                               another computer is printed.
#   --client NAME               Client/household name for the report title.
#   --help                      Show this help.
#
# Run order:
#   1 A1 get-endpoint-security-status-macos.sh / -linux.sh   Computer security settings
#   2 A2 get-home-network-map.sh                             Devices on the network
#   3 A3 get-wifi-security-audit-macos.sh / -linux.sh        Wi-Fi security
#   4 A4 get-open-port-scan.sh                               Open ports
#   5 A5 get-browser-security-check.sh                       Web browsers
#   6 A6 get-update-compliance-macos.sh / -linux.sh          Updates and end of support
#   7 A7 get-router-security-check.sh                        Router
#   8 A8 get-home-device-inventory.sh                        Device and software inventory
#
# Each script runs in its own bash process, so a crash or "exit" in one cannot stop the
# others. A script still running after --timeout-minutes is stopped and reported as failed.
# Scripts are found next to this file first (a flat folder on a USB stick), then in their
# normal repository folders. Anything under an _archive folder is refused.
#
# Examples:
#   bash run-home-audit-bundle.sh
#   sudo bash run-home-audit-bundle.sh --all-users --include-router-checklist --technician "J. Smith"
#   bash run-home-audit-bundle.sh --passive --output ~/Desktop/Audit
#
# Purpose       : One command for the whole home network audit on a Mac or Linux computer.
# Use Case      : Home network security audits (run on each computer the client wants checked).
# Scope         : This computer, its local subnet (A2; A4 with --scan-lan) and its default
#                 gateway (A7). With --passive: this computer only.
# Risk Level    : Read-Only -- runs read-only scripts and writes result files only.
# Prerequisites : macOS 12+ or Linux | bash 3.2+ | root: No (recommended: sudo, for complete
#                 results) | The eight audit scripts must be present (see Run order)
# Version       : 1.0.0
# Limitations   : Runs on the local computer only; repeat on each computer to audit. Per-script
#                 output appears on screen as each one runs; each script's own log is in
#                 ${TMPDIR:-/tmp}/msp-toolkit. The HTML report needs PowerShell 7.

set -u
MSP_SCRIPT_FILE=$0

#region MSPToolkit (generated) Sections=Core
# DO NOT EDIT — regenerate with Sync-MSPEmbeddedHelper.ps1
# Source: endpoint-systems/utilities/msp-toolkit-common.sh | Sections: Core | SHA256: 973c32cda8c7bcd7deb382fdd30e7df70a3edc3db9231b0dd3a55396649b62d1
#region MSPHelper:Core
# --- Run state ------------------------------------------------------------------------------
# One toolkit script = one "run": one log file, one findings list, one optional export.
MSP_SCHEMA_VERSION='2.0'
MSP_CHECK_ID=''
MSP_SCRIPT_NAME=''
MSP_SCRIPT_VERSION=''
MSP_RISK=''
MSP_PLATFORM=''
MSP_OS_VERSION=''
MSP_SHELL=''
MSP_HOST=''
MSP_USER=''
MSP_IS_ADMIN='false'
MSP_START_EPOCH=0
MSP_START_ISO=''
MSP_START_STAMP=''
MSP_END_ISO=''
MSP_LOG_PATH=''
MSP_LOG_FAILED=0
MSP_WORK_DIR=''
MSP_COLOR=0
MSP_PARAM_COUNT=0
MSP_PARAM_KEYS=()
MSP_PARAM_VALUES=()
MSP_F_COUNT=0
MSP_F_ID=()
MSP_F_CATEGORY=()
MSP_F_CHECK=()
MSP_F_STATUS=()
MSP_F_SEVERITY=()
MSP_F_TARGET=()
MSP_F_DETAIL=()
MSP_F_REC=()
MSP_F_EVIDENCE=()
MSP_DATA_COUNT=0
MSP_DATA_NAMES=()

# --- Small utilities --------------------------------------------------------------------------
msp_have() {
    # True when a command is available. Used before every optional tool (nmcli, nc, ...).
    command -v "$1" >/dev/null 2>&1
}

msp_is_root() {
    [ "$(id -u 2>/dev/null)" = "0" ]
}

msp_repeat() {
    # msp_repeat CHAR COUNT -> CHAR repeated COUNT times (no seq/printf -v tricks needed).
    local out='' i=0
    while [ "$i" -lt "$2" ]; do out="$out$1"; i=$((i + 1)); done
    printf '%s' "$out"
}

msp_iso_time() {
    # Local time as ISO 8601 with a +hh:mm offset, matching the PowerShell helper.
    local d
    d=$(date '+%Y-%m-%dT%H:%M:%S%z')
    printf '%s:%s' "${d%??}" "${d#"${d%??}"}"
}

msp_run_timeout() {
    # msp_run_timeout SECONDS COMMAND [ARGS...]
    # Runs COMMAND, stopping it after SECONDS (macOS has no "timeout" command). Returns the
    # command's exit code, or 124 when it was stopped. Output goes wherever the caller sends it.
    local secs=$1 pid watcher rc flag
    shift
    flag="${MSP_WORK_DIR:-${TMPDIR:-/tmp}}/timeout.$$.$RANDOM"
    "$@" &
    pid=$!
    (
        sleep "$secs" &
        sp=$!
        trap 'kill "$sp" 2>/dev/null; exit 0' TERM
        wait "$sp"
        : >"$flag"
        kill -TERM "$pid" 2>/dev/null
        sleep 1
        kill -KILL "$pid" 2>/dev/null
    ) >/dev/null 2>&1 &
    watcher=$!
    # 2>/dev/null hides bash's "Terminated" job notice, which would otherwise appear on screen.
    wait "$pid" 2>/dev/null
    rc=$?
    kill -TERM "$watcher" 2>/dev/null
    wait "$watcher" 2>/dev/null
    if [ -f "$flag" ]; then
        rm -f "$flag"
        return 124
    fi
    return "$rc"
}

# --- JSON and CSV ---------------------------------------------------------------------------
msp_json_escape() {
    # Prints the argument as the inside of a JSON string: escapes " \ and control characters.
    # Works byte by byte (LC_ALL=C) so UTF-8 text passes through unchanged. Unit-tested in
    # tests/bash/test-json-escape.sh.
    local s=${1-}
    case "$s" in
        *[\"\\]* | *[[:cntrl:]]*) ;;
        *)
            printf '%s' "$s"
            return 0
            ;;
    esac
    local LC_ALL=C
    local out='' c code esc i=0 n=${#s}
    while [ "$i" -lt "$n" ]; do
        c=${s:$i:1}
        # shellcheck disable=SC1003  # '\' is a one-character backslash pattern, not an escaped quote.
        case "$c" in
            '"') out="$out"'\"' ;;
            '\') out="$out"'\\' ;;
            $'\n') out="$out"'\n' ;;
            $'\r') out="$out"'\r' ;;
            $'\t') out="$out"'\t' ;;
            $'\b') out="$out"'\b' ;;
            $'\f') out="$out"'\f' ;;
            [[:cntrl:]])
                printf -v code '%d' "'$c"
                printf -v esc '\\u%04x' "$code"
                out="$out$esc"
                ;;
            *) out="$out$c" ;;
        esac
        i=$((i + 1))
    done
    printf '%s' "$out"
}

msp_json_str() {
    # A complete JSON string value, with quotes.
    printf '"%s"' "$(msp_json_escape "${1-}")"
}

msp_json_obj() {
    # msp_json_obj KEY VALUE [KEY VALUE ...] -> {"KEY":"VALUE",...}
    # Values are strings. Append # to a key to write its value raw (numbers, true/false, or
    # JSON built elsewhere): msp_json_obj Port# 443 Open# true Name "SSH".
    local out='' key val sep=''
    while [ $# -ge 2 ]; do
        key=$1
        val=$2
        shift 2
        case "$key" in
            *'#') out="$out$sep$(msp_json_str "${key%#}"):$val" ;;
            *) out="$out$sep$(msp_json_str "$key"):$(msp_json_str "$val")" ;;
        esac
        sep=','
    done
    printf '{%s}' "$out"
}

msp_csv_field() {
    # One CSV field, always quoted, with embedded quotes doubled (same as Export-Csv).
    local s=${1-}
    case "$s" in
        *\"*) s=$(printf '%s' "$s" | sed 's/"/""/g') ;;
    esac
    printf '"%s"' "$s"
}

msp_id_part() {
    # "Remote-access tool: Kaseya" -> "Remote-access-tool-Kaseya". Must match ConvertTo-MSPIdPart.
    local part
    part=$(printf '%s' "${1-}" | LC_ALL=C sed 's/[^A-Za-z0-9][^A-Za-z0-9]*/-/g; s/^-//; s/-$//')
    [ -n "$part" ] || part='General'
    printf '%s' "$part"
}

msp_json_flatten() {
    # msp_json_flatten FILE - reads JSON (FILE, or - for stdin) and prints one line per value:
    # "<path><TAB><value>", for example  .addons[0].defaultLocale.name<TAB>uBlock Origin
    # Strings are unescaped (\" \\ \/; newlines and tabs become spaces; \uXXXX is kept as text).
    # Lets scripts read browser manifests, policies and plutil -convert json output without jq
    # or python. Splitting records on '"' keeps it linear on large files (Firefox's
    # extensions.json). Malformed JSON gives partial output, never an error.
    awk '
        function unescape(x) {
            gsub(/\\\\/, "\001", x); gsub(/\\"/, "\"", x); gsub(/\\\//, "/", x)
            gsub(/\\[nrt]/, " ", x); gsub(/\\[bf]/, "", x); gsub(/\001/, "\\", x)
            return x
        }
        function path(   d, p) {
            p = ""
            for (d = 1; d <= depth; d++) p = p (type[d] == "o" ? "." key[d] : "[" idx[d] "]")
            return p
        }
        function emit(v) { print path() "\t" v }
        function flush_literal() { if (lit != "") { emit(lit); lit = "" } }
        function outside(t,   i, c) {
            for (i = 1; i <= length(t); i++) {
                c = substr(t, i, 1)
                if (c == "{") { depth++; type[depth] = "o"; expectkey[depth] = 1; key[depth] = "" }
                else if (c == "[") { depth++; type[depth] = "a"; idx[depth] = 0 }
                else if (c == "}" || c == "]") { flush_literal(); depth-- }
                else if (c == ",") { flush_literal(); if (type[depth] == "o") expectkey[depth] = 1; else idx[depth]++ }
                else if (c == ":" || c == " " || c == "\t" || c == "\n" || c == "\r") { flush_literal() }
                else lit = lit c
            }
        }
        BEGIN { RS = "\""; depth = 0; instr = 0; buf = ""; lit = "" }
        {
            if (!instr) { outside($0); instr = 1; next }
            # Inside a string. A record ending in an odd number of backslashes ended at an
            # escaped quote, so the string continues in the next record.
            n = 0; i = length($0); while (i > 0 && substr($0, i, 1) == "\\") { n++; i-- }
            if (n % 2 == 1) { buf = buf $0 "\""; next }
            v = unescape(buf $0); buf = ""; instr = 0
            if (depth > 0 && type[depth] == "o" && expectkey[depth]) { key[depth] = v; expectkey[depth] = 0 }
            else emit(v)
        }
        END { flush_literal() }
    ' "${1:--}"
}

# --- Console output -------------------------------------------------------------------------
msp_color_init() {
    # Colors only on an interactive terminal; plain text when piped, redirected, or NO_COLOR is set.
    MSP_COLOR=0
    if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != "dumb" ]; then MSP_COLOR=1; fi
}

msp_c() {
    # msp_c ANSI_CODE TEXT -> TEXT in color (no newline). Codes: 31 red, 32 green, 33 yellow,
    # 35 magenta, 36 cyan, 90 gray, 1 bold.
    if [ "$MSP_COLOR" -eq 1 ]; then printf '\033[%sm%s\033[0m' "$1" "$2"; else printf '%s' "$2"; fi
}

msp_status_color() {
    case "$1" in
        PASS) printf '32' ;;
        WARN) printf '33' ;;
        FAIL) printf '31' ;;
        INFO) printf '36' ;;
        SKIPPED) printf '90' ;;
        ERROR) printf '35' ;;
        *) printf '0' ;;
    esac
}

msp_say() {
    # msp_say [ANSI_CODE] TEXT -> one console line.
    if [ $# -ge 2 ]; then msp_c "$1" "$2"; else printf '%s' "${1-}"; fi
    printf '\n'
}

# --- Logging --------------------------------------------------------------------------------
msp_log() {
    # msp_log LEVEL MESSAGE. Never fails: a full or locked disk must not stop a diagnostic.
    [ -n "$MSP_LOG_PATH" ] && [ "$MSP_LOG_FAILED" -eq 0 ] || return 0
    if ! printf '%s [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" "$2" >>"$MSP_LOG_PATH" 2>/dev/null; then
        MSP_LOG_FAILED=1
    fi
    return 0
}

msp_param() {
    # msp_param NAME VALUE - records one parameter for the log and JSON. Call before msp_init.
    MSP_PARAM_KEYS[MSP_PARAM_COUNT]=$1
    MSP_PARAM_VALUES[MSP_PARAM_COUNT]=${2-}
    MSP_PARAM_COUNT=$((MSP_PARAM_COUNT + 1))
}

msp_detect_platform() {
    local os
    os=$(uname -s 2>/dev/null)
    case "$os" in
        Darwin)
            MSP_PLATFORM='macOS'
            MSP_OS_VERSION="macOS $(sw_vers -productVersion 2>/dev/null)"
            ;;
        Linux)
            MSP_PLATFORM='Linux'
            MSP_OS_VERSION=$(sed -n 's/^PRETTY_NAME=//p' /etc/os-release 2>/dev/null | head -n 1 | sed 's/^"//; s/"$//')
            [ -n "$MSP_OS_VERSION" ] || MSP_OS_VERSION="Linux $(uname -r 2>/dev/null)"
            ;;
        *)
            MSP_PLATFORM='Other'
            MSP_OS_VERSION=$os
            ;;
    esac
}

msp__log_folder() {
    # ${TMPDIR:-/tmp}/msp-toolkit. If another account (for example root from an earlier sudo run)
    # owns it, use a per-user folder so the log still gets written.
    local base dir
    base=${TMPDIR:-/tmp}
    base=${base%/}
    dir="$base/msp-toolkit"
    if [ -d "$dir" ] && [ ! -w "$dir" ]; then dir="$base/msp-toolkit-$(id -u)"; fi
    (umask 077 && mkdir -p "$dir") 2>/dev/null || return 1
    [ -w "$dir" ] || return 1
    printf '%s' "$dir"
}

msp__cleanup() {
    [ -n "$MSP_WORK_DIR" ] && [ -d "$MSP_WORK_DIR" ] && rm -rf "$MSP_WORK_DIR"
    return 0
}

msp_init() {
    # msp_init SCRIPT_NAME VERSION CHECK_ID RISK DESCRIPTION [ROOT_SECTIONS]
    # Starts a run: log file, start time, host, user, banner. Call once, after msp_param calls.
    # CHECK_ID is the catalog ID (A1, B2, ...), the same on Windows, macOS and Linux.
    # ROOT_SECTIONS names the parts that need sudo, so the banner says so up front.
    # Sets an EXIT trap that removes the run's temporary folder.
    MSP_SCRIPT_NAME=$1
    MSP_SCRIPT_VERSION=$2
    MSP_CHECK_ID=$3
    MSP_RISK=$4
    local description=${5-} root_sections=${6-} stamp dir i
    case "$MSP_RISK" in
        Read-Only | Safe | Elevated | Destructive) ;;
        *)
            printf 'msp_init: invalid risk level "%s"\n' "$MSP_RISK" >&2
            exit 2
            ;;
    esac
    msp_color_init
    msp_detect_platform
    stamp=$(date '+%Y-%m-%dT%H:%M:%S%z %Y%m%d-%H%M%S %s')
    MSP_START_ISO=${stamp%% *}
    MSP_START_ISO="${MSP_START_ISO%??}:${MSP_START_ISO#"${MSP_START_ISO%??}"}"
    stamp=${stamp#* }
    MSP_START_STAMP=${stamp%% *}
    MSP_START_EPOCH=${stamp#* }
    MSP_HOST=$(uname -n 2>/dev/null)
    MSP_HOST=${MSP_HOST%%.*}
    MSP_USER=$(id -un 2>/dev/null)
    MSP_IS_ADMIN='false'
    if msp_is_root; then MSP_IS_ADMIN='true'; fi
    MSP_SHELL="bash ${BASH_VERSION%%(*}"

    MSP_WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/msp-run.XXXXXX" 2>/dev/null) || MSP_WORK_DIR=''
    trap msp__cleanup EXIT
    trap 'exit 130' INT TERM

    MSP_LOG_PATH=''
    if dir=$(msp__log_folder); then
        MSP_LOG_PATH="$dir/${MSP_SCRIPT_NAME}_${MSP_HOST}_${MSP_START_STAMP}.log"
    fi

    msp_log INFO "===== START $MSP_SCRIPT_NAME v$MSP_SCRIPT_VERSION ($MSP_CHECK_ID) ====="
    msp_log INFO "Host=$MSP_HOST; User=$MSP_USER; Elevated=$MSP_IS_ADMIN; Platform=$MSP_PLATFORM; OS=$MSP_OS_VERSION; Shell=$MSP_SHELL; Risk=$MSP_RISK"
    if [ -n "${SUDO_USER:-}" ]; then msp_log INFO "Started with sudo by: $SUDO_USER"; fi
    local params=''
    i=0
    while [ "$i" -lt "$MSP_PARAM_COUNT" ]; do
        params="$params${params:+; }${MSP_PARAM_KEYS[$i]}=${MSP_PARAM_VALUES[$i]}"
        i=$((i + 1))
    done
    msp_log INFO "Parameters: ${params:-(none)}"

    local bar admin_text='No'
    bar=$(msp_repeat '=' 72)
    [ "$MSP_IS_ADMIN" = 'true' ] && admin_text='Yes'
    printf '\n'
    msp_say 36 "$bar"
    msp_say 36 " $MSP_SCRIPT_NAME v$MSP_SCRIPT_VERSION   [$MSP_CHECK_ID]   [Risk: $MSP_RISK]"
    [ -n "$description" ] && msp_say 90 " $description"
    msp_say 90 " Computer: $MSP_HOST ($MSP_OS_VERSION)"
    msp_say 90 " User    : $MSP_USER   Elevated (root/sudo): $admin_text"
    msp_say 90 " Started : $(date '+%Y-%m-%d %H:%M:%S')"
    if [ -n "$MSP_LOG_PATH" ]; then msp_say 90 " Log     : $MSP_LOG_PATH"; else msp_say 90 " Log     : (could not create a log file; console output is complete)"; fi
    msp_say 36 "$bar"
    if [ "$MSP_IS_ADMIN" != 'true' ]; then
        msp_say 90 ' Not running as root (sudo). Checks that need it will show SKIPPED;'
        msp_say 90 ' everything else still runs. This script never asks for a password itself.'
        if [ -n "$root_sections" ]; then msp_say 90 " Needs sudo: $root_sections"; fi
    fi
}

msp_section() {
    # Section heading so long output is easy to follow on a screen share.
    local title="--- $1 " pad
    pad=$((72 - ${#title}))
    [ "$pad" -gt 0 ] || pad=0
    printf '\n'
    msp_say 36 "$title$(msp_repeat '-' "$pad")"
    msp_log INFO "--- $1"
}

# --- Findings -------------------------------------------------------------------------------
msp_finding() {
    # Records one finding and prints it as a colored line.
    #   --status    PASS|WARN|FAIL|INFO|SKIPPED|ERROR (required)
    #   --check     short check name (required)
    #   --detail    what was found
    #   --severity  Critical|High|Medium|Low|Info (default: FAIL High, WARN Medium, else Info)
    #   --rec       recommendation (shown under WARN/FAIL)
    #   --category  area, used in the finding ID (default General)
    #   --target    device the finding is about (default this host)
    #   --id        override the generated <CheckId>.<Category>.<Check> ID
    #   --evidence  a JSON object (build it with msp_json_obj)
    #   --quiet     record and log only, no console line
    local status='' check='' detail='' severity='' rec='' category='General' target='' id='' evidence='' quiet=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --status) status=${2-}; shift; shift ;;
            --check) check=${2-}; shift; shift ;;
            --detail) detail=${2-}; shift; shift ;;
            --severity) severity=${2-}; shift; shift ;;
            --rec) rec=${2-}; shift; shift ;;
            --category) category=${2-}; shift; shift ;;
            --target) target=${2-}; shift; shift ;;
            --id) id=${2-}; shift; shift ;;
            --evidence) evidence=${2-}; shift; shift ;;
            --quiet) quiet=1; shift ;;
            *)
                msp_log ERROR "msp_finding: unknown option '$1' ignored"
                shift
                ;;
        esac
    done
    case "$status" in
        PASS | WARN | FAIL | INFO | SKIPPED | ERROR) ;;
        *)
            msp_log ERROR "msp_finding: invalid status '$status' for '$check'; recorded as ERROR"
            detail="Internal: invalid status '$status'. $detail"
            status='ERROR'
            ;;
    esac
    case "$severity" in
        Critical | High | Medium | Low | Info) ;;
        *)
            case "$status" in
                FAIL) severity='High' ;;
                WARN) severity='Medium' ;;
                *) severity='Info' ;;
            esac
            ;;
    esac
    [ -n "$target" ] || target=$MSP_HOST
    [ -n "$id" ] || id="$MSP_CHECK_ID.$(msp_id_part "$category").$(msp_id_part "$check")"

    local n=$MSP_F_COUNT
    MSP_F_ID[n]=$id
    MSP_F_CATEGORY[n]=$category
    MSP_F_CHECK[n]=$check
    MSP_F_STATUS[n]=$status
    MSP_F_SEVERITY[n]=$severity
    MSP_F_TARGET[n]=$target
    MSP_F_DETAIL[n]=$detail
    MSP_F_REC[n]=$rec
    MSP_F_EVIDENCE[n]=$evidence
    MSP_F_COUNT=$((n + 1))
    msp_log INFO "[$status/$severity] $check | $target | $detail"

    if [ "$quiet" -eq 0 ]; then
        local tag
        tag=$(printf '%-10s' "[$status]")
        printf '  '
        msp_c "$(msp_status_color "$status")" "$tag"
        if [ -n "$detail" ]; then printf '%s - %s\n' "$check" "$detail"; else printf '%s\n' "$check"; fi
        if [ -n "$rec" ] && { [ "$status" = 'WARN' ] || [ "$status" = 'FAIL' ]; }; then
            msp_say 90 "            -> $rec"
        fi
    fi
}

msp_skip() {
    # msp_skip CATEGORY CHECK REASON [HOW_TO_FIX] - records SKIPPED with a plain-English reason.
    msp_finding --status SKIPPED --category "$1" --check "$2" --detail "$3" --rec "${4-}"
}

msp_root_hint() {
    printf 'Re-run with sudo to include this check: sudo bash %s' "${MSP_SCRIPT_FILE:-$MSP_SCRIPT_NAME.sh}"
}

msp_fda_status() {
    # macOS only. Prints granted / missing / unknown for Full Disk Access of the app running
    # this shell (Terminal, iTerm...). Reading the first byte of the system TCC database is
    # only allowed with Full Disk Access; the byte itself is a file header, not data.
    [ "$MSP_PLATFORM" = 'macOS' ] || { printf 'unknown'; return 0; }
    local db='/Library/Application Support/com.apple.TCC/TCC.db'
    if [ ! -e "$db" ]; then printf 'unknown'; return 0; fi
    if head -c 1 "$db" >/dev/null 2>&1; then printf 'granted'; else printf 'missing'; fi
}

msp_fda_hint() {
    printf '%s' 'Grant Full Disk Access to Terminal: System Settings > Privacy & Security > Full Disk Access > turn on Terminal (quit and reopen Terminal), re-run, then turn it off again.'
}

msp_friendly_error() {
    # msp_friendly_error TEXT [EXIT_CODE] -> one plain-English sentence for the ticket.
    local text=${1-} rc=${2-}
    text=$(printf '%s' "$text" | head -n 1)
    case "$text" in
        *'Permission denied'* | *'Operation not permitted'* | *'not permitted'*)
            if [ "$MSP_PLATFORM" = 'macOS' ]; then
                printf '%s' 'macOS denied access for the current account. Running with sudo, or giving Terminal Full Disk Access, may allow it.'
            else
                printf '%s' 'Linux denied access for the current account. Running with sudo may allow it.'
            fi
            ;;
        *'command not found'* | *'No such file or directory'*)
            printf 'A command or file this check needs is not available on this computer (%s). This is normal on some versions.' "$text"
            ;;
        *'timed out'* | *'Timeout'*)
            printf '%s' 'The check took too long to answer and was stopped.'
            ;;
        '')
            if [ "$rc" = '124' ]; then printf '%s' 'The check took too long to answer and was stopped.'
            else printf 'The check could not complete (exit code %s).' "${rc:-unknown}"; fi
            ;;
        *) printf 'The check could not complete: %s' "$text" ;;
    esac
}

msp_check() {
    # msp_check [--root REASON] [--fda REASON] CATEGORY NAME FUNCTION [ARGS...]
    # Runs one check function in the current shell so it can record findings and set variables.
    #   --root: not root -> SKIPPED with REASON and how to re-run with sudo; FUNCTION is not run.
    #   --fda:  macOS without Full Disk Access -> SKIPPED with REASON and how to grant it.
    # If FUNCTION returns non-zero without recording a finding, an ERROR finding explains why in
    # plain English using the first line it wrote to stderr. ERROR means "could not check",
    # never "checked and it is bad" (that is FAIL, which the function records itself).
    local need_root='' need_fda=''
    while [ $# -gt 0 ]; do
        case "$1" in
            --root) need_root=${2-}; shift; shift ;;
            --fda) need_fda=${2-}; shift; shift ;;
            *) break ;;
        esac
    done
    local category=$1 name=$2
    shift 2
    if [ -n "$need_root" ] && [ "$MSP_IS_ADMIN" != 'true' ]; then
        msp_skip "$category" "$name" "Skipped: requires root (sudo). $need_root" "$(msp_root_hint)"
        return 0
    fi
    if [ -n "$need_fda" ] && [ "$(msp_fda_status)" = 'missing' ]; then
        msp_skip "$category" "$name" "Skipped: Terminal does not have Full Disk Access. $need_fda" "$(msp_fda_hint)"
        return 0
    fi
    local before=$MSP_F_COUNT errfile=/dev/null rc
    [ -n "$MSP_WORK_DIR" ] && errfile="$MSP_WORK_DIR/check.err"
    msp_log INFO "Check start: $name"
    "$@" 2>"$errfile"
    rc=$?
    if [ "$rc" -ne 0 ]; then
        local errtext=''
        [ "$errfile" != /dev/null ] && errtext=$(head -n 1 "$errfile" 2>/dev/null)
        msp_log ERROR "Check error in \"$name\": exit $rc: $errtext"
        if [ "$MSP_F_COUNT" -eq "$before" ]; then
            msp_finding --status ERROR --severity Info --category "$category" --check "$name" \
                --detail "$(msp_friendly_error "$errtext" "$rc")" \
                --rec 'This check could not run; the other results are still valid. If it matters for this ticket, re-run with sudo or escalate with the log file.'
        fi
    fi
    return 0
}

# --- Data tables ----------------------------------------------------------------------------
MSP__DATA_IDX=0
msp__data_sync() {
    # Reloads the table names from the run folder. Names are kept in a file, not only in
    # MSP_DATA_NAMES, because rows are often added inside a pipeline ("... | while read"),
    # which runs in a subshell: a table created there would otherwise be unknown to the main
    # script (left out of the export, and its index reused by the next new table).
    local n
    MSP_DATA_COUNT=0
    MSP_DATA_NAMES=()
    [ -n "$MSP_WORK_DIR" ] && [ -f "$MSP_WORK_DIR/data_names" ] || return 0
    while IFS= read -r n; do
        MSP_DATA_NAMES[MSP_DATA_COUNT]=$n
        MSP_DATA_COUNT=$((MSP_DATA_COUNT + 1))
    done <"$MSP_WORK_DIR/data_names"
}

msp__data_index() {
    # Sets MSP__DATA_IDX to the index of table NAME, creating it if needed (bash 3.2 has no
    # associative arrays). Sets a global instead of printing: $(...) would run in a subshell
    # and lose a newly created table.
    local i=0
    msp__data_sync
    while [ "$i" -lt "$MSP_DATA_COUNT" ]; do
        if [ "${MSP_DATA_NAMES[$i]}" = "$1" ]; then MSP__DATA_IDX=$i; return 0; fi
        i=$((i + 1))
    done
    printf '%s\n' "$1" >>"$MSP_WORK_DIR/data_names"
    MSP_DATA_NAMES[MSP_DATA_COUNT]=$1
    MSP__DATA_IDX=$MSP_DATA_COUNT
    MSP_DATA_COUNT=$((MSP_DATA_COUNT + 1))
}

msp_data_row() {
    # msp_data_row TABLE KEY VALUE [KEY VALUE ...] - adds one row to a table for JSON/CSV export.
    # Every row of a table must use the same keys in the same order (they become CSV columns).
    # Keys ending in # are written raw in JSON (numbers, true/false).
    [ -n "$MSP_WORK_DIR" ] || return 0
    local table=$1 idx header='' row='' sep='' key
    shift
    msp__data_index "$table"
    idx=$MSP__DATA_IDX
    local args_json
    args_json=$(msp_json_obj "$@")
    while [ $# -ge 2 ]; do
        key=${1%#}
        header="$header$sep$(msp_csv_field "$key")"
        row="$row$sep$(msp_csv_field "$2")"
        sep=','
        shift 2
    done
    if [ ! -f "$MSP_WORK_DIR/data_$idx.csv" ]; then printf '%s\n' "$header" >"$MSP_WORK_DIR/data_$idx.csv"; fi
    printf '%s\n' "$row" >>"$MSP_WORK_DIR/data_$idx.csv"
    printf '%s\n' "$args_json" >>"$MSP_WORK_DIR/data_$idx.jsonl"
}

# --- Summary, ticket block, export -----------------------------------------------------------
msp_count_status() {
    local i=0 c=0
    while [ "$i" -lt "$MSP_F_COUNT" ]; do
        [ "${MSP_F_STATUS[$i]}" = "$1" ] && c=$((c + 1))
        i=$((i + 1))
    done
    printf '%s' "$c"
}

msp__severity_rank() {
    case "$1" in Critical) printf 0 ;; High) printf 1 ;; Medium) printf 2 ;; Low) printf 3 ;; *) printf 4 ;; esac
}

msp_sorted_issues() {
    # Indexes of WARN/FAIL findings, most severe first (FAIL before WARN at equal severity).
    local i=0 s
    while [ "$i" -lt "$MSP_F_COUNT" ]; do
        s=${MSP_F_STATUS[$i]}
        if [ "$s" = 'FAIL' ] || [ "$s" = 'WARN' ]; then
            if [ "$s" = 'FAIL' ]; then s=0; else s=1; fi
            printf '%s %s %05d\n' "$(msp__severity_rank "${MSP_F_SEVERITY[$i]}")" "$s" "$i"
        fi
        i=$((i + 1))
    done | sort | awk '{ print $3 + 0 }'
}

msp_ticket_text() {
    # Plain-text block (no colors) for pasting into a ticket. Same layout as the PowerShell helper.
    local now duration admin_text='No' i shown=0 total target text max=40
    now=$(date +%s)
    duration=$((now - MSP_START_EPOCH))
    [ "$MSP_IS_ADMIN" = 'true' ] && admin_text='Yes'
    printf '[MSP Toolkit] %s %s v%s | Risk: %s\n' "$MSP_CHECK_ID" "$MSP_SCRIPT_NAME" "$MSP_SCRIPT_VERSION" "$MSP_RISK"
    printf 'Computer: %s (%s) | User: %s | Elevated: %s | Run: %s (%ss)\n' "$MSP_HOST" "$MSP_OS_VERSION" "$MSP_USER" "$admin_text" \
        "$(printf '%s' "$MSP_START_ISO" | sed 's/T/ /; s/:[0-9][0-9][-+].*$//')" "$duration"
    printf 'Result: PASS %s | WARN %s | FAIL %s | INFO %s | SKIPPED %s | ERROR %s\n' \
        "$(msp_count_status PASS)" "$(msp_count_status WARN)" "$(msp_count_status FAIL)" \
        "$(msp_count_status INFO)" "$(msp_count_status SKIPPED)" "$(msp_count_status ERROR)"
    local issues
    issues=$(msp_sorted_issues)
    if [ -n "$issues" ]; then
        total=$(printf '%s\n' "$issues" | wc -l | tr -d ' ')
        printf 'Issues (most severe first):\n'
        for i in $issues; do
            if [ "$shown" -ge "$max" ]; then
                printf '  ... %s more issue(s) - see the exported CSV/JSON or the log.\n' "$((total - shown))"
                break
            fi
            target=''
            [ "${MSP_F_TARGET[$i]}" != "$MSP_HOST" ] && target=" [${MSP_F_TARGET[$i]}]"
            text="  - [${MSP_F_STATUS[$i]}/${MSP_F_SEVERITY[$i]}] ${MSP_F_CHECK[$i]}$target: ${MSP_F_DETAIL[$i]}"
            [ -n "${MSP_F_REC[$i]}" ] && text="$text Action: ${MSP_F_REC[$i]}"
            printf '%s\n' "$text"
            shown=$((shown + 1))
        done
    else
        printf 'Issues: none found by the checks that ran.\n'
    fi
    if [ "$(msp_count_status ERROR)" -gt 0 ]; then
        printf 'Could not run (ERROR - not the same as a failed check):\n'
        i=0
        while [ "$i" -lt "$MSP_F_COUNT" ]; do
            [ "${MSP_F_STATUS[$i]}" = 'ERROR' ] && printf '  - %s: %s\n' "${MSP_F_CHECK[$i]}" "${MSP_F_DETAIL[$i]}"
            i=$((i + 1))
        done
    fi
    if [ "$(msp_count_status SKIPPED)" -gt 0 ]; then
        printf 'Skipped:\n'
        i=0
        while [ "$i" -lt "$MSP_F_COUNT" ]; do
            [ "${MSP_F_STATUS[$i]}" = 'SKIPPED' ] && printf '  - %s: %s\n' "${MSP_F_CHECK[$i]}" "${MSP_F_DETAIL[$i]}"
            i=$((i + 1))
        done
    fi
    if [ -n "$MSP_LOG_PATH" ] && [ "$MSP_LOG_FAILED" -eq 0 ]; then printf 'Log: %s\n' "$MSP_LOG_PATH"; fi
    return 0
}

msp_print_summary() {
    local bar s c color issues i shown=0 total
    bar=$(msp_repeat '=' 72)
    printf '\n'
    msp_say 36 "$bar"
    msp_c 36 ' SUMMARY  '
    for s in PASS WARN FAIL INFO SKIPPED ERROR; do
        c=$(msp_count_status "$s")
        color=90
        [ "$c" -gt 0 ] && color=$(msp_status_color "$s")
        msp_c "$color" "$s: $c   "
    done
    printf '\n'
    msp_say 36 "$bar"
    issues=$(msp_sorted_issues)
    if [ -n "$issues" ]; then
        total=$(printf '%s\n' "$issues" | wc -l | tr -d ' ')
        msp_say 1 ' Most important items:'
        for i in $issues; do
            [ "$shown" -ge 10 ] && break
            printf '  '
            msp_c "$(msp_status_color "${MSP_F_STATUS[$i]}")" "[${MSP_F_STATUS[$i]}/${MSP_F_SEVERITY[$i]}] "
            printf '%s: %s\n' "${MSP_F_CHECK[$i]}" "${MSP_F_DETAIL[$i]}"
            shown=$((shown + 1))
        done
        [ "$total" -gt 10 ] && msp_say 90 "  ... and $((total - 10)) more (see ticket block below)."
    else
        msp_say 32 ' No WARN or FAIL items from the checks that ran.'
    fi
    c=$(msp_count_status ERROR)
    if [ "$c" -gt 0 ]; then
        msp_say 35 " $c check(s) could not run (ERROR). That is not a failed check - see details above."
    fi
    local ticket
    ticket=$(msp_ticket_text)
    printf '\n'
    msp_say 1 "----- COPY FOR TICKET (plain text) $(msp_repeat '-' 37)"
    printf '%s\n' "$ticket"
    msp_say 1 "$(msp_repeat '-' 72)"
    msp_log INFO "Ticket block:"
    msp_log INFO "$ticket"
}

msp_json_result() {
    # The full result as JSON (schema 2.0). Field names and order match Get-MSPResultObject.
    local i sep='' t f
    printf '{\n'
    printf '  "SchemaVersion": %s,\n' "$(msp_json_str "$MSP_SCHEMA_VERSION")"
    printf '  "CheckId": %s,\n' "$(msp_json_str "$MSP_CHECK_ID")"
    printf '  "ScriptName": %s,\n' "$(msp_json_str "$MSP_SCRIPT_NAME")"
    printf '  "Version": %s,\n' "$(msp_json_str "$MSP_SCRIPT_VERSION")"
    printf '  "Platform": %s,\n' "$(msp_json_str "$MSP_PLATFORM")"
    printf '  "OSVersion": %s,\n' "$(msp_json_str "$MSP_OS_VERSION")"
    printf '  "Shell": %s,\n' "$(msp_json_str "$MSP_SHELL")"
    printf '  "Host": %s,\n' "$(msp_json_str "$MSP_HOST")"
    printf '  "User": %s,\n' "$(msp_json_str "$MSP_USER")"
    printf '  "IsAdmin": %s,\n' "$MSP_IS_ADMIN"
    printf '  "RiskLevel": %s,\n' "$(msp_json_str "$MSP_RISK")"
    printf '  "Parameters": {'
    i=0
    while [ "$i" -lt "$MSP_PARAM_COUNT" ]; do
        printf '%s%s: %s' "$sep" "$(msp_json_str "${MSP_PARAM_KEYS[$i]}")" "$(msp_json_str "${MSP_PARAM_VALUES[$i]}")"
        sep=', '
        i=$((i + 1))
    done
    printf '},\n'
    printf '  "Timestamp": %s,\n' "$(msp_json_str "$MSP_START_ISO")"
    printf '  "EndTime": %s,\n' "$(msp_json_str "${MSP_END_ISO:-$(msp_iso_time)}")"
    printf '  "Summary": {"PASS": %s, "WARN": %s, "FAIL": %s, "INFO": %s, "SKIPPED": %s, "ERROR": %s},\n' \
        "$(msp_count_status PASS)" "$(msp_count_status WARN)" "$(msp_count_status FAIL)" \
        "$(msp_count_status INFO)" "$(msp_count_status SKIPPED)" "$(msp_count_status ERROR)"
    printf '  "Findings": ['
    i=0
    sep=''
    while [ "$i" -lt "$MSP_F_COUNT" ]; do
        printf '%s\n    {"Id": %s, "Category": %s, "Check": %s, "Status": %s, "Severity": %s, "Target": %s, "Detail": %s, "Recommendation": %s, "Evidence": %s}' \
            "$sep" "$(msp_json_str "${MSP_F_ID[$i]}")" "$(msp_json_str "${MSP_F_CATEGORY[$i]}")" \
            "$(msp_json_str "${MSP_F_CHECK[$i]}")" "$(msp_json_str "${MSP_F_STATUS[$i]}")" \
            "$(msp_json_str "${MSP_F_SEVERITY[$i]}")" "$(msp_json_str "${MSP_F_TARGET[$i]}")" \
            "$(msp_json_str "${MSP_F_DETAIL[$i]}")" "$(msp_json_str "${MSP_F_REC[$i]}")" \
            "${MSP_F_EVIDENCE[$i]:-null}"
        sep=','
        i=$((i + 1))
    done
    [ "$MSP_F_COUNT" -gt 0 ] && printf '\n  '
    printf '],\n'
    printf '  "Data": {'
    msp__data_sync
    i=0
    sep=''
    while [ "$i" -lt "$MSP_DATA_COUNT" ]; do
        t=${MSP_DATA_NAMES[$i]}
        f="$MSP_WORK_DIR/data_$i.jsonl"
        printf '%s\n    %s: [' "$sep" "$(msp_json_str "$t")"
        if [ -f "$f" ]; then
            # Join the stored one-object-per-line rows with commas.
            awk 'NR > 1 { printf "," } { printf "\n      %s", $0 }' "$f"
            printf '\n    '
        fi
        printf ']'
        sep=','
        i=$((i + 1))
    done
    [ "$MSP_DATA_COUNT" -gt 0 ] && printf '\n  '
    printf '}\n'
    printf '}\n'
}

msp_export() {
    # msp_export FOLDER - writes <Script>_<Host>_<yyyyMMdd-HHmmss>.json, ..._findings.csv and
    # ..._<Table>.csv for each data table. Prints where the files went.
    local folder=$1 base json csv i name dst
    mkdir -p "$folder" 2>/dev/null || { printf 'cannot create folder\n' >&2; return 1; }
    folder=$(cd "$folder" && pwd) || return 1
    base="$folder/${MSP_SCRIPT_NAME}_${MSP_HOST}_${MSP_START_STAMP}"
    json="$base.json"
    csv="${base}_findings.csv"
    msp__data_sync
    msp_json_result >"$json" || return 1
    {
        printf '"CheckId","ScriptName","Platform","Host","Timestamp","Id","Category","Check","Status","Severity","Target","Detail","Recommendation"\n'
        i=0
        while [ "$i" -lt "$MSP_F_COUNT" ]; do
            printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
                "$(msp_csv_field "$MSP_CHECK_ID")" "$(msp_csv_field "$MSP_SCRIPT_NAME")" "$(msp_csv_field "$MSP_PLATFORM")" \
                "$(msp_csv_field "$MSP_HOST")" "$(msp_csv_field "$MSP_START_ISO")" "$(msp_csv_field "${MSP_F_ID[$i]}")" \
                "$(msp_csv_field "${MSP_F_CATEGORY[$i]}")" "$(msp_csv_field "${MSP_F_CHECK[$i]}")" \
                "$(msp_csv_field "${MSP_F_STATUS[$i]}")" "$(msp_csv_field "${MSP_F_SEVERITY[$i]}")" \
                "$(msp_csv_field "${MSP_F_TARGET[$i]}")" "$(msp_csv_field "${MSP_F_DETAIL[$i]}")" \
                "$(msp_csv_field "${MSP_F_REC[$i]}")"
            i=$((i + 1))
        done
    } >"$csv" || return 1
    printf '\n'
    msp_say 32 ' Results saved:'
    msp_say 90 "   $json"
    msp_say 90 "   $csv"
    i=0
    while [ "$i" -lt "$MSP_DATA_COUNT" ]; do
        if [ -f "$MSP_WORK_DIR/data_$i.csv" ]; then
            name=$(printf '%s' "${MSP_DATA_NAMES[$i]}" | LC_ALL=C sed 's/[^A-Za-z0-9]//g')
            dst="${base}_$name.csv"
            cp "$MSP_WORK_DIR/data_$i.csv" "$dst" && msp_say 90 "   $dst"
        fi
        i=$((i + 1))
    done
    msp_log INFO "Exported: $json; $csv"
    return 0
}

msp_complete() {
    # msp_complete [OUTPUT_FOLDER] - prints the summary and ticket block, exports if a folder
    # was given, and writes the end of the log. Findings never change the exit code; the exit
    # code only says whether the script itself ran.
    local out=${1-} err errf
    MSP_END_ISO=$(msp_iso_time)
    msp_print_summary
    if [ -n "$out" ]; then
        errf="${MSP_WORK_DIR:-${TMPDIR:-/tmp}}/export.$$.err"
        if ! msp_export "$out" 2>"$errf"; then
            err=$(head -n 1 "$errf" 2>/dev/null)
            msp_say 31 " Could not save results to \"$out\": ${err:-unknown error}"
            msp_say 31 ' The console output and log above are still complete.'
            msp_log ERROR "Export failed: $err"
        fi
    fi
    local duration
    duration=$(($(date +%s) - MSP_START_EPOCH))
    msp_log INFO "===== END $(date '+%Y-%m-%d %H:%M:%S') | duration ${duration}s | PASS $(msp_count_status PASS) WARN $(msp_count_status WARN) FAIL $(msp_count_status FAIL) INFO $(msp_count_status INFO) SKIPPED $(msp_count_status SKIPPED) ERROR $(msp_count_status ERROR) ====="
    if [ -n "$MSP_LOG_PATH" ] && [ "$MSP_LOG_FAILED" -eq 0 ]; then msp_say 90 " Log file: $MSP_LOG_PATH"; fi
    printf '\n'
}
#endregion MSPHelper:Core
#endregion MSPToolkit (generated)

SCRIPT_VERSION='1.0.0'
OUTPUT=''
PASSIVE=0
SCAN_LAN=0
HOME_SSID=''
ONLINE=0
ROUTER_CHECKLIST=0
APPROVED=''
APPROVED_GIVEN=0
ALL_USERS=0
SKIP=''
TIMEOUT_MINUTES=15
TECHNICIAN=''
CLIENT=''
need_value() {
    [ -n "${2-}" ] || { printf 'Missing value after %s\n' "$1" >&2; exit 2; }
}
while [ $# -gt 0 ]; do
    case "$1" in
        --output) need_value "$1" "${2-}"; OUTPUT=$2; shift 2 ;;
        --passive) PASSIVE=1; shift ;;
        --scan-lan) SCAN_LAN=1; shift ;;
        --home-ssid) need_value "$1" "${2-}"; HOME_SSID=$2; shift 2 ;;
        --online) ONLINE=1; shift ;;
        --include-router-checklist) ROUTER_CHECKLIST=1; shift ;;
        --approved-remote-tool) APPROVED=${2-}; APPROVED_GIVEN=1; shift; [ $# -gt 0 ] && shift ;;
        --all-users) ALL_USERS=1; shift ;;
        --skip) need_value "$1" "${2-}"; SKIP=$2; shift 2 ;;
        --timeout-minutes)
            need_value "$1" "${2-}"
            case "$2" in
                *[!0-9]*) printf -- '--timeout-minutes must be a number from 2 to 60\n' >&2; exit 2 ;;
            esac
            if [ "$2" -lt 2 ] || [ "$2" -gt 60 ]; then printf -- '--timeout-minutes must be a number from 2 to 60\n' >&2; exit 2; fi
            TIMEOUT_MINUTES=$2
            shift 2
            ;;
        --technician) need_value "$1" "${2-}"; TECHNICIAN=$2; shift 2 ;;
        --client) need_value "$1" "${2-}"; CLIENT=$2; shift 2 ;;
        -h | --help)
            awk 'NR > 2 && /^#/ { sub(/^# ?/, ""); print; next } NR > 2 { exit }' "$0"
            exit 0
            ;;
        *)
            printf 'Unknown option: %s (see --help)\n' "$1" >&2
            exit 2
            ;;
    esac
done
if [ "$PASSIVE" -eq 1 ] && { [ "$SCAN_LAN" -eq 1 ] || [ "$ONLINE" -eq 1 ]; }; then
    printf -- '--passive cannot be combined with --scan-lan or --online (both send network traffic)\n' >&2
    exit 2
fi

[ -n "$OUTPUT" ] && msp_param Output "$OUTPUT"
[ "$PASSIVE" -eq 1 ] && msp_param Passive 1
[ "$SCAN_LAN" -eq 1 ] && msp_param ScanLan 1
[ -n "$HOME_SSID" ] && msp_param HomeSsid "$HOME_SSID"
[ "$ONLINE" -eq 1 ] && msp_param Online 1
[ "$ROUTER_CHECKLIST" -eq 1 ] && msp_param IncludeRouterChecklist 1
[ "$APPROVED_GIVEN" -eq 1 ] && msp_param ApprovedRemoteTool "$APPROVED"
[ "$ALL_USERS" -eq 1 ] && msp_param AllUsers 1
[ -n "$SKIP" ] && msp_param Skip "$SKIP"
msp_param TimeoutMinutes "$TIMEOUT_MINUTES"
[ -n "$TECHNICIAN" ] && msp_param TechnicianName "$TECHNICIAN"
[ -n "$CLIENT" ] && msp_param ClientName "$CLIENT"
msp_init 'run-home-audit-bundle' "$SCRIPT_VERSION" 'Bundle' 'Read-Only' 'Home network audit: runs A1-A8 and collects the results' \
    'parts of A1, A3, A5 and A8 (each script says which)'

HERE=$(cd "$(dirname "$0")" 2>/dev/null && pwd)
REPO_ROOT=$(cd "$HERE/../.." 2>/dev/null && pwd)
case "$MSP_PLATFORM" in
    macOS) SUFFIX='macos' ;;
    Linux) SUFFIX='linux' ;;
    *) SUFFIX='' ;;
esac

# Run order: ID|script name|repository folder.
PLAN="A1|get-endpoint-security-status-$SUFFIX|security-operations/diagnostics/endpoint-posture
A2|get-home-network-map|core-infrastructure/networking/diagnostics
A3|get-wifi-security-audit-$SUFFIX|core-infrastructure/networking/diagnostics
A4|get-open-port-scan|security-operations/diagnostics/endpoint-posture
A5|get-browser-security-check|endpoint-systems/diagnostics/system-info
A6|get-update-compliance-$SUFFIX|endpoint-systems/diagnostics/system-info
A7|get-router-security-check|core-infrastructure/networking/diagnostics
A8|get-home-device-inventory|endpoint-systems/audit/software-inventory"

find_script() {
    # find_script NAME FOLDER - same folder as this script first (flat USB copy), then the
    # repository layout. Never anything under _archive.
    local c
    for c in "$HERE/$1.sh" "$REPO_ROOT/$2/$1.sh"; do
        case "$c" in */_archive/*) continue ;; esac
        if [ -f "$c" ]; then printf '%s' "$c"; return 0; fi
    done
    return 1
}

is_skipped() {
    # is_skipped ID NAME - true when --skip names the script (with or without .sh) or its ID.
    local item
    for item in $(printf '%s' "$SKIP" | tr ',' ' '); do
        item=${item%.sh}
        [ "$item" = "$1" ] || [ "$item" = "$2" ] && return 0
    done
    return 1
}

# =========================================================================================
msp_section 'Setup'
# =========================================================================================
if [ -z "$SUFFIX" ]; then
    msp_finding --status ERROR --category 'Setup' --check 'Platform' \
        --detail "This runner is for macOS and Linux; this computer reports '$MSP_OS_VERSION'." \
        --rec 'On Windows, run Invoke-HomeAuditBundle.ps1 instead.'
    msp_complete
    exit 1
fi
RUN_FOLDER=''
make_run_folder() {
    local parent=$OUTPUT folder
    if [ -z "$parent" ]; then parent=$(msp__log_folder) || { printf 'cannot create %s\n' "${TMPDIR:-/tmp}/msp-toolkit" >&2; return 1; }; fi
    folder="$parent/HomeAudit_${MSP_HOST}_$(date '+%Y%m%d-%H%M%S')"
    (umask 077 && mkdir -p "$folder") || return 1
    RUN_FOLDER=$(cd "$folder" && pwd) || return 1
    msp_finding --status INFO --category 'Setup' --check 'Results folder' --detail "$RUN_FOLDER"
}
msp_check 'Setup' 'Results folder' make_run_folder
if [ -z "$RUN_FOLDER" ]; then
    msp_complete
    exit 1
fi
if [ "$MSP_IS_ADMIN" != 'true' ]; then
    msp_finding --status INFO --category 'Setup' --check 'Administrator' \
        --detail 'Not running with sudo: FileVault/firewall details, saved Wi-Fi security types, other users and some Linux checks will show SKIPPED. For complete results, re-run with sudo bash.'
fi
if [ "$ALL_USERS" -eq 1 ] && [ "$MSP_IS_ADMIN" != 'true' ]; then
    msp_finding --status INFO --category 'Setup' --check 'All users' --detail '--all-users needs sudo; other users are not included in this run.'
fi
if [ "$PASSIVE" -eq 1 ]; then
    msp_finding --status INFO --category 'Setup' --check 'Passive mode' \
        --detail 'Nothing is sent on the network: A2 reads the ARP table only and A7 (router) is not run.'
fi

# =========================================================================================
MARKER="${MSP_WORK_DIR:-$RUN_FOLDER}/started"
COMPLETED=0
STEP=0
TOTAL=$(printf '%s\n' "$PLAN" | grep -c .)
while IFS='|' read -r ID NAME FOLDER; do
    [ -n "$ID" ] || continue
    STEP=$((STEP + 1))
    msp_section "[$STEP/$TOTAL] $ID $NAME"
    if is_skipped "$ID" "$NAME"; then
        msp_finding --status SKIPPED --category 'Run' --check "$NAME" --detail 'Skipped with --skip.'
        msp_data_row 'Runs' Step# "$STEP" CheckId "$ID" Script "$NAME" Result 'Skipped' Seconds# 0 PASS '' WARN '' FAIL '' ERROR ''
        continue
    fi
    if [ "$ID" = 'A7' ] && [ "$PASSIVE" -eq 1 ]; then
        msp_finding --status SKIPPED --category 'Run' --check "$NAME" --detail 'Not run with --passive: every router check sends traffic to the router.'
        msp_data_row 'Runs' Step# "$STEP" CheckId "$ID" Script "$NAME" Result 'Skipped (passive)' Seconds# 0 PASS '' WARN '' FAIL '' ERROR ''
        continue
    fi
    if ! SCRIPT=$(find_script "$NAME" "$FOLDER"); then
        msp_finding --status ERROR --category 'Run' --check "$NAME" --detail "Script file $NAME.sh was not found next to this script or in $FOLDER." \
            --rec 'Copy the complete toolkit folder (without _archive) and run again.'
        msp_data_row 'Runs' Step# "$STEP" CheckId "$ID" Script "$NAME" Result 'Not found' Seconds# 0 PASS '' WARN '' FAIL '' ERROR ''
        continue
    fi

    # Script-specific options.
    set -- "$SCRIPT" --output "$RUN_FOLDER"
    case "$ID" in
        A2) [ "$PASSIVE" -eq 1 ] && set -- "$@" --passive ;;
        A3) [ -n "$HOME_SSID" ] && set -- "$@" --home-ssid "$HOME_SSID" ;;
        A4) [ "$SCAN_LAN" -eq 1 ] && set -- "$@" --scan-lan ;;
        A5) [ "$ALL_USERS" -eq 1 ] && [ "$MSP_IS_ADMIN" = 'true' ] && set -- "$@" --all-users ;;
        A6) [ "$ONLINE" -eq 1 ] && set -- "$@" --online ;;
        A7) [ "$ROUTER_CHECKLIST" -eq 1 ] || set -- "$@" --skip-checklist-prompt ;;
        A8)
            [ "$APPROVED_GIVEN" -eq 1 ] && set -- "$@" --approved-remote-tool "$APPROVED"
            [ "$ALL_USERS" -eq 1 ] && [ "$MSP_IS_ADMIN" = 'true' ] && [ "$MSP_PLATFORM" = 'macOS' ] && set -- "$@" --all-users
            ;;
    esac
    msp_log INFO "Starting $NAME: bash $*"

    : >"$MARKER"
    STARTED=$(date +%s)
    REASON=''
    if [ "$ID" = 'A7' ] && [ "$ROUTER_CHECKLIST" -eq 1 ] && { : </dev/tty; } 2>/dev/null; then
        # The checklist questions need the keyboard and take as long as they take: no time
        # limit. Without a terminal A7 records the items as "Not verified" itself.
        bash "$@" </dev/tty
        RC=$?
    else
        msp_run_timeout $((TIMEOUT_MINUTES * 60)) bash "$@"
        RC=$?
    fi
    SECONDS_TAKEN=$(($(date +%s) - STARTED))
    if [ "$RC" -eq 124 ]; then REASON="stopped after the $TIMEOUT_MINUTES-minute time limit"
    elif [ "$RC" -ne 0 ]; then REASON="exited with code $RC"; fi

    # The newest results file this script wrote during this run.
    JSON=$(find "$RUN_FOLDER" -maxdepth 1 -name "${NAME}_*.json" -newer "$MARKER" 2>/dev/null | sort | tail -n 1)
    S_PASS='' S_WARN='' S_FAIL='' S_ERROR=''
    if [ -n "$JSON" ]; then
        # shellcheck disable=SC2046  # Splits the four numbers into $1-$4.
        set -- $(sed -n 's/.*"Summary": {"PASS": \([0-9]*\), "WARN": \([0-9]*\), "FAIL": \([0-9]*\), "INFO": [0-9]*, "SKIPPED": [0-9]*, "ERROR": \([0-9]*\)}.*/\1 \2 \3 \4/p' "$JSON" | head -n 1)
        S_PASS=${1-} S_WARN=${2-} S_FAIL=${3-} S_ERROR=${4-}
    elif [ -z "$REASON" ]; then
        REASON='finished but saved no results file'
    fi

    if [ -z "$REASON" ]; then
        COMPLETED=$((COMPLETED + 1))
        msp_finding --status INFO --category 'Run' --check "$NAME" --quiet \
            --detail "Completed in ${SECONDS_TAKEN}s: PASS $S_PASS, WARN $S_WARN, FAIL $S_FAIL, ERROR $S_ERROR."
        RESULT='Completed'
    else
        msp_finding --status ERROR --category 'Run' --check "$NAME" --detail "Did not complete ($REASON). The other scripts still ran." \
            --rec "Run $NAME.sh on its own to see the problem; its log is in ${TMPDIR:-/tmp}/msp-toolkit."
        RESULT="FAILED: $REASON"
    fi
    msp_data_row 'Runs' Step# "$STEP" CheckId "$ID" Script "$NAME" Result "$RESULT" Seconds# "$SECONDS_TAKEN" \
        PASS "$S_PASS" WARN "$S_WARN" FAIL "$S_FAIL" ERROR "$S_ERROR"
done <<EOF
$PLAN
EOF

# =========================================================================================
msp_section 'Bundle results'
# =========================================================================================
RUNS_CSV=''
msp__data_index 'Runs'
[ -n "$MSP_WORK_DIR" ] && RUNS_CSV="$MSP_WORK_DIR/data_$MSP__DATA_IDX.csv"
if [ -n "$RUNS_CSV" ] && [ -f "$RUNS_CSV" ]; then
    # Columns: Step, CheckId, Script, Result, Seconds, PASS, WARN, FAIL, ERROR (all quoted).
    awk '{ gsub(/^"|"$/, ""); n = split($0, f, /","/); printf "  %-4s %-7s %-36s %7s %5s %5s %5s %5s  %s\n", f[1], f[2], f[3], f[5], f[6], f[7], f[8], f[9], f[4] }' "$RUNS_CSV"
fi
printf '\n'
msp_say 32 " All results are in: $RUN_FOLDER"
msp_complete "$RUN_FOLDER"

REPORT_SCRIPT=''
for c in "$HERE/Export-SecurityAuditReport.ps1" "$REPO_ROOT/security-operations/diagnostics/Export-SecurityAuditReport.ps1"; do
    case "$c" in */_archive/*) continue ;; esac
    if [ -f "$c" ]; then REPORT_SCRIPT=$c; break; fi
done
if [ -n "$TECHNICIAN" ]; then
    if [ -n "$REPORT_SCRIPT" ] && msp_have pwsh; then
        set -- -NoProfile -File "$REPORT_SCRIPT" -InputPath "$RUN_FOLDER" -TechnicianName "$TECHNICIAN"
        [ -n "$CLIENT" ] && set -- "$@" -ClientName "$CLIENT"
        pwsh "$@" || msp_say 31 ' The HTML report could not be created; see the messages above.'
    elif [ -z "$REPORT_SCRIPT" ]; then
        msp_say 33 ' Export-SecurityAuditReport.ps1 was not found, so no HTML report was created.'
    else
        msp_say 33 ' PowerShell 7 (pwsh) is not installed, so no HTML report was created. Copy the results folder'
        msp_say 33 ' to a computer with PowerShell (Windows, or pwsh on macOS/Linux) and run:'
        msp_say 90 "   pwsh -File Export-SecurityAuditReport.ps1 -InputPath \"<results folder>\" -TechnicianName \"$TECHNICIAN\""
    fi
else
    msp_say 90 " To build the HTML report: pwsh -File \"${REPORT_SCRIPT:-Export-SecurityAuditReport.ps1}\" -InputPath \"$RUN_FOLDER\" -TechnicianName \"<your name>\""
fi

# Exit 1 only if no audit script completed; individual failures are in the summary above.
[ "$COMPLETED" -gt 0 ] || exit 1
exit 0
