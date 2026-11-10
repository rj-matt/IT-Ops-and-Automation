#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2329  # The embedded helper defines globals and functions this script does not use; checks run through msp_check.
# get-performance-snapshot.sh - read-only "why is this computer slow?" snapshot for a Mac or Linux
# computer: CPU, memory and disk sampled over a short window, the busiest processes, memory
# pressure, startup load, uptime and pending restart, throttling and power settings, known
# slow-down causes, and the next step for what it found. Changes nothing. The Windows version is
# Get-PerformanceSnapshot.ps1 (same checks and finding IDs).
#
# Usage:  bash get-performance-snapshot.sh [--seconds N] [--top N] [--output DIR] [--help]
#
# Options:
#   --seconds N   How long to sample (5-120, default 30), every 2 seconds.
#   --top N       How many processes to list by CPU and by memory (3-20, default 5).
#   --output DIR  Also save results as JSON and CSV (toolkit schema 2.0) with Samples, TopCpu,
#                 TopMemory, Startup and NextSteps tables.
#   --help        Show this help.
#
# Checks
#   CPU               Average and peak use over the window; average 85 % or more = WARN.
#   Memory            Linux: in use from MemAvailable (90 % or more, or under 500 MB available =
#                     WARN). macOS: memory pressure level and free percentage (memory_pressure).
#   Memory pressure   Swapping during the window (100 pages/s or more = WARN); Linux PSI
#                     (memory "some" 10 % or more = WARN); macOS pressure level warn/critical.
#   Disk activity     Linux: busy time of each disk (95 % or more = WARN, "disk at 100 %").
#                     macOS does not report disk busy time (SKIPPED).
#   Top processes     The busiest processes by CPU over the window and by memory.
#   Startup programs  macOS: third-party launch agents and daemons; Linux: desktop autostart
#                     entries (more than 15 = WARN) and enabled services. The heaviest running.
#   Uptime            More than 30 days = WARN. Restart pending: Linux reboot-required /
#                     needs-restarting (macOS has no such flag: INFO).
#   Throttling/power  macOS: pmset thermal speed limit, Low Power Mode, battery. Linux: CPU
#                     temperature, speed against its maximum, power profile, battery.
#   Known causes      Antivirus scanning, updates installing, Spotlight / file indexing (by the
#                     CPU they used), the disk at 100 %, a nearly full system disk (B5's rule:
#                     under 5 % or 5 GB free = FAIL, under 15 % or 20 GB = WARN).
#   What to do        The next step for each problem found.
#
# Examples:
#   bash get-performance-snapshot.sh
#   bash get-performance-snapshot.sh --seconds 60 --output ~/Desktop/Ticket123
#
# Purpose       : Find the reason a computer is slow, while it is slow.
# Use Case      : "My computer is slow" tickets; before deciding on more memory or a new computer.
# Scope         : This computer only. No network traffic.
# Risk Level    : Read-Only -- reads counters, processes and settings; changes nothing.
# Prerequisites : macOS 12+ or Linux | bash 3.2+ | root: No (sudo sees every process's CPU time)
# Version       : 1.0.0
# Limitations   : A snapshot of the window it ran in: run it while the computer is slow. macOS
#                 per-process CPU is ps's recent average. MSP_TEST_ROOT (development tests only)
#                 prefixes the files read.

set -u
MSP_SCRIPT_FILE=$0

#region MSPToolkit (generated) Sections=Core
# DO NOT EDIT — regenerate with Sync-MSPEmbeddedHelper.ps1
# Source: endpoint-systems/utilities/msp-toolkit-common.sh | Sections: Core | SHA256: 7254aec8688b18c47620afce7827ff2104c3ce6df5f6ff626eeaf281011a6c25
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
            # MSP_TEST_ROOT: the tests' fake root (unset on a real computer).
            MSP_OS_VERSION=$(sed -n 's/^PRETTY_NAME=//p' "${MSP_TEST_ROOT:-}/etc/os-release" 2>/dev/null | head -n 1 | sed 's/^"//; s/"$//')
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
SECONDS_WANTED=30
TOP=5
while [ $# -gt 0 ]; do
    case "$1" in
        --output)
            OUTPUT=${2-}
            [ -n "$OUTPUT" ] || { printf 'Missing folder after --output\n' >&2; exit 2; }
            shift 2
            ;;
        --seconds) SECONDS_WANTED=${2-}; shift 2 ;;
        --top) TOP=${2-}; shift 2 ;;
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

[ -n "$OUTPUT" ] && msp_param Output "$OUTPUT"
msp_param Seconds "$SECONDS_WANTED"
msp_param Top "$TOP"
msp_init 'get-performance-snapshot' "$SCRIPT_VERSION" 'B6' 'Read-Only' 'Performance snapshot: CPU, memory, disk over a window; processes, startup, throttling, causes (read-only)'

# Number options: a value outside the range gets a plain message and exit 1 (like the PowerShell scripts).
range_ok=1
check_range() {
    # check_range NAME VALUE MIN MAX
    case "$2" in '' | *[!0-9]*) ;; *) if [ "$2" -ge "$3" ] && [ "$2" -le "$4" ]; then return 0; fi ;; esac
    msp_finding --status ERROR --category 'Setup' --check 'Parameters' \
        --detail "--$1 must be between $3 and $4 (you gave ${2:-nothing}). Nothing was checked or changed." \
        --rec "Run it again with --$1 set to a number from $3 to $4, or leave it out to use the default."
    range_ok=0
}
check_range 'seconds' "$SECONDS_WANTED" 5 120
check_range 'top' "$TOP" 3 20
if [ "$range_ok" -eq 0 ]; then
    msp_complete "$OUTPUT"
    exit 1
fi

ROOT=${MSP_TEST_ROOT:-}
W=$MSP_WORK_DIR
STEPS="$W/steps.txt"
: >"$STEPS"
step() { printf '%s\n' "$1" >>"$STEPS"; }
INTERVALS=$((SECONDS_WANTED / 2))
[ "$INTERVALS" -ge 1 ] || INTERVALS=1
ELAPSED=$((INTERVALS * 2))
if [ "$MSP_PLATFORM" = 'macOS' ]; then CORES=$(sysctl -n hw.logicalcpu 2>/dev/null); else CORES=$(nproc 2>/dev/null); fi
case "${CORES:-}" in '' | *[!0-9]*) CORES=1 ;; esac
CPU_AVG=0
DISK_MAX=''

proc_snapshot() {
    # Linux: "PID COMM TICKS RSS_PAGES" for every process (utime + stime from /proc/PID/stat).
    cat "$ROOT"/proc/[0-9]*/stat 2>/dev/null | awk '{
        l = $0; o = index(l, "("); c = 0
        for (i = length(l); i > 0; i--) if (substr(l, i, 1) == ")") { c = i; break }
        if (o == 0 || c == 0) next
        pid = substr(l, 1, o - 2); comm = substr(l, o + 1, c - o - 1); rest = substr(l, c + 2)
        n = split(rest, a, " "); gsub(/[ \t]/, "~", comm)
        print pid, comm, a[12] + a[13], a[22] }'
}
cpu_line() { awk '$1 == "cpu" { idle = $5 + $6; t = 0; for (i = 2; i <= NF; i++) t += $i; print t, idle; exit }' "$ROOT/proc/stat" 2>/dev/null; }
vm_swap() { awk '$1 == "pswpin" || $1 == "pswpout" { s += $2 } END { print s + 0 }' "$ROOT/proc/vmstat" 2>/dev/null; }
disk_ticks() { awk '$3 ~ /^(sd[a-z]+|nvme[0-9]+n[0-9]+|vd[a-z]+|xvd[a-z]+|mmcblk[0-9]+|hd[a-z]+)$/ { print $3, $13 }' "$ROOT/proc/diskstats" 2>/dev/null; }
mem_kb() { awk -v k="$1" '$1 == k":" { print $2; exit }' "$ROOT/proc/meminfo" 2>/dev/null; }

# =========================================================================================
msp_section "Sampling for $SECONDS_WANTED seconds"
# =========================================================================================
SWAP_RATE=0
sample_linux() {
    local before after t0 i0 t1 i1 dt di pct avail swap0 swap1 n=0
    swap0=$(vm_swap)
    disk_ticks >"$W/disk0.txt"
    proc_snapshot >"$W/proc0.txt"
    before=$(cpu_line)
    [ -n "$before" ] || { printf 'cannot read /proc/stat\n' >&2; return 1; }
    : >"$W/samples.txt"
    while [ "$n" -lt "$INTERVALS" ]; do
        sleep 2
        after=$(cpu_line)
        t0=${before% *}; i0=${before#* }; t1=${after% *}; i1=${after#* }
        dt=$((t1 - t0)); di=$((i1 - i0))
        pct=0
        [ "$dt" -gt 0 ] && pct=$(((dt - di) * 100 / dt))
        avail=$(($(mem_kb MemAvailable) / 1024))
        printf '%s %s %s\n' "$(date '+%H:%M:%S')" "$pct" "$avail" >>"$W/samples.txt"
        msp_data_row 'Samples' Time "$(date '+%H:%M:%S')" CpuPercent# "$pct" AvailableMB# "$avail"
        before=$after
        n=$((n + 1))
    done
    swap1=$(vm_swap)
    SWAP_RATE=$(((swap1 - swap0) / ELAPSED))
    disk_ticks >"$W/disk1.txt"
    proc_snapshot >"$W/proc1.txt"
    local tck page
    tck=$(getconf CLK_TCK 2>/dev/null)
    page=$(getconf PAGESIZE 2>/dev/null)
    # PID NAME CPU% RSS_MB for processes seen at both ends of the window.
    awk -v tck="${tck:-100}" -v page="${page:-4096}" -v el="$ELAPSED" -v cores="$CORES" \
        'NR == FNR { t[$1] = $3; next } ($1 in t) { printf "%s %s %.1f %d\n", $1, $2, ($3 - t[$1]) / tck / el / cores * 100, $4 * page / 1048576 }' \
        "$W/proc0.txt" "$W/proc1.txt" >"$W/procs.txt"
    DISK_MAX=$(awk -v el="$ELAPSED" 'NR == FNR { t[$1] = $2; next } ($1 in t) { u = ($2 - t[$1]) / (el * 10); if (u > 100) u = 100; if (u > m) { m = u; d = $1 } } END { if (d != "") printf "%d %s", m, d }' "$W/disk0.txt" "$W/disk1.txt")
    msp_finding --status INFO --category 'Sampling' --check 'Sampling' --detail "$INTERVALS sample(s) over $ELAPSED seconds, $CORES logical processor(s)."
}
sample_mac() {
    local swap0 swap1
    swap0=$(vm_stat 2>/dev/null | awk '/^Swapouts:/ { gsub(/\./, "", $2); print $2 + 0 }')
    # top's first sample counts since boot; the following ones are 2 seconds apart.
    top -l "$((INTERVALS + 1))" -s 2 -n 0 2>/dev/null | awk '/^CPU usage:/ { n++; if (n == 1) next; for (i = 1; i <= NF; i++) if ($(i + 1) == "idle") { v = $i; sub(/%/, "", v); printf "%d\n", 100 - v + 0.5 } }' >"$W/cpu.txt"
    [ -s "$W/cpu.txt" ] || { printf 'top reported no CPU samples\n' >&2; return 1; }
    : >"$W/samples.txt"
    local pct
    while read -r pct; do
        printf '%s %s 0\n' "-" "$pct" >>"$W/samples.txt"
        msp_data_row 'Samples' Time '' CpuPercent# "$pct" AvailableMB# 0
    done <"$W/cpu.txt"
    swap1=$(vm_stat 2>/dev/null | awk '/^Swapouts:/ { gsub(/\./, "", $2); print $2 + 0 }')
    SWAP_RATE=$(((${swap1:-0} - ${swap0:-0}) / ELAPSED))
    # PID NAME CPU% RSS_MB (ps: CPU is the recent average).
    ps -Ao pid=,pcpu=,rss=,comm= 2>/dev/null | awk -v cores="$CORES" '{ c = $4; for (i = 5; i <= NF; i++) c = c "~" $i; n = split(c, p, "/"); printf "%s %s %.1f %d\n", $1, p[n], $2 / cores, $3 / 1024 }' >"$W/procs.txt"
    msp_finding --status INFO --category 'Sampling' --check 'Sampling' --detail "$INTERVALS sample(s) over $ELAPSED seconds, $CORES logical processor(s)."
}
if [ "$MSP_PLATFORM" = 'macOS' ]; then msp_check 'Sampling' 'Sampling' sample_mac; else msp_check 'Sampling' 'Sampling' sample_linux; fi
touch "$W/samples.txt" "$W/procs.txt"
proc_cpu() {
    # proc_cpu NAME... - CPU % used by processes with these names (Linux names are cut to 15 characters).
    awk -v names=" $* " '{ if (index(names, " " $2 " ") > 0) s += $3 } END { printf "%.1f", s + 0 }' "$W/procs.txt"
}

# =========================================================================================
msp_section 'CPU, memory and disk'
# =========================================================================================
check_cpu() {
    [ -s "$W/samples.txt" ] || { msp_skip 'Load' 'CPU' 'No samples were taken (see "Sampling").'; return 0; }
    local avg peak top
    avg=$(awk '{ s += $2; n++ } END { printf "%d", (n ? s / n : 0) + 0.5 }' "$W/samples.txt")
    peak=$(awk '$2 > m { m = $2 } END { print m + 0 }' "$W/samples.txt")
    CPU_AVG=$avg
    local text="Average $avg %, peak $peak % over $ELAPSED seconds."
    if [ "$avg" -ge 85 ]; then
        top=$(sort -k3,3nr "$W/procs.txt" | head -n 1 | tr '~' ' ')
        msp_finding --status WARN --severity High --category 'Load' --check 'CPU' --detail "$text" \
            --rec 'The processor is the bottleneck: see the top processes below for what is using it.'
        # $top is "PID NAME CPU% MB"; NAME may contain spaces.
        [ -n "$top" ] && step "CPU is busy ($avg % on average): look at $(printf '%s' "$top" | awk '{ $1 = ""; $NF = ""; $(NF - 1) = ""; sub(/^ +/, ""); sub(/ +$/, ""); print }') first (it used $(printf '%s' "$top" | awk '{ print $(NF - 1) }') % of the CPU); quit it, update it, or ask the vendor if it stays high."
    else
        msp_finding --status PASS --category 'Load' --check 'CPU' --detail "$text"
    fi
}
msp_check 'Load' 'CPU' check_cpu

check_memory() {
    local text
    if [ "$MSP_PLATFORM" = 'macOS' ]; then
        local free level total_gb
        free=$(memory_pressure 2>/dev/null | sed -n 's/.*memory free percentage: *\([0-9]*\)%.*/\1/p' | head -n 1)
        level=$(sysctl -n kern.memorystatus_vm_pressure_level 2>/dev/null)
        total_gb=$(($(sysctl -n hw.memsize 2>/dev/null || echo 0) / 1073741824))
        [ -n "$free" ] || { printf 'memory_pressure gave no reading\n' >&2; return 1; }
        text="$((100 - free)) % of $total_gb GB in use (memory pressure level ${level:-unknown}: 1 normal, 2 warning, 4 critical)."
        if [ "$free" -lt 10 ] || [ "${level:-1}" -ge 2 ]; then
            msp_finding --status WARN --severity High --category 'Load' --check 'Memory' --detail "$text" \
                --rec 'Quit what is not needed (see the top processes by memory); if it is always like this, the Mac needs more memory.'
            step "Memory is under pressure: quit the biggest apps listed below, or plan a computer with more memory if this is normal use ($total_gb GB installed)."
        else
            msp_finding --status PASS --category 'Load' --check 'Memory' --detail "$text"
        fi
        return 0
    fi
    local total avail min used
    total=$(mem_kb MemTotal)
    [ -n "$total" ] && [ "$total" -gt 0 ] || { printf 'cannot read /proc/meminfo\n' >&2; return 1; }
    avail=$(awk '{ s += $3; n++ } END { printf "%d", (n ? s / n : 0) }' "$W/samples.txt")
    min=$(awk 'NR == 1 || $3 < m { m = $3 } END { print m + 0 }' "$W/samples.txt")
    used=$(awk -v a="$avail" -v t="$total" 'BEGIN { printf "%d", 100 - a * 1024 * 100 / t + 0.5 }')
    text="$used % of $((total / 1048576)) GB in use on average; lowest available $min MB."
    if [ "$used" -ge 90 ] || [ "$min" -lt 500 ]; then
        msp_finding --status WARN --severity High --category 'Load' --check 'Memory' --detail "$text" \
            --rec 'Close what is not needed (see the top processes by memory); if it is always this full, the computer needs more memory.'
        step "Memory is nearly full ($used % in use): close the biggest programs listed below, or plan a memory upgrade if this is normal use."
    else
        msp_finding --status PASS --category 'Load' --check 'Memory' --detail "$text"
    fi
}
msp_check 'Load' 'Memory' check_memory

check_pressure() {
    local why='' text psi=''
    if [ -r "$ROOT/proc/pressure/memory" ]; then psi=$(awk '$1 == "some" { for (i = 2; i <= NF; i++) if ($i ~ /^avg10=/) { sub(/avg10=/, "", $i); printf "%d", $i + 0.5 } }' "$ROOT/proc/pressure/memory"); fi
    text="Swapping $SWAP_RATE pages/s during the window${psi:+; memory stall (PSI some avg10) $psi %}."
    [ "$SWAP_RATE" -ge 100 ] && why="swapping to disk"
    if [ -n "$psi" ] && [ "$psi" -ge 10 ]; then why="${why:+$why, }programs waiting for memory"; fi
    if [ -n "$why" ]; then
        msp_finding --status WARN --severity High --category 'Load' --check 'Memory pressure' --detail "$text" \
            --rec 'The system is short of memory and using swap: close programs, look for one that keeps growing, or add memory.'
        step "Memory pressure ($why): restart the program that grew the most, then check again; if it comes back, the computer needs more memory."
    else
        msp_finding --status PASS --category 'Load' --check 'Memory pressure' --detail "$text"
    fi
}
msp_check 'Load' 'Memory pressure' check_pressure

check_disk() {
    if [ "$MSP_PLATFORM" = 'macOS' ]; then msp_skip 'Load' 'Disk activity' 'macOS does not report how busy a disk is (Activity Monitor > Disk shows reads and writes).'; return 0; fi
    [ -n "$DISK_MAX" ] || { msp_skip 'Load' 'Disk activity' 'No disk statistics were found in /proc/diskstats.'; return 0; }
    local pct=${DISK_MAX%% *} dev=${DISK_MAX#* }
    if [ "$pct" -ge 95 ]; then
        msp_finding --status WARN --severity High --category 'Load' --check 'Disk activity' --detail "$dev busy $pct % of the time during the window." \
            --rec 'The disk is the bottleneck ("disk at 100 %"): see Known causes; an old hard disk (HDD) is the usual reason, and an SSD is the fix.'
    else
        msp_finding --status PASS --category 'Load' --check 'Disk activity' --detail "Busiest disk $dev: $pct % of the time."
    fi
}
msp_check 'Load' 'Disk activity' check_disk

check_top() {
    [ -s "$W/procs.txt" ] || { msp_skip 'Processes' 'Top processes' 'No processes could be read.'; return 0; }
    local cpu mem pid name c m
    cpu=$(sort -k3,3nr "$W/procs.txt" | head -n "$TOP")
    mem=$(sort -k4,4nr "$W/procs.txt" | head -n "$TOP")
    while read -r pid name c m; do name=$(printf '%s' "$name" | tr '~' ' '); msp_data_row 'TopCpu' Name "$name" Id# "$pid" CpuPercent# "$c" MemoryMB# "$m"; done <<EOF
$cpu
EOF
    while read -r pid name c m; do name=$(printf '%s' "$name" | tr '~' ' '); msp_data_row 'TopMemory' Name "$name" Id# "$pid" MemoryMB# "$m" CpuPercent# "$c"; done <<EOF
$mem
EOF
    msp_finding --status INFO --category 'Processes' --check 'Top processes by CPU' --detail "$(printf '%s\n' "$cpu" | awk '{ n = $2; gsub(/~/, " ", n); printf "%s%s %s %%", (NR > 1 ? "; " : ""), n, $3 }')"
    msp_finding --status INFO --category 'Processes' --check 'Top processes by memory' --detail "$(printf '%s\n' "$mem" | awk '{ n = $2; gsub(/~/, " ", n); printf "%s%s %d MB", (NR > 1 ? "; " : ""), n, $4 }')"
}
msp_check 'Processes' 'Top processes' check_top

# =========================================================================================
msp_section 'Startup, uptime and restarts'
# =========================================================================================
check_startup() {
    local f prog name mb count=0 heavy='' services=''
    : >"$W/startup.txt"
    if [ "$MSP_PLATFORM" = 'macOS' ]; then
        for f in "$HOME"/Library/LaunchAgents/*.plist /Library/LaunchAgents/*.plist /Library/LaunchDaemons/*.plist; do
            [ -f "$f" ] || continue
            case "${f##*/}" in com.apple.*) continue ;; esac
            prog=$(/usr/libexec/PlistBuddy -c 'Print :Program' "$f" 2>/dev/null || /usr/libexec/PlistBuddy -c 'Print :ProgramArguments:0' "$f" 2>/dev/null)
            printf '%s\t%s\n' "${f##*/}" "${prog##*/}" >>"$W/startup.txt"
        done
    else
        for f in "$HOME"/.config/autostart/*.desktop "$ROOT"/etc/xdg/autostart/*.desktop; do
            [ -f "$f" ] || continue
            grep -qiE '^(Hidden=true|X-GNOME-Autostart-enabled=false)' "$f" && continue
            prog=$(sed -n 's/^Exec=//p' "$f" | head -n 1 | awk '{ print $1 }')
            printf '%s\t%s\n' "${f##*/}" "${prog##*/}" >>"$W/startup.txt"
        done
        msp_have systemctl && services=$(systemctl list-unit-files --type=service --state=enabled --no-legend 2>/dev/null | wc -l | tr -d ' ')
    fi
    while IFS="$(printf '\t')" read -r name prog; do
        [ -n "$name" ] || continue
        count=$((count + 1))
        mb=$(awk -v p="$(printf '%s' "$prog" | cut -c1-15)" '$2 == p { s += $4 } END { print s + 0 }' "$W/procs.txt")
        msp_data_row 'Startup' Name "$name" Program "$prog" RunningMB# "$mb"
        [ "$mb" -gt 0 ] && printf '%s %s\n' "$mb" "$name" >>"$W/heavy.txt"
    done <"$W/startup.txt"
    [ -s "$W/heavy.txt" ] && heavy=$(sort -k1,1nr "$W/heavy.txt" | head -n 3 | awk '{ printf "%s%s %d MB", (NR > 1 ? ", " : ""), $2, $1 }')
    local what='startup item(s) (launch agents and daemons outside Apple'"'"'s own)'
    [ "$MSP_PLATFORM" = 'macOS' ] || what="desktop autostart entr(ies)${services:+, $services enabled service(s)}"
    local text="$count $what.${heavy:+ Heaviest running now: $heavy.}"
    if [ "$count" -gt 15 ]; then
        msp_finding --status WARN --severity Low --category 'Startup' --check 'Startup programs' --detail "$text" \
            --rec 'Turn off what the user does not need at startup (macOS: System Settings > General > Login Items; Linux: Startup Applications in the desktop settings).'
        step "Too many startup items ($count): turn off what the user does not need (macOS: System Settings > General > Login Items & Extensions; Linux: Startup Applications)."
    else
        msp_finding --status PASS --category 'Startup' --check 'Startup programs' --detail "$text"
    fi
}
msp_check 'Startup' 'Startup programs' check_startup

check_uptime() {
    local up days
    if [ "$MSP_PLATFORM" = 'macOS' ]; then
        local boot
        boot=$(sysctl -n kern.boottime 2>/dev/null | sed -n 's/^{ *sec = \([0-9]*\),.*/\1/p')
        up=$(($(date +%s) - ${boot:-0}))
    else
        up=$(awk '{ printf "%d", $1 }' "$ROOT/proc/uptime" 2>/dev/null)
    fi
    [ -n "$up" ] && [ "$up" -gt 0 ] || { printf 'uptime not readable\n' >&2; return 1; }
    days=$((up / 86400))
    if [ "$days" -gt 30 ]; then
        msp_finding --status WARN --severity Medium --category 'Startup' --check 'Uptime' --detail "Up $days days." --rec 'Restart the computer.'
        step "Restart the computer (up $days days), then check again."
    else
        msp_finding --status PASS --category 'Startup' --check 'Uptime' --detail "Up $days day(s)."
    fi
}
msp_check 'Startup' 'Uptime' check_uptime

check_restart() {
    if [ "$MSP_PLATFORM" = 'macOS' ]; then
        msp_finding --status INFO --category 'Startup' --check 'Restart pending' --detail 'macOS keeps no restart-pending flag; updates restart the Mac themselves.'
        return 0
    fi
    local why=''
    { [ -f "$ROOT/var/run/reboot-required" ] || [ -f "$ROOT/run/reboot-required" ]; } && why='updates installed that need a restart (reboot-required)'
    if [ -z "$why" ] && msp_have needs-restarting && ! needs-restarting -r >/dev/null 2>&1; then why='updates installed that need a restart (needs-restarting)'; fi
    if [ -n "$why" ]; then
        msp_finding --status WARN --severity Medium --category 'Startup' --check 'Restart pending' --detail "Waiting for a restart: $why." --rec 'Restart to finish installing the updates.'
        step 'Restart to finish the installed updates.'
    else
        msp_finding --status PASS --category 'Startup' --check 'Restart pending' --detail 'No restart pending.'
    fi
}
msp_check 'Startup' 'Restart pending' check_restart

# =========================================================================================
msp_section 'Throttling and power'
# =========================================================================================
check_power_mac() {
    local therm limit batt lpm text warn=''
    therm=$(pmset -g therm 2>/dev/null)
    limit=$(printf '%s\n' "$therm" | sed -n 's/.*CPU_Speed_Limit *= *\([0-9]*\).*/\1/p' | head -n 1)
    batt=$(pmset -g batt 2>/dev/null)
    lpm=$(pmset -g 2>/dev/null | awk '$1 == "lowpowermode" { print $2 }')
    text="CPU speed limit ${limit:-100} %; $(printf '%s\n' "$batt" | sed -n "s/.*drawing from '\\(.*\\)'.*/\\1/p" | head -n 1)$(printf '%s\n' "$batt" | awk '/%/ { for (i = 1; i <= NF; i++) if ($i ~ /%;?$/) { v = $i; sub(/;$/, "", v); printf ", battery %s", v; exit } }'); Low Power Mode ${lpm:-0}."
    if [ -n "$limit" ] && [ "$limit" -lt 100 ]; then
        warn='hot'
        msp_finding --status WARN --severity Medium --category 'Power' --check 'CPU speed' --detail "$text" --rec 'The Mac is slowing itself down because of heat: check the vents and that it is not on a soft surface or in the sun.'
        step 'The Mac is throttling because of heat: clear the vents, use it on a hard surface, and check Activity Monitor for anything using the CPU constantly.'
    fi
    if [ "${lpm:-0}" = 1 ]; then
        msp_finding --status WARN --severity Low --category 'Power' --check 'Power plan' --detail "$text" --rec 'Low Power Mode slows the Mac on purpose: turn it off in System Settings > Battery.'
        step 'Low Power Mode is on: turn it off in System Settings > Battery (Low Power Mode: Never or Only on Battery).'
    elif [ -z "$warn" ]; then
        msp_finding --status INFO --category 'Power' --check 'Power plan' --detail "$text"
    fi
}
check_power_linux() {
    local temp='' cur='' max='' gov='' profile='' batt='' text f warn=0
    for f in "$ROOT"/sys/class/thermal/thermal_zone*/temp; do [ -r "$f" ] && temp="$temp $(cat "$f")"; done
    temp=$(printf '%s\n' "$temp" | awk '{ for (i = 1; i <= NF; i++) if ($i > m) m = $i } END { if (m) printf "%d", m / 1000 }')
    cur=$(cat "$ROOT/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq" 2>/dev/null)
    max=$(cat "$ROOT/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq" 2>/dev/null)
    gov=$(cat "$ROOT/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor" 2>/dev/null)
    msp_have powerprofilesctl && profile=$(powerprofilesctl get 2>/dev/null)
    for f in "$ROOT"/sys/class/power_supply/BAT*; do
        [ -d "$f" ] && batt="$(cat "$f/status" 2>/dev/null), battery $(cat "$f/capacity" 2>/dev/null) %"
    done
    text="CPU temperature ${temp:-not reported}${temp:+ C}; speed ${cur:+$((cur / 1000)) MHz of }${max:+$((max / 1000)) MHz}${gov:+ (governor $gov)}${profile:+; power profile $profile}; ${batt:-no battery}."
    if [ -n "$temp" ] && [ "$temp" -ge 90 ]; then
        warn=1
        msp_finding --status WARN --severity Medium --category 'Power' --check 'CPU speed' --detail "$text" --rec 'The CPU is very hot and will slow itself down: clean the vents and fan, check the fan runs.'
        step "The CPU is at $temp C: clean the vents and fan, and check the fan runs; heat makes the CPU slow down."
    elif [ -n "$cur" ] && [ -n "$max" ] && [ "$max" -gt 0 ] && [ "$CPU_AVG" -ge 50 ] && [ $((cur * 100 / max)) -lt 60 ]; then
        warn=1
        msp_finding --status WARN --severity Medium --category 'Power' --check 'CPU speed' --detail "$text" --rec 'The CPU runs slow while busy (power saving or heat): check the power profile and the cooling.'
        step 'The CPU is running slow while busy: switch the power profile to Balanced or Performance and check the cooling.'
    else
        msp_finding --status INFO --category 'Power' --check 'CPU speed' --detail "$text"
    fi
    if [ "$profile" = 'power-saver' ]; then
        msp_finding --status WARN --severity Low --category 'Power' --check 'Power plan' --detail "Power profile: power-saver." --rec 'Power saving slows the CPU on purpose: choose Balanced (Settings > Power).'
        step 'Power saving is on: choose the Balanced power profile (Settings > Power, or powerprofilesctl set balanced).'
    fi
}
if [ "$MSP_PLATFORM" = 'macOS' ]; then msp_check 'Power' 'Power plan' check_power_mac; else msp_check 'Power' 'CPU speed' check_power_linux; fi

# =========================================================================================
msp_section 'Known slow-down causes'
# =========================================================================================
check_causes() {
    local found='' cpu
    if [ "$MSP_PLATFORM" = 'macOS' ]; then
        AV='XProtect XprotectService MRT SentinelAgent falcond SophosScanD bdservicehost wdavdaemon clamd'
        UPD='softwareupdated softwareupdate installd'
        IDX='mds mds_stores mdworker mdworker_shared'
        IDXSTEP='Spotlight is indexing: let it finish (it can take hours after an update or a big copy); if it never ends, rebuild the index (System Settings > Siri & Spotlight > Spotlight Privacy, add and remove the disk).'
    else
        AV='clamd clamscan wdavdaemon falcon-sensor SentinelAgent'
        UPD='apt apt-get dpkg unattended-upgr packagekitd dnf yum snapd'
        IDX='tracker-miner-f tracker-miner-fs-3 tracker-extract baloo_file baloo_file_extr'
        IDXSTEP='File indexing (Tracker / Baloo) is busy: let it finish, or exclude large folders from search in the desktop settings.'
    fi
    # shellcheck disable=SC2086  # the name lists are split on purpose
    cpu=$(proc_cpu $AV)
    if awk -v c="$cpu" 'BEGIN { exit !(c >= 10) }'; then found="${found:+$found; }antivirus scan ($cpu % CPU)"; step 'The antivirus is scanning: let it finish, or move full scans outside working hours in its policy.'; fi
    # shellcheck disable=SC2086
    cpu=$(proc_cpu $UPD)
    if awk -v c="$cpu" 'BEGIN { exit !(c >= 10) }'; then found="${found:+$found; }updates installing ($cpu % CPU)"; step 'Updates are installing: let them finish and restart; the computer should be fast again afterwards.'; fi
    # shellcheck disable=SC2086
    cpu=$(proc_cpu $IDX)
    if awk -v c="$cpu" 'BEGIN { exit !(c >= 10) }'; then found="${found:+$found; }indexing ($cpu % CPU)"; step "$IDXSTEP"; fi
    if [ -n "$DISK_MAX" ] && [ "${DISK_MAX%% *}" -ge 95 ]; then
        found="${found:+$found; }disk at 100 % (${DISK_MAX#* })"
        step 'The disk is at 100 %: if it is a hard disk (HDD), replacing it with an SSD is the fix; otherwise find the process using it (iotop, or the system monitor).'
    fi
    local mount='/' line size avail size_gb free_gb pct small=0 status=PASS
    [ "$MSP_PLATFORM" = 'macOS' ] && [ -d /System/Volumes/Data ] && mount='/System/Volumes/Data'
    line=$(df -kP "$ROOT$mount" 2>/dev/null | awk 'NR == 2')
    size=$(printf '%s\n' "$line" | awk '{ print $2 }')
    avail=$(printf '%s\n' "$line" | awk '{ print $4 }')
    if [ -n "$size" ] && [ "$size" -gt 0 ] 2>/dev/null; then
        size_gb=$((size / 1048576)); free_gb=$((avail / 1048576)); pct=$((avail * 100 / size))
        [ "$size_gb" -lt 50 ] && small=1
        if [ "$pct" -lt 5 ] || { [ "$small" -eq 0 ] && [ "$free_gb" -lt 5 ]; }; then status=FAIL
        elif [ "$pct" -lt 15 ] || { [ "$small" -eq 0 ] && [ "$free_gb" -lt 20 ]; }; then status=WARN; fi
        if [ "$status" != PASS ]; then
            found="${found:+$found; }system disk nearly full ($free_gb GB free, $pct %)"
            step "The system disk is nearly full ($free_gb GB free): run B5 get-disk-space-report.sh for where the space went and what can be cleaned."
        fi
    fi
    if [ -n "$found" ]; then
        msp_finding --status WARN --severity Medium --category 'Causes' --check 'Known causes' --detail "Found: $found." --rec 'See What to do for the step for each.'
    else
        msp_finding --status PASS --category 'Causes' --check 'Known causes' --detail 'No antivirus scan, update install or indexing busy, disk not at 100 %, system disk not nearly full.'
    fi
}
msp_check 'Causes' 'Known causes' check_causes

# =========================================================================================
msp_section 'What to do (by hand; this script changed nothing)'
# =========================================================================================
if [ ! -s "$STEPS" ]; then step 'Nothing stood out while sampling. If the user says it is slow at other times, run this again while it is slow (--seconds 60), and check B3 get-recent-critical-errors.sh for crashes.'; fi
i=0
all=''
while IFS= read -r s; do
    [ -n "$s" ] || continue
    case "
$all" in *" $s"*) continue ;; esac
    i=$((i + 1))
    printf '  %2d. %s\n' "$i" "$s"
    msp_data_row 'NextSteps' Step# "$i" Action "$s"
    all="$all${all:+ }$i. $s"
done <"$STEPS"
msp_finding --status INFO --category 'Summary' --check 'What to do' --detail "$all" --quiet

msp_complete "$OUTPUT"
exit 0
