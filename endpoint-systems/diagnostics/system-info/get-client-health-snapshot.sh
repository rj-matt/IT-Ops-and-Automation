#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2329  # The embedded helper defines globals and functions this script does not use; checks run through msp_check.
# get-client-health-snapshot.sh - read-only health snapshot of a Mac or Linux computer for a
# ticket: computer and OS version, uptime and pending restart, memory, CPU load, free disk space,
# last update installed and updates waiting. The Windows version is Get-ClientHealthSnapshot.ps1
# (same checks and finding IDs).
#
# Usage:  bash get-client-health-snapshot.sh [--output DIR] [--help]
#
# Options:
#   --output DIR  Also save results as JSON and CSV (toolkit schema 2.0), with a Disks table.
#   --help        Show this help.
#
# Checks
#   Computer          Maker, model, serial number (Linux: sudo), signed-in user.
#   OS version        Version and build (macOS) or distribution and kernel (Linux), architecture.
#   Uptime            Days since the last restart (more than 30 = WARN).
#   Restart pending   Linux: reboot-required, needs-restarting, newer kernel installed. macOS
#                     keeps no such flag (updates restart the Mac themselves): INFO.
#   Memory            macOS: memory pressure (free percentage). Linux: MemAvailable.
#                     90 % or more in use = WARN.
#   CPU               1-minute load average per logical CPU (90 % or more = WARN).
#   Disk space        The system volume ("System drive space") and other local volumes
#                     ("Disk space <mount>"). Less than 10 % (or 5 GB) free = FAIL, less than
#                     20 % (or 15 GB) = WARN; 100 GB or more free is always fine; volumes under
#                     50 GB (e.g. /boot) are judged on the percentage only.
#   Updates           Last update installed and updates waiting, from the system's own last
#                     check (no network traffic). Full check: get-update-compliance-*.sh (A6).
#
# Examples:
#   bash get-client-health-snapshot.sh
#   bash get-client-health-snapshot.sh --output ~/Desktop/Ticket123
#
# Purpose       : One-screen "how healthy is this computer right now" for the start of a ticket.
# Use Case      : Slow computer, crashes, "it's acting up" tickets; onboarding.
# Scope         : This computer only. No network traffic.
# Risk Level    : Read-Only -- reads system information and the update records; changes nothing.
# Prerequisites : macOS 12+ or Linux (apt or dnf for pending updates) | bash 3.2+ | root: No
#                 (Linux: sudo adds the serial number)
# Version       : 1.0.0
# Limitations   : CPU and memory are a snapshot, not a trend; the load average is not the same
#                 measure as Windows' CPU percentage. Pending updates come from the last check
#                 and can be out of date. MSP_TEST_ROOT (development tests only) prefixes the
#                 files read.

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
while [ $# -gt 0 ]; do
    case "$1" in
        --output)
            OUTPUT=${2-}
            [ -n "$OUTPUT" ] || { printf 'Missing folder after --output\n' >&2; exit 2; }
            shift 2
            ;;
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
msp_init 'get-client-health-snapshot' "$SCRIPT_VERSION" 'B1' 'Read-Only' 'Health snapshot: system, uptime, memory, CPU, disk space, updates (read-only)' \
    'serial number (Linux)'

ROOT=${MSP_TEST_ROOT:-}
NOW=$(date +%s)

file_mtime() {
    if [ "$MSP_PLATFORM" = 'macOS' ]; then stat -f %m "$1" 2>/dev/null; else stat -c %Y "$1" 2>/dev/null; fi # linux-only: stat -c
}
ymd() {
    if [ "$MSP_PLATFORM" = 'macOS' ]; then date -r "$1" '+%Y-%m-%d'; else date -d "@$1" '+%Y-%m-%d'; fi # linux-only: date -d
}
disk_status() {
    # disk_status SIZE_GB FREE_GB PERCENT_FREE (whole numbers) -> PASS / WARN / FAIL.
    local size=$1 free=$2 pct=$3 small=0
    [ "$size" -lt 50 ] && small=1
    if [ "$free" -ge 100 ]; then printf 'PASS'; return 0; fi
    if [ "$pct" -lt 10 ] || { [ "$small" -eq 0 ] && [ "$free" -lt 5 ]; }; then printf 'FAIL'; return 0; fi
    if [ "$pct" -lt 20 ] || { [ "$small" -eq 0 ] && [ "$free" -lt 15 ]; }; then printf 'WARN'; return 0; fi
    printf 'PASS'
}

# =========================================================================================
msp_section 'System'
# =========================================================================================
check_computer() {
    local maker='' model='' serial='' hw
    if [ "$MSP_PLATFORM" = 'macOS' ]; then
        hw=$(system_profiler SPHardwareDataType 2>/dev/null)
        maker='Apple'
        model=$(printf '%s\n' "$hw" | sed -n 's/^ *Model Name: //p' | head -n 1)
        local ident
        ident=$(printf '%s\n' "$hw" | sed -n 's/^ *Model Identifier: //p' | head -n 1)
        [ -n "$ident" ] && model="$model ($ident)"
        serial=$(printf '%s\n' "$hw" | sed -n 's/^ *Serial Number (system): //p' | head -n 1)
    else
        maker=$(cat "$ROOT/sys/class/dmi/id/sys_vendor" 2>/dev/null)
        model=$(cat "$ROOT/sys/class/dmi/id/product_name" 2>/dev/null)
        serial=$(cat "$ROOT/sys/class/dmi/id/product_serial" 2>/dev/null)
        [ -n "$serial" ] || serial='(needs sudo)'
    fi
    msp_finding --status INFO --category 'System' --check 'Computer' \
        --evidence "$(msp_json_obj Manufacturer "$maker" Model "$model" Serial "$serial")" \
        --detail "${maker:-Unknown maker} ${model:-unknown model} (S/N ${serial:-unknown}), user ${SUDO_USER:-$MSP_USER}"
}
msp_check 'System' 'Computer' check_computer

check_os() {
    local build='' arch
    arch=$(uname -m 2>/dev/null)
    if [ "$MSP_PLATFORM" = 'macOS' ]; then
        build=$(sw_vers -buildVersion 2>/dev/null)
        msp_finding --status INFO --category 'System' --check 'OS version' --evidence "$(msp_json_obj Version "$MSP_OS_VERSION" Build "$build" Architecture "$arch")" \
            --detail "$MSP_OS_VERSION (build $build, $arch)"
    else
        build=$(uname -r 2>/dev/null)
        msp_finding --status INFO --category 'System' --check 'OS version' --evidence "$(msp_json_obj Version "$MSP_OS_VERSION" Kernel "$build" Architecture "$arch")" \
            --detail "$MSP_OS_VERSION (kernel $build, $arch)"
    fi
}
msp_check 'System' 'OS version' check_os

UP_DAYS=''
check_uptime() {
    local secs boot
    if [ "$MSP_PLATFORM" = 'macOS' ]; then
        # "{ sec = 1792190174, usec = 290649 } ...": the first number is the boot time.
        boot=$(sysctl -n kern.boottime 2>/dev/null | sed -n 's/^{ *sec = \([0-9]*\),.*/\1/p')
        [ -n "$boot" ] || { printf 'Could not read the boot time\n' >&2; return 1; }
        secs=$((NOW - boot))
    else
        secs=$(cut -d. -f1 "$ROOT/proc/uptime" 2>/dev/null)
        [ -n "$secs" ] || { printf 'No such file or directory: /proc/uptime\n' >&2; return 1; }
        boot=$((NOW - secs))
    fi
    UP_DAYS=$((secs / 86400))
    local hours=$(((secs % 86400) / 3600)) ev
    ev=$(msp_json_obj LastBoot "$(ymd "$boot")" Days# "$UP_DAYS")
    if [ "$UP_DAYS" -gt 30 ]; then
        msp_finding --status WARN --severity Low --category 'System' --check 'Uptime' --evidence "$ev" \
            --detail "Up $UP_DAYS day(s) $hours hour(s), since $(ymd "$boot")." \
            --rec 'Restart the computer: updates and many fixes only take effect after a restart.'
    else
        msp_finding --status PASS --category 'System' --check 'Uptime' --evidence "$ev" --detail "Up $UP_DAYS day(s) $hours hour(s), since $(ymd "$boot")."
    fi
}
msp_check 'System' 'Uptime' check_uptime

check_restart() {
    if [ "$MSP_PLATFORM" = 'macOS' ]; then
        msp_finding --status INFO --category 'System' --check 'Restart pending' \
            --detail 'macOS keeps no pending-restart flag: updates that need a restart restart the Mac when they are installed.'
        return 0
    fi
    local reasons='' running newest pkgs
    if [ -f "$ROOT/var/run/reboot-required" ] || [ -f "$ROOT/run/reboot-required" ]; then
        pkgs=$(cat "$ROOT/var/run/reboot-required.pkgs" "$ROOT/run/reboot-required.pkgs" 2>/dev/null | sort -u | head -n 5 | paste -sd ',' - | sed 's/,/, /g')
        reasons="the system asked for a restart${pkgs:+ (for $pkgs)}"
    fi
    if [ -z "$reasons" ] && msp_have needs-restarting; then
        needs-restarting -r >/dev/null 2>&1
        [ $? -eq 1 ] && reasons='needs-restarting reports updated core packages'
    fi
    # A newer kernel installed than the one running also means a restart is due.
    running=$(uname -r)
    newest=$(for k in "$ROOT"/boot/vmlinuz-*; do [ -e "$k" ] && printf '%s\n' "${k##*/vmlinuz-}"; done | grep -v rescue | sort -V | tail -n 1) # linux-only: sort -V
    if [ -n "$newest" ] && [ "$newest" != "$running" ] && [ "$(printf '%s\n%s\n' "$running" "$newest" | sort -V | tail -n 1)" = "$newest" ]; then # linux-only: sort -V
        reasons="$reasons${reasons:+; }kernel $newest is installed but $running is running"
    fi
    if [ -n "$reasons" ]; then
        msp_finding --status WARN --severity Medium --category 'System' --check 'Restart pending' \
            --evidence "$(msp_json_obj Reasons "$reasons")" --detail "A restart is needed: $reasons." \
            --rec 'Restart the computer at a convenient time (with the client'\''s agreement).'
    else
        msp_finding --status PASS --category 'System' --check 'Restart pending' --detail 'No restart pending.'
    fi
}
msp_check 'System' 'Restart pending' check_restart

# =========================================================================================
msp_section 'Resources'
# =========================================================================================
check_memory() {
    local total_kb avail_kb used_pct total_gb avail_gb how
    if [ "$MSP_PLATFORM" = 'macOS' ]; then
        total_kb=$(($(sysctl -n hw.memsize 2>/dev/null || echo 0) / 1024))
        # memory_pressure reports what macOS considers free (free + reclaimable). It only reads.
        local free_pct
        free_pct=$(memory_pressure 2>/dev/null | sed -n 's/^System-wide memory free percentage: *\([0-9]*\)%.*/\1/p')
        [ -n "$free_pct" ] && [ "$total_kb" -gt 0 ] || { printf 'Could not read memory pressure\n' >&2; return 1; }
        used_pct=$((100 - free_pct))
        avail_kb=$((total_kb * free_pct / 100))
        how='memory pressure'
    else
        total_kb=$(awk '$1 == "MemTotal:" { print $2 }' "$ROOT/proc/meminfo" 2>/dev/null)
        avail_kb=$(awk '$1 == "MemAvailable:" { print $2 }' "$ROOT/proc/meminfo" 2>/dev/null)
        [ -n "$total_kb" ] && [ -n "$avail_kb" ] && [ "$total_kb" -gt 0 ] || { printf 'No such file or directory: /proc/meminfo\n' >&2; return 1; }
        used_pct=$((100 - avail_kb * 100 / total_kb))
        how='MemAvailable'
    fi
    total_gb=$(awk -v k="$total_kb" 'BEGIN { printf "%.1f", k / 1048576 }')
    avail_gb=$(awk -v k="$avail_kb" 'BEGIN { printf "%.1f", k / 1048576 }')
    local ev text
    ev=$(msp_json_obj TotalGB# "$total_gb" AvailableGB# "$avail_gb" UsedPercent# "$used_pct")
    text="$used_pct % of $total_gb GB in use ($avail_gb GB available, from $how)."
    if [ "$used_pct" -ge 90 ]; then
        local where='Activity Monitor > Memory'
        [ "$MSP_PLATFORM" = 'Linux' ] && where='System Monitor, or top sorted by memory'
        msp_finding --status WARN --severity Medium --category 'Resources' --check 'Memory' --evidence "$ev" --detail "$text" \
            --rec "Close programs and browser tabs that are not needed ($where). If it is always this high, the computer needs more memory."
    else
        msp_finding --status PASS --category 'Resources' --check 'Memory' --evidence "$ev" --detail "$text"
    fi
}
msp_check 'Resources' 'Memory' check_memory

check_cpu() {
    local name cores logical load pct
    if [ "$MSP_PLATFORM" = 'macOS' ]; then
        name=$(sysctl -n machdep.cpu.brand_string 2>/dev/null)
        cores=$(sysctl -n hw.physicalcpu 2>/dev/null)
        logical=$(sysctl -n hw.logicalcpu 2>/dev/null)
        load=$(sysctl -n vm.loadavg 2>/dev/null | awk '{ print $2 }')
    else
        name=$(sed -n 's/^model name[[:space:]]*: //p' "$ROOT/proc/cpuinfo" 2>/dev/null | head -n 1)
        logical=$(grep -c '^processor' "$ROOT/proc/cpuinfo" 2>/dev/null)
        cores=$(awk -F': ' '/^core id/ { c[$2] = 1 } /^physical id/ { p[$2] = 1 } END { n = 0; for (i in c) n++; m = 0; for (j in p) m++; if (m < 1) m = 1; print n * m }' "$ROOT/proc/cpuinfo" 2>/dev/null)
        [ "${cores:-0}" -gt 0 ] || cores=$logical
        load=$(cut -d' ' -f1 "$ROOT/proc/loadavg" 2>/dev/null)
    fi
    [ -n "$load" ] && [ "${logical:-0}" -gt 0 ] || { printf 'Could not read the load average\n' >&2; return 1; }
    pct=$(awk -v l="$load" -v n="$logical" 'BEGIN { printf "%d", (l / n) * 100 + 0.5 }')
    local ev text
    ev=$(msp_json_obj Name "$name" Cores# "${cores:-0}" LogicalProcessors# "$logical" LoadAverage# "$load" LoadPercent# "$pct")
    text="${name:-CPU} ($cores cores / $logical threads): 1-minute load $load = about $pct % of capacity."
    if [ "$pct" -ge 90 ]; then
        local where='Activity Monitor > CPU'
        [ "$MSP_PLATFORM" = 'Linux' ] && where='System Monitor, or top'
        msp_finding --status WARN --severity Low --category 'Resources' --check 'CPU' --evidence "$ev" --detail "$text" \
            --rec "Find the busy program ($where). A short spike is normal; constant high load is not."
    else
        msp_finding --status PASS --category 'Resources' --check 'CPU' --evidence "$ev" --detail "$text"
    fi
}
msp_check 'Resources' 'CPU' check_cpu

check_disks() {
    local lines system_mount='/' count=0
    if [ "$MSP_PLATFORM" = 'macOS' ]; then
        # User data lives on the Data volume; / is the read-only system snapshot in the same
        # container (same free space). Other local volumes are under /Volumes.
        [ -d /System/Volumes/Data ] && system_mount='/System/Volumes/Data'
        lines=$(df -kPl 2>/dev/null | awk -v s="$system_mount" 'NR > 1 && ($6 == s || $6 ~ /^\/Volumes\//)')
    else
        lines=$(df -kPl -x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs -x ramfs 2>/dev/null | awk 'NR > 1 && $6 !~ /^\/(snap|run|dev|sys|proc)(\/|$)/') # linux-only: df -x
    fi
    [ -n "$lines" ] || { printf 'df reported no volumes\n' >&2; return 1; }
    local dev size used avail cap mount size_gb free_gb pct status check ev text
    while read -r dev size used avail cap mount; do
        [ -n "$mount" ] && [ "${size:-0}" -gt 0 ] 2>/dev/null || continue
        size_gb=$((size / 1048576))
        free_gb=$((avail / 1048576))
        pct=$((avail * 100 / size))
        status=$(disk_status "$size_gb" "$free_gb" "$pct")
        check="Disk space $mount"
        [ "$mount" = "$system_mount" ] && check='System drive space'
        text="$mount: $free_gb GB free of $size_gb GB ($pct % free)."
        ev=$(msp_json_obj Mount "$mount" Device "$dev" SizeGB# "$size_gb" FreeGB# "$free_gb" PercentFree# "$pct")
        msp_data_row 'Disks' Mount "$mount" Device "$dev" SizeGB# "$size_gb" FreeGB# "$free_gb" PercentFree# "$pct" Status "$status"
        count=$((count + 1))
        case "$status" in
            FAIL)
                msp_finding --status FAIL --severity High --category 'Resources' --check "$check" --evidence "$ev" --detail "$text" \
                    --rec 'Free up space now (empty Downloads and the Trash; macOS: System Settings > General > Storage). Updates and apps fail when the disk is nearly full.' ;;
            WARN)
                msp_finding --status WARN --severity Medium --category 'Resources' --check "$check" --evidence "$ev" --detail "$text" \
                    --rec 'Free up space before it runs out; system updates need 15-25 GB free.' ;;
            *) msp_finding --status PASS --category 'Resources' --check "$check" --evidence "$ev" --detail "$text" ;;
        esac
    done <<EOF
$lines
EOF
    [ "$count" -gt 0 ] || { printf 'df reported no usable volumes\n' >&2; return 1; }
}
msp_check 'Resources' 'Disk space' check_disks

# =========================================================================================
msp_section 'Updates'
# =========================================================================================
check_pending() {
    local names='' security='' others='' source total=0 nsec=0 ev
    if [ "$MSP_PLATFORM" = 'macOS' ]; then
        local plist="$ROOT/Library/Preferences/com.apple.SoftwareUpdate" major name ver last
        major=$(sw_vers -productVersion 2>/dev/null | cut -d. -f1)
        names=$(defaults read "$plist" RecommendedUpdates 2>/dev/null | sed -n 's/.*"Display Name" = "\{0,1\}\([^";]*\)"\{0,1\};.*/\1/p' | awk '!seen[$0]++')
        last=$(defaults read "$plist" LastSuccessfulDate 2>/dev/null | cut -c1-10)
        source="macOS's last check (${last:-never})"
        while IFS= read -r name; do
            [ -n "$name" ] || continue
            case "$name" in
                *macOS*)
                    # A newer major macOS is an optional upgrade, not a missing update.
                    ver=$(printf '%s' "$name" | grep -oE '[0-9]+(\.[0-9]+)+' | head -n 1 | cut -d. -f1)
                    [ "$ver" = "$major" ] && security="$security${security:+; }$name"
                    ;;
                *'Security Response'* | *'Background Security'* | *Safari*) security="$security${security:+; }$name" ;;
                *) others="$others${others:+; }$name" ;;
            esac
        done <<EOF
$names
EOF
        [ -n "$security" ] && nsec=$(printf '%s\n' "$security" | tr ';' '\n' | grep -c .)
        [ -n "$others" ] && total=$(printf '%s\n' "$others" | tr ';' '\n' | grep -c .)
        total=$((total + nsec))
        security=$(printf '%s' "$security" | sed 's/; /, /g')
    elif msp_have apt-get; then
        local out
        # Simulation only (-s) against the local package lists: installs nothing, no network.
        out=$(apt-get -s -o Debug::NoLocking=1 dist-upgrade 2>/dev/null)
        total=$(printf '%s\n' "$out" | grep -c '^Inst ')
        security=$(printf '%s\n' "$out" | awk '/^Inst / && /-security/ { print $2 }' | head -n 8 | paste -sd ',' - | sed 's/,/, /g')
        nsec=$(printf '%s\n' "$out" | awk '/^Inst / && /-security/' | grep -c .)
        source='local package lists'
    elif msp_have dnf; then
        local out rc
        # -C: cache only, no network.
        out=$(msp_run_timeout 120 dnf -q -C check-update 2>&1)
        rc=$?
        if [ "$rc" -ne 0 ] && [ "$rc" -ne 100 ]; then printf 'dnf could not check: %s\n' "$(printf '%s' "$out" | head -n 1)" >&2; return 1; fi
        total=$(printf '%s\n' "$out" | awk 'NF == 3 && $1 ~ /\./' | grep -c .)
        local sec_list
        sec_list=$(dnf -q -C updateinfo list --security 2>/dev/null | awk 'NF >= 3 { print $3 }' | sort -u)
        nsec=$(printf '%s\n' "$sec_list" | grep -c .)
        security=$(printf '%s\n' "$sec_list" | head -n 8 | paste -sd ',' - | sed 's/,/, /g')
        source='dnf cache'
    else
        msp_skip 'Updates' 'Pending updates' 'Skipped: no apt or dnf package manager found.' 'Check updates with the distribution'\''s own tool.'
        return 0
    fi
    ev=$(msp_json_obj Pending# "$total" Security# "$nsec" Source "$source")
    if [ "$nsec" -gt 0 ]; then
        msp_finding --status WARN --severity High --category 'Updates' --check 'Pending updates' --evidence "$ev" \
            --detail "$total update(s) waiting, $nsec of them security updates ($security). Source: $source." \
            --rec 'Install them now (macOS: System Settings > General > Software Update; Linux: Software Updater, sudo apt upgrade or sudo dnf upgrade), then restart if asked.'
    elif [ "$total" -gt 0 ]; then
        msp_finding --status INFO --category 'Updates' --check 'Pending updates' --evidence "$ev" --detail "$total non-security update(s) waiting. Source: $source."
    else
        msp_finding --status PASS --category 'Updates' --check 'Pending updates' --evidence "$ev" \
            --detail "None waiting. Source: $source. For a live check run get-update-compliance-*.sh --online (A6)."
    fi
}
msp_check 'Updates' 'Pending updates' check_pending

check_last_install() {
    local last='' name=''
    if [ "$MSP_PLATFORM" = 'macOS' ]; then
        local line
        # Newest Apple update (macOS or a security response) in InstallHistory.plist.
        line=$(plutil -convert xml1 -o - "$ROOT/Library/Receipts/InstallHistory.plist" 2>/dev/null | awk '
            /<dict>/ { d = ""; n = ""; p = "" }
            /<key>date<\/key>/ { getline; d = $0 }
            /<key>displayName<\/key>/ { getline; n = $0 }
            /<key>processName<\/key>/ { getline; p = $0 }
            /<\/dict>/ { gsub(/<[^>]*>|\t/, "", d); gsub(/<[^>]*>|\t/, "", n); gsub(/<[^>]*>|\t/, "", p); if (d != "") print d "|" n "|" p }' |
            awk -F'|' '$3 ~ /softwareupdated/ && $2 ~ /^macOS|Background Security|Security Response|Rapid Security/' | tail -n 1)
        if [ -n "$line" ]; then
            last=$(date -j -u -f '%Y-%m-%dT%H:%M:%SZ' "${line%%|*}" '+%s' 2>/dev/null)
            name=$(printf '%s' "$line" | cut -d'|' -f2)
        fi
    elif [ -f "$ROOT/var/log/dpkg.log" ]; then
        local line
        line=$(cat "$ROOT/var/log/dpkg.log" "$ROOT/var/log/dpkg.log.1" 2>/dev/null | awk '$3 == "status" && $4 == "installed" { print $1 " " $2 }' | sort | tail -n 1)
        [ -n "$line" ] && last=$(date -d "$line" +%s 2>/dev/null) # linux-only: date -d
    elif msp_have rpm; then
        last=$(rpm -qa --qf '%{INSTALLTIME}\n' 2>/dev/null | sort -n | tail -n 1)
    fi
    if [ -z "$last" ]; then
        msp_finding --status WARN --severity Medium --category 'Updates' --check 'Last update installed' \
            --detail 'No update installation date could be found.' --rec 'Check that updates are being installed (macOS: Software Update; Linux: Software Updater, apt or dnf history).'
        return 0
    fi
    local age=$(((NOW - last) / 86400)) ev
    ev=$(msp_json_obj LastInstall "$(ymd "$last")" DaysAgo# "$age")
    if [ "$age" -gt 75 ]; then
        msp_finding --status FAIL --severity High --category 'Updates' --check 'Last update installed' --evidence "$ev" \
            --detail "The last update${name:+ ($name)} was installed $(ymd "$last") ($age days ago). Security updates are certainly missing." \
            --rec 'Install all updates and restart; run get-update-compliance-*.sh (A6) for the reason updates stopped.'
    elif [ "$age" -gt 45 ]; then
        msp_finding --status WARN --severity Medium --category 'Updates' --check 'Last update installed' --evidence "$ev" \
            --detail "The last update${name:+ ($name)} was installed $(ymd "$last") ($age days ago)." --rec 'Install pending updates and restart.'
    else
        msp_finding --status PASS --category 'Updates' --check 'Last update installed' --evidence "$ev" --detail "${name:+$name, }$(ymd "$last") ($age days ago)."
    fi
}
msp_check 'Updates' 'Last update installed' check_last_install

msp_complete "$OUTPUT"
exit 0
