#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2329  # The embedded helper defines globals and functions this script does not use; checks run through msp_check.
# get-disk-space-report.sh - read-only disk space report for a Mac or Linux computer: free space
# on every local volume, where the space went, how much is known to be reclaimable, disk health,
# and the cleanup steps to take by hand. Deletes nothing. The Windows version is
# Get-DiskSpaceReport.ps1 (same checks and finding IDs).
#
# Usage:  bash get-disk-space-report.sh [--time-limit SECONDS] [--top N] [--output DIR] [--help]
#
# Options:
#   --time-limit SECONDS  Total time for measuring folders (10-600, default 60): half for the home
#                         folder, the rest for the system volume; each reclaimable item gets up
#                         to 20 seconds of its own.
#   --top N               How many of the largest folders to list for each place (5-50, default 10).
#   --output DIR          Also save results as JSON and CSV (toolkit schema 2.0) with Volumes,
#                         LargestFolders, Reclaimable and NextSteps tables.
#   --help                Show this help.
#
# Checks
#   Disk space          Every local volume: size, free, percent free. Less than 5 % or 5 GB free
#                       = FAIL, less than 15 % or 20 GB = WARN. Volumes under 50 GB (/boot, EFI)
#                       are judged on the percentage only. macOS: the Data volume and /Volumes.
#   Largest folders     The biggest folders one and two levels under the home folder and the
#                       system volume (du, one file system, symbolic links not followed). Each
#                       folder is measured against the time limit, so it never hangs on a huge
#                       disk; folders not finished in time are named.
#   Reclaimable space   Measured, never deleted. macOS: user caches, Trash, iPhone/iPad backups,
#                       Xcode data (if present). Linux: package caches, the systemd journal, Trash,
#                       ~/.cache, old (disabled) snap revisions.
#   Disk health         macOS: SMART status of the internal disks (diskutil). Linux: SMART only if
#                       smartctl is installed (run with sudo), and disk I/O errors in the kernel
#                       log of the last 7 days (journal).
#   What to do          Cleanup steps by hand, biggest first.
#
# Examples:
#   bash get-disk-space-report.sh
#   bash get-disk-space-report.sh --time-limit 180 --output ~/Desktop/Ticket123
#
# Purpose       : "Where did the disk space go, and what can safely be cleaned?"
# Use Case      : Low disk space warnings, updates failing for lack of space, slow computers.
# Scope         : This computer only. No network traffic.
# Risk Level    : Read-Only -- reads volume information, folder sizes and logs; deletes nothing.
# Prerequisites : macOS 12+ or Linux | bash 3.2+ | root: No (sudo measures other users' and
#                 system folders completely; Linux SMART needs sudo and smartctl). macOS: the
#                 Trash and iPhone backups need Full Disk Access for Terminal to be measured.
# Version       : 1.0.0
# Limitations   : Sizes are du's disk usage of what this account can read. A walk stopped by the
#                 time limit is a minimum. MSP_TEST_ROOT (development tests only) prefixes the
#                 system paths read.

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
TIME_LIMIT=60
TOP=10
while [ $# -gt 0 ]; do
    case "$1" in
        --output)
            OUTPUT=${2-}
            [ -n "$OUTPUT" ] || { printf 'Missing folder after --output\n' >&2; exit 2; }
            shift 2
            ;;
        --time-limit)
            TIME_LIMIT=${2-}
            shift 2
            ;;
        --top)
            TOP=${2-}
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
msp_param TimeLimit "$TIME_LIMIT"
msp_param Top "$TOP"
msp_init 'get-disk-space-report' "$SCRIPT_VERSION" 'B5' 'Read-Only' 'Disk space: volumes, largest folders, reclaimable space, disk health (read-only; deletes nothing)' \
    'other users'"'"' and system folders (complete sizes), SMART on Linux'

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
check_range 'time-limit' "$TIME_LIMIT" 10 600
check_range 'top' "$TOP" 5 50
if [ "$range_ok" -eq 0 ]; then
    msp_complete "$OUTPUT"
    exit 1
fi

ROOT=${MSP_TEST_ROOT:-}
STEPS="$MSP_WORK_DIR/steps.txt"
: >"$STEPS"
VOLUME_LINE=''

fmt_kb() {
    # fmt_kb KB -> "12.3 GB" / "850 MB" / "12 KB"
    awk -v k="${1:-0}" 'BEGIN { if (k >= 1048576) printf "%.1f GB", k / 1048576; else if (k >= 1024) printf "%d MB", k / 1024; else printf "%d KB", k }'
}
add_step() {
    # add_step KB TEXT - one cleanup step; sorted biggest first at the end.
    printf '%s\t%s\n' "$1" "$2" >>"$STEPS"
}
volume_status() {
    # volume_status SIZE_GB FREE_GB PERCENT_FREE -> PASS / WARN / FAIL (whole numbers).
    local size=$1 free=$2 pct=$3 small=0
    [ "$size" -lt 50 ] && small=1
    if [ "$pct" -lt 5 ] || { [ "$small" -eq 0 ] && [ "$free" -lt 5 ]; }; then printf 'FAIL'; return 0; fi
    if [ "$pct" -lt 15 ] || { [ "$small" -eq 0 ] && [ "$free" -lt 20 ]; }; then printf 'WARN'; return 0; fi
    printf 'PASS'
}
measure_kb() {
    # measure_kb SECONDS PATH... -> "KB PARTIAL DENIED" (du -sk of each path that exists).
    local secs=$1 total=0 partial=0 denied=0 p out rc kb
    shift
    for p in "$@"; do
        [ -e "$p" ] || continue
        out=$(msp_run_timeout "$secs" du -sk "$p" 2>"$MSP_WORK_DIR/du.err")
        rc=$?
        [ "$rc" -eq 124 ] && partial=1
        [ -s "$MSP_WORK_DIR/du.err" ] && denied=1
        kb=$(printf '%s\n' "$out" | awk 'NR == 1 { print $1 + 0 }')
        total=$((total + ${kb:-0}))
    done
    printf '%s %s %s\n' "$total" "$partial" "$denied"
}

# =========================================================================================
msp_section 'Volumes'
# =========================================================================================
SYSTEM_MOUNT='/'
[ "$MSP_PLATFORM" = 'macOS' ] && [ -d /System/Volumes/Data ] && SYSTEM_MOUNT='/System/Volumes/Data'
check_volumes() {
    local lines count=0
    if [ "$MSP_PLATFORM" = 'macOS' ]; then
        # User data lives on the Data volume; / is the read-only system snapshot in the same
        # container. Other local volumes are under /Volumes.
        lines=$(df -kPl 2>/dev/null | awk -v s="$SYSTEM_MOUNT" 'NR > 1 && ($6 == s || $6 ~ /^\/Volumes\//)')
    else
        lines=$(df -kPl -x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs -x ramfs 2>/dev/null | awk 'NR > 1 && $6 !~ /^\/(snap|run|dev|sys|proc)(\/|$)/') # linux-only: df -x
    fi
    [ -n "$lines" ] || { printf 'df reported no volumes\n' >&2; return 1; }
    local dev size used avail cap mount size_gb free_gb pct status check ev text need
    while read -r dev size used avail cap mount; do
        [ -n "$mount" ] && [ "${size:-0}" -gt 0 ] 2>/dev/null || continue
        size_gb=$((size / 1048576))
        free_gb=$((avail / 1048576))
        pct=$((avail * 100 / size))
        status=$(volume_status "$size_gb" "$free_gb" "$pct")
        check="Disk space $mount"
        text="$mount: $(fmt_kb "$avail") free of $(fmt_kb "$size") ($pct % free)."
        ev=$(msp_json_obj Volume "$mount" Device "$dev" SizeGB# "$size_gb" FreeGB# "$free_gb" PercentFree# "$pct")
        msp_data_row 'Volumes' Volume "$mount" Device "$dev" SizeGB# "$size_gb" FreeGB# "$free_gb" PercentFree# "$pct" Status "$status"
        count=$((count + 1))
        case "$status" in
            FAIL)
                msp_finding --status FAIL --severity High --category 'Volumes' --check "$check" --evidence "$ev" --detail "$text" \
                    --rec 'Free space now (see What to do): updates and many programs fail when a volume is nearly full.' ;;
            WARN)
                msp_finding --status WARN --severity Medium --category 'Volumes' --check "$check" --evidence "$ev" --detail "$text" \
                    --rec 'Free space before it runs out (see What to do); system updates need 15-25 GB free.' ;;
            *) msp_finding --status PASS --category 'Volumes' --check "$check" --evidence "$ev" --detail "$text" ;;
        esac
        if [ "$status" != 'PASS' ] && { [ -z "$VOLUME_LINE" ] || [ "$mount" = "$SYSTEM_MOUNT" ]; }; then
            need=$(awk -v s="$size_gb" -v f="$free_gb" 'BEGIN { a = 20 - f; b = s * 0.15 - f; n = (a > b ? a : b); if (n < 0) n = 0; printf "%d", n + 0.999 }')
            VOLUME_LINE="$mount needs about $need GB more free space to be out of the warning zone; work down this list until it has."
        fi
    done <<EOF
$lines
EOF
    [ "$count" -gt 0 ] || { printf 'df reported no usable volumes\n' >&2; return 1; }
}
msp_check 'Volumes' 'Disk space' check_volumes

# =========================================================================================
msp_section 'Where the space went'
# =========================================================================================
device_of() {
    # device_of PATH - the file system device number (to stay on one file system).
    if [ "$MSP_PLATFORM" = 'macOS' ]; then stat -f %d "$1" 2>/dev/null; else stat -c %d "$1" 2>/dev/null; fi # linux-only: stat -c
}
largest_folders() {
    # largest_folders PLACE DIR SECONDS - du of each folder directly under DIR (one level more
    # inside it), one folder at a time against the deadline: a stopped du loses its buffered
    # output, so each finished folder is exact and the unfinished ones are named.
    local place=$1 dir=$2 secs=$3 deadline now left c name dev root_dev out rc unfinished='' note='' text='' top
    [ -d "$dir" ] || { msp_skip 'Folders' "Largest folders: $place" "$place not found ($dir)."; return 0; }
    dir=${dir%/}
    deadline=$(($(date +%s) + secs))
    root_dev=$(device_of "${dir:-/}")
    : >"$MSP_WORK_DIR/folders.txt"
    for c in "$dir"/* "$dir"/.[!.]*; do
        [ -d "$c" ] && [ ! -L "$c" ] || continue
        name=${c##*/}
        case "$dir/$name" in /proc | /sys | /dev | /run | "$ROOT"/proc | "$ROOT"/sys | "$ROOT"/dev | "$ROOT"/run) continue ;; esac
        dev=$(device_of "$c")
        [ -n "$root_dev" ] && [ -n "$dev" ] && [ "$dev" != "$root_dev" ] && continue
        now=$(date +%s)
        left=$((deadline - now))
        if [ "$left" -le 0 ]; then unfinished="$unfinished${unfinished:+, }$name"; continue; fi
        out=$(msp_run_timeout "$left" du -x -k -d 1 "$c" 2>/dev/null)
        rc=$?
        if [ "$rc" -eq 124 ]; then unfinished="$unfinished${unfinished:+, }$name"; continue; fi
        printf '%s\n' "$out" | awk -F '\t' -v c="$c" '$2 == c { printf "%s\t1\t%s\n", $1, $2; next } $2 != "" { printf "%s\t2\t%s\n", $1, $2 }' >>"$MSP_WORK_DIR/folders.txt"
    done
    sort -t "$(printf '\t')" -k1,1nr "$MSP_WORK_DIR/folders.txt" -o "$MSP_WORK_DIR/folders.txt"
    local kb level path
    while IFS="$(printf '\t')" read -r kb level path; do
        [ -n "$path" ] || continue
        msp_data_row 'LargestFolders' Place "$place" Folder "$path" Level# "$level" SizeGB "$(awk -v k="$kb" 'BEGIN { printf "%.2f", k / 1048576 }')"
    done <"$MSP_WORK_DIR/folders.txt"
    top=$(awk -F '\t' -v n="$TOP" '$2 == 1 && c < n { c++; print }' "$MSP_WORK_DIR/folders.txt")
    if [ -n "$unfinished" ]; then
        local shown more
        shown=$(printf '%s\n' "$unfinished" | awk -F ', ' '{ n = (NF < 8 ? NF : 8); for (i = 1; i <= n; i++) printf "%s%s", (i > 1 ? ", " : ""), $i; if (NF > 8) printf " and %d more", NF - 8 }')
        note=" Not finished within the $secs-second time limit (more time: --time-limit): $shown."
    fi
    [ "$MSP_IS_ADMIN" = 'true' ] || note="$note Without sudo, folders this account cannot read are not counted."
    if [ -z "$top" ]; then
        msp_finding --status INFO --category 'Folders' --check "Largest folders: $place" --detail "No folder under $dir could be measured.$note"
        return 0
    fi
    while IFS="$(printf '\t')" read -r kb level path; do
        local sub subkb inside=''
        sub=$(awk -F '\t' -v p="$path/" '$2 == 2 && index($3, p) == 1 { print; exit }' "$MSP_WORK_DIR/folders.txt")
        subkb=${sub%%"$(printf '\t')"*}
        if [ -n "$sub" ] && [ "${subkb:-0}" -ge 1048576 ]; then inside=" (most in ${sub##*/}, $(fmt_kb "$subkb"))"; fi
        text="$text${text:+; }${path##*/} $(fmt_kb "$kb")$inside"
        # The home folder's top three for What to do.
        if [ "$place" = 'Home folder' ]; then printf '%s\t%s\n' "${path##*/}" "$(fmt_kb "$kb")" >>"$MSP_WORK_DIR/home-top.txt"; fi
    done <<EOF
$top
EOF
    msp_finding --status INFO --category 'Folders' --check "Largest folders: $place" --detail "$dir: $text.$note"
}
HALF=$((TIME_LIMIT / 2))
msp_check 'Folders' 'Largest folders: Home folder' largest_folders 'Home folder' "$HOME" "$HALF"
msp_check 'Folders' 'Largest folders: System volume' largest_folders 'System volume' "$ROOT$SYSTEM_MOUNT" "$((TIME_LIMIT - HALF))"

# =========================================================================================
msp_section 'Reclaimable space (measured, not deleted)'
# =========================================================================================
RECLAIM="$MSP_WORK_DIR/reclaim.txt"
: >"$RECLAIM"
reclaim_item() {
    # reclaim_item NAME STEP PATH... - measures the paths that exist and records the item.
    local name=$1 step=$2 r kb partial denied note='' found=0 p
    shift 2
    for p in "$@"; do [ -e "$p" ] && found=1; done
    [ "$found" -eq 1 ] || return 0
    r=$(measure_kb 20 "$@")
    kb=${r%% *}
    partial=$(printf '%s' "$r" | awk '{ print $2 }')
    denied=$(printf '%s' "$r" | awk '{ print $3 }')
    [ "$partial" = 1 ] && note='at least: the time limit stopped the count'
    if [ "$denied" = 1 ]; then
        if [ "$MSP_PLATFORM" = 'macOS' ] && [ "$kb" -eq 0 ]; then note="${note:+$note; }not readable without Full Disk Access for Terminal"
        elif [ "$MSP_IS_ADMIN" != 'true' ]; then note="${note:+$note; }some of it is readable only with sudo"; fi
    fi
    printf '%s\t%s\t%s\t%s\n' "$kb" "$name" "$step" "$note" >>"$RECLAIM"
}
check_reclaimable() {
    if [ "$MSP_PLATFORM" = 'macOS' ]; then
        reclaim_item 'User caches' 'Quit the apps, then delete the contents of ~/Library/Caches (apps rebuild what they need; the next start is slower).' "$HOME/Library/Caches"
        reclaim_item 'Trash' 'Empty the Trash after the user confirms nothing in it is needed.' "$HOME/.Trash"
        reclaim_item 'iPhone and iPad backups' 'Finder > the device > Manage Backups (or Music/iTunes on older macOS): delete backups of devices no longer used.' "$HOME/Library/Application Support/MobileSync/Backup"
        reclaim_item 'Xcode data' 'In Xcode: Settings > Locations > Derived Data (delete); remove old archives in the Organizer; xcrun simctl delete unavailable.' \
            "$HOME/Library/Developer/Xcode/DerivedData" "$HOME/Library/Developer/Xcode/Archives" "$HOME/Library/Developer/Xcode/iOS DeviceSupport" "$HOME/Library/Developer/CoreSimulator/Devices"
    else
        reclaim_item 'Package cache' 'Clear the package cache: sudo apt clean (Debian/Ubuntu), sudo dnf clean packages (Fedora), sudo pacman -Sc (Arch).' \
            "$ROOT/var/cache/apt/archives" "$ROOT/var/cache/dnf" "$ROOT/var/cache/yum" "$ROOT/var/cache/pacman/pkg"
        local jkb='' line
        if msp_have journalctl; then
            line=$(journalctl --disk-usage 2>/dev/null | tail -n 1)
            jkb=$(printf '%s\n' "$line" | awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^[0-9.]+[KMGT]?B?$/ && $(i-1) == "up") { v = $i; u = substr(v, length(v)); sub(/[KMGTB]+$/, "", v); m = (u == "G" ? 1048576 : (u == "M" ? 1024 : (u == "T" ? 1073741824 : 1))); printf "%d", v * m } }')
        fi
        if [ -n "$jkb" ]; then
            printf '%s\t%s\t%s\t\n' "$jkb" 'System journal' 'Shrink the journal: sudo journalctl --vacuum-time=4weeks (keeps the last 4 weeks of logs).' >>"$RECLAIM"
        else
            reclaim_item 'System journal' 'Shrink the journal: sudo journalctl --vacuum-time=4weeks (keeps the last 4 weeks of logs).' "$ROOT/var/log/journal"
        fi
        reclaim_item 'Trash' 'Empty the Trash after the user confirms nothing in it is needed.' "$HOME/.local/share/Trash"
        reclaim_item 'User cache (~/.cache)' 'Close the programs, then delete the contents of ~/.cache (they rebuild what they need).' "$HOME/.cache"
        if msp_have snap; then
            local name rev kb=0 list='' f
            while read -r name rev; do
                f="$ROOT/var/lib/snapd/snaps/${name}_${rev}.snap"
                [ -f "$f" ] || continue
                kb=$((kb + $(du -k "$f" 2>/dev/null | awk '{ print $1 + 0 }')))
                list="$list${list:+, }$name rev $rev"
            done <<EOF
$(snap list --all 2>/dev/null | awk 'NR > 1 && /disabled/ { print $1, $3 }')
EOF
            [ -n "$list" ] && printf '%s\t%s\t%s\t\n' "$kb" 'Old snap revisions' "Remove the disabled snap revisions ($list): sudo snap remove NAME --revision=REV for each, and sudo snap set system refresh.retain=2 to keep fewer." >>"$RECLAIM"
        fi
    fi
    if [ ! -s "$RECLAIM" ]; then
        msp_finding --status INFO --category 'Reclaimable' --check 'Reclaimable space' --detail 'None of the known cleanup locations exist here.'
        return 0
    fi
    sort -t "$(printf '\t')" -k1,1nr "$RECLAIM" -o "$RECLAIM"
    # The note is last: it can be empty, and read collapses empty fields between tabs.
    local total=0 text='' kb name note step
    while IFS="$(printf '\t')" read -r kb name step note; do
        total=$((total + kb))
        msp_data_row 'Reclaimable' Item "$name" SizeGB "$(awk -v k="$kb" 'BEGIN { printf "%.2f", k / 1048576 }')" Note "$note"
        [ "$kb" -gt 0 ] || [ -n "$note" ] || continue
        text="$text${text:+; }$name $(fmt_kb "$kb")${note:+ ($note)}"
        [ "$kb" -ge 102400 ] && add_step "$kb" "$name ($(fmt_kb "$kb")): $step"
    done <"$RECLAIM"
    msp_finding --status INFO --category 'Reclaimable' --check 'Reclaimable space' \
        --evidence "$(msp_json_obj TotalKB# "$total")" --detail "$(fmt_kb "$total") in known cleanup locations: ${text:-all empty}. Nothing was deleted."
}
msp_check 'Reclaimable' 'Reclaimable space' check_reclaimable

# =========================================================================================
msp_section 'Disk health'
# =========================================================================================
check_health_mac() {
    local disks d info smart model rows='' bad=0 unknown=0
    disks=$(diskutil list internal physical 2>/dev/null | awk '/^\/dev\/disk[0-9]+/ { sub(/^\/dev\//, "", $1); print $1 }')
    [ -n "$disks" ] || { printf 'diskutil listed no internal disks\n' >&2; return 1; }
    for d in $disks; do
        info=$(diskutil info "$d" 2>/dev/null)
        smart=$(printf '%s\n' "$info" | sed -n 's/^ *SMART Status: *//p' | head -n 1)
        model=$(printf '%s\n' "$info" | sed -n 's/^ *Device \/ Media Name: *//p' | head -n 1)
        rows="$rows${rows:+; }$d (${model:-unknown}): ${smart:-unknown}"
        case "$smart" in
            Failing) bad=1 ;;
            Verified) ;;
            *) unknown=1 ;;
        esac
    done
    if [ "$bad" -eq 1 ]; then
        msp_finding --status FAIL --severity Critical --category 'Health' --check 'Disk health' --detail "SMART: $rows." \
            --rec 'Back up the data now and replace the disk; cleaning up space will not help a failing disk.'
        add_step 999999999999 'Back up the data now: a disk reports SMART failing. Replace the disk before cleaning anything up.'
    elif [ "$unknown" -eq 1 ]; then
        msp_finding --status INFO --category 'Health' --check 'Disk health' --detail "SMART: $rows (not every disk reports SMART to macOS)."
    else
        msp_finding --status PASS --category 'Health' --check 'Disk health' --detail "SMART: $rows."
    fi
}
check_smart_linux() {
    msp_have smartctl || { msp_skip 'Health' 'Disk health' 'smartctl (smartmontools) is not installed, and Linux has no built-in SMART reader. The kernel log check below still looks for disk errors.' 'For SMART: sudo apt install smartmontools (or dnf), then sudo smartctl -H /dev/sda.'; return 0; }
    local d out res rows='' bad=0
    for d in $(lsblk -dn -o NAME,TYPE 2>/dev/null | awk '$2 == "disk" { print $1 }'); do
        out=$(smartctl -H "/dev/$d" 2>/dev/null)
        res=$(printf '%s\n' "$out" | sed -n 's/.*self-assessment test result: *//p; s/^SMART Health Status: *//p' | head -n 1)
        rows="$rows${rows:+; }$d: ${res:-not reported}"
        case "$res" in FAILED* | *FAIL*) bad=1 ;; esac
    done
    [ -n "$rows" ] || { printf 'lsblk listed no disks\n' >&2; return 1; }
    if [ "$bad" -eq 1 ]; then
        msp_finding --status FAIL --severity Critical --category 'Health' --check 'Disk health' --detail "SMART: $rows." \
            --rec 'Back up the data now and replace the disk; cleaning up space will not help a failing disk.'
        add_step 999999999999 'Back up the data now: a disk reports SMART failing. Replace the disk before cleaning anything up.'
    else
        msp_finding --status PASS --category 'Health' --check 'Disk health' --detail "SMART: $rows."
    fi
}
check_disk_errors_linux() {
    msp_have journalctl || { msp_skip 'Health' 'Disk errors' 'There is no systemd journal to read.'; return 0; }
    local log n sample
    log=$(journalctl -k --since '7 days ago' --no-pager -q 2>/dev/null)
    if [ -z "$log" ] && [ "$MSP_IS_ADMIN" != 'true' ]; then
        msp_skip 'Health' 'Disk errors' 'The kernel log could not be read by this account.' "$(msp_root_hint) (or add the user to the adm / systemd-journal group)"
        return 0
    fi
    n=$(printf '%s\n' "$log" | grep -Eic 'I/O error|blk_update_request|critical medium error|ata[0-9.]+: .*(failed command|error)|nvme[0-9]+: .*(timeout|error)|EXT4-fs error|XFS .*(error|corruption)')
    if [ "$n" -gt 0 ]; then
        sample=$(printf '%s\n' "$log" | grep -Ei 'I/O error|blk_update_request|critical medium error|ata[0-9.]+: .*(failed command|error)|nvme[0-9]+: .*(timeout|error)|EXT4-fs error|XFS .*(error|corruption)' | tail -n 1 | sed 's/^.*kernel: //' | cut -c1-140)
        msp_finding --status WARN --severity High --category 'Health' --check 'Disk errors' --detail "$n disk or file system error line(s) in the kernel log in 7 days, last: $sample" \
            --rec 'Bad blocks or a failing cable/controller: check the backup, then the SMART status (sudo smartctl -a), and see B3 get-recent-critical-errors.sh.'
    else
        msp_finding --status PASS --category 'Health' --check 'Disk errors' --detail 'No disk or file system errors in the kernel log in 7 days.'
    fi
}
if [ "$MSP_PLATFORM" = 'macOS' ]; then
    msp_check 'Health' 'Disk health' check_health_mac
else
    msp_check --root 'SMART needs root.' 'Health' 'Disk health' check_smart_linux
    msp_check 'Health' 'Disk errors' check_disk_errors_linux
fi

# =========================================================================================
msp_section 'What to do (by hand; this script deleted nothing)'
# =========================================================================================
FINAL="$MSP_WORK_DIR/final.txt"
: >"$FINAL"
[ -n "$VOLUME_LINE" ] && printf '%s\n' "$VOLUME_LINE" >>"$FINAL"
sort -t "$(printf '\t')" -k1,1nr "$STEPS" | cut -f 2- >>"$FINAL"
if [ -s "$MSP_WORK_DIR/home-top.txt" ]; then
    printf 'Go through the largest folders in the home folder with the user (move old files to an external drive or cloud storage, delete what is not needed): %s.\n' \
        "$(head -n 3 "$MSP_WORK_DIR/home-top.txt" | awk -F '\t' '{ printf "%s%s %s", (NR > 1 ? ", " : ""), $1, $2 }')" >>"$FINAL"
fi
if [ "$MSP_PLATFORM" = 'macOS' ]; then
    printf '%s\n' 'System Settings > General > Storage shows more recommendations (optimise storage, empty Trash automatically).' >>"$FINAL"
else
    printf '%s\n' 'The Disk Usage Analyzer (baobab) shows the same folders graphically if the user wants to look for themselves.' >>"$FINAL"
fi
i=0
all=''
while IFS= read -r s; do
    [ -n "$s" ] || continue
    i=$((i + 1))
    printf '  %2d. %s\n' "$i" "$s"
    msp_data_row 'NextSteps' Step# "$i" Action "$s"
    all="$all${all:+ }$i. $s"
done <"$FINAL"
msp_finding --status INFO --category 'Summary' --check 'What to do' --detail "$all" --quiet

msp_complete "$OUTPUT"
exit 0
