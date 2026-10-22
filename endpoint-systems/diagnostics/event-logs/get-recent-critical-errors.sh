#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2329  # The embedded helper defines globals and functions this script does not use; checks run through msp_check.
# get-recent-critical-errors.sh - read-only summary of what went wrong on a Mac or Linux computer
# recently: system crashes (kernel panics), unexpected shutdowns, disk errors, services that
# failed, application crashes, and (Linux) the error messages in the system journal. The Windows
# version is Get-RecentCriticalErrors.ps1 (same check names and finding IDs).
#
# Usage:  bash get-recent-critical-errors.sh [--hours N] [--include-warnings]
#                                            [--include-system-log] [--output DIR]
#
# Options:
#   --hours N           How far back to look, 1-168 (default 48).
#   --include-warnings  Linux: also count journal warnings (priority 4) in Error events.
#   --include-system-log
#                       macOS: also search the unified system log for kernel disk errors
#                       (I/O and media errors). Slow: a 48-hour search can take a minute or
#                       more (stopped after 10 minutes). Linux always reads the journal.
#   --output DIR        Also save results as JSON and CSV (toolkit schema 2.0), with Events
#                       (newest 500) and Sources tables.
#   --help              Show this help.
#
# Checks           macOS                                 Linux
#   System crashes   kernel panic reports                  kernel panic / oops / BUG / machine
#                    (/Library/Logs/DiagnosticReports)     check messages, kdump folders in /var/crash
#   Unexpected       a restart with no shutdown recorded   boots that ended in "crash" (last -x)
#   shutdowns        before it (last reboot shutdown)
#   Disk errors      SMART status of internal disks; with  kernel I/O, file system and drive errors
#                    --include-system-log also kernel I/O
#                    and media errors in the unified log
#   Service failures crash reports of system processes     systemd units that failed
#   Application      crash reports in ~/Library/Logs/      segfaults in the kernel log, apport crash
#   crashes          DiagnosticReports                     files in /var/crash
#   Error events     not counted (macOS logs thousands     journal messages of priority 0-3, top
#                    of routine errors)                    sources
#
# Examples:
#   bash get-recent-critical-errors.sh
#   bash get-recent-critical-errors.sh --hours 168 --output ~/Desktop/Ticket123
#   bash get-recent-critical-errors.sh --include-system-log
#
# Purpose       : Answer "what has gone wrong on this computer lately?" in one screen.
# Use Case      : Crashes, freezes, restarts, "it was fine yesterday" tickets.
# Scope         : This computer only. No network traffic.
# Risk Level    : Read-Only -- reads crash report names and dates, login records, disk status and
#                 the system journal; never opens crash report contents; changes nothing.
# Prerequisites : macOS 12+ or Linux (systemd journal for most checks) | bash 3.2+ | root: No
#                 (Linux: sudo, or membership of the adm / systemd-journal group, is needed to
#                 read system messages)
# Version       : 1.1.0
# Limitations   : macOS: the unified log is only searched with --include-system-log (a 48-hour
#                 search takes a minute or more); without it disk errors are judged by SMART
#                 status only. Linux: a kernel panic is often not
#                 written to the journal before the computer stops; it shows up as an unexpected
#                 shutdown instead. Other users' application crash reports are not listed.
#                 MSP_TEST_ROOT (development tests only) prefixes the files read.

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

SCRIPT_VERSION='1.1.0'
OUTPUT=''
HOURS=48
WARNINGS=0
SYSTEM_LOG=0
while [ $# -gt 0 ]; do
    case "$1" in
        --output)
            OUTPUT=${2-}
            [ -n "$OUTPUT" ] || { printf 'Missing folder after --output\n' >&2; exit 2; }
            shift 2
            ;;
        --hours)
            HOURS=${2-}
            case "$HOURS" in '' | *[!0-9]*) printf -- '--hours needs 1-168\n' >&2; exit 2 ;; esac
            if [ "$HOURS" -lt 1 ] || [ "$HOURS" -gt 168 ]; then printf -- '--hours needs 1-168\n' >&2; exit 2; fi
            shift 2
            ;;
        --include-warnings) WARNINGS=1; shift ;;
        --include-system-log) SYSTEM_LOG=1; shift ;;
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
msp_param Hours "$HOURS"
[ "$WARNINGS" -eq 1 ] && msp_param IncludeWarnings 1
[ "$SYSTEM_LOG" -eq 1 ] && msp_param IncludeSystemLog 1
msp_init 'get-recent-critical-errors' "$SCRIPT_VERSION" 'B3' 'Read-Only' "Crashes, shutdowns, disk/service errors in the last $HOURS hours (read-only)" \
    'system journal messages (Linux, unless in the adm or systemd-journal group)'

ROOT=${MSP_TEST_ROOT:-}
NOW=$(date +%s)
SINCE=$((NOW - HOURS * 3600))

file_mtime() {
    if [ "$MSP_PLATFORM" = 'macOS' ]; then stat -f %m "$1" 2>/dev/null; else stat -c %Y "$1" 2>/dev/null; fi # linux-only: stat -c
}
ymdhm() {
    if [ "$MSP_PLATFORM" = 'macOS' ]; then date -r "$1" '+%Y-%m-%d %H:%M'; else date -d "@$1" '+%Y-%m-%d %H:%M'; fi # linux-only: date -d
}

stability() {
    # stability CHECK COUNT STATUS SEVERITY WHAT ITEMS REC - PASS when COUNT is 0, otherwise
    # STATUS with up to 5 items listed.
    local check=$1 count=$2 status=$3 severity=$4 what=$5 items=$6 rec=$7
    if [ "$count" -eq 0 ]; then
        msp_finding --status PASS --category 'Stability' --check "$check" --detail "None in the last $HOURS hours."
        return 0
    fi
    items=$(printf '%s\n' "$items" | grep . | head -n 5 | paste -sd ';' - | sed 's/;/; /g')
    msp_finding --status "$status" --severity "$severity" --category 'Stability' --check "$check" \
        --evidence "$(msp_json_obj Count# "$count" Hours# "$HOURS")" \
        --detail "$count $what in the last $HOURS hours: $items" --rec "$rec"
}

recent_files() {
    # recent_files DIR... - "epoch|name" for files in DIR changed since the window start, newest first.
    local d f m
    for d in "$@"; do
        for f in "$d"/*; do
            [ -f "$f" ] || continue
            m=$(file_mtime "$f")
            [ -n "$m" ] && [ "$m" -ge "$SINCE" ] && printf '%s|%s\n' "$m" "${f##*/}"
        done
    done | sort -rn
}

crash_reports() {
    # crash_reports DIR... - "epoch|process" for crash reports (.ips named <process>-<date>.ips)
    # in the window. Resource reports (.diag), JetsamEvent (memory pressure) and panics are left out.
    recent_files "$@" | awk -F'|' '$2 ~ /\.ips$/ && $2 !~ /^(JetsamEvent|panic|Kernel)/ && $2 ~ /-[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9]/ {
        p = $2; sub(/-[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9].*/, "", p); sub(/^ExcUserFault_/, "", p); print $1 "|" p }'
}

event_row() {
    # event_row EPOCH LEVEL SOURCE MESSAGE - one row of the Events table.
    msp_data_row 'Events' Time "$(ymdhm "$1")" Level "$2" Source "$3" Message "$(printf '%s' "$4" | cut -c1-300)"
}

if [ "$MSP_PLATFORM" = 'macOS' ]; then
    SYS_REPORTS="$ROOT/Library/Logs/DiagnosticReports"
    USER_REPORTS="$ROOT$HOME/Library/Logs/DiagnosticReports"
    if [ -n "${SUDO_USER:-}" ]; then
        USER_REPORTS="$ROOT$(dscl . -read "/Users/$SUDO_USER" NFSHomeDirectory 2>/dev/null | awk '{ print $2 }')/Library/Logs/DiagnosticReports"
    fi

    # =====================================================================================
    msp_section "Stability, last $HOURS hours"
    # =====================================================================================
    check_panics() {
        local list count
        list=$(recent_files "$SYS_REPORTS" "$SYS_REPORTS/Retired" | awk -F'|' '$2 ~ /panic|^Kernel/')
        count=$(printf '%s\n' "$list" | grep -c .)
        printf '%s\n' "$list" | while IFS='|' read -r m n; do [ -n "$n" ] && event_row "$m" 'Critical' 'kernel panic' "$n"; done
        stability 'System crashes' "$count" FAIL High 'kernel panic(s)' \
            "$(printf '%s\n' "$list" | while IFS='|' read -r m n; do [ -n "$n" ] && printf '%s %s\n' "$(ymdhm "$m")" "$n"; done)" \
            'Note what the Mac was doing; update macOS and remove old kernel extensions/drivers. Repeated panics need escalation with the panic reports from /Library/Logs/DiagnosticReports.'
    }
    msp_check 'Stability' 'System crashes' check_panics

    check_shutdowns() {
        # "last reboot shutdown" lists newest first. A reboot whose next (older) line is not a
        # shutdown means the Mac went down without shutting down: power loss, a forced power-off
        # or a panic. Dates have no year: assume the most recent one not in the future.
        local rows y count=0 items='' prev_kind='' prev_time=''
        y=$(date '+%Y')
        rows=$(last reboot shutdown 2>/dev/null | awk '$1 == "reboot" || $1 == "shutdown" { print $1 "|" $(NF - 3) " " $(NF - 2) " " $(NF - 1) " " $NF }')
        [ -n "$rows" ] || { msp_finding --status INFO --category 'Stability' --check 'Unexpected shutdowns' --detail 'macOS has no restart records to compare.'; return 0; }
        local kind when e
        while IFS='|' read -r kind when; do
            [ -n "$kind" ] || continue
            if [ "$prev_kind" = 'reboot' ] && [ "$kind" != 'shutdown' ]; then
                e=$(date -j -f '%a %b %d %H:%M %Y' "$prev_time $y" '+%s' 2>/dev/null)
                [ -n "$e" ] && [ "$e" -gt "$NOW" ] && e=$(date -j -f '%a %b %d %H:%M %Y' "$prev_time $((y - 1))" '+%s' 2>/dev/null)
                if [ -n "$e" ] && [ "$e" -ge "$SINCE" ]; then
                    count=$((count + 1))
                    items="$items$(ymdhm "$e") restart without a shutdown before it
"
                    event_row "$e" 'Error' 'unexpected shutdown' 'Restarted without a recorded shutdown (power loss, forced power-off or panic).'
                fi
            fi
            prev_kind=$kind
            prev_time=$when
        done <<EOF
$rows
EOF
        stability 'Unexpected shutdowns' "$count" WARN High 'unexpected shutdown(s)' "$items" \
            'Ask the client: power cut, battery ran out, or held the power button because it froze? Freezes point to software, overheating or failing hardware.'
    }
    msp_check 'Stability' 'Unexpected shutdowns' check_shutdowns

    check_smart() {
        local disks d info status name bad='' ok='' count=0
        disks=$(diskutil list internal physical 2>/dev/null | awk '/^\/dev\/disk/ { sub(/^\/dev\//, "", $1); print $1 }')
        [ -n "$disks" ] || { printf 'diskutil listed no internal disks\n' >&2; return 1; }
        for d in $disks; do
            info=$(diskutil info "$d" 2>/dev/null)
            status=$(printf '%s\n' "$info" | sed -n 's/^ *SMART Status: *//p' | head -n 1)
            name=$(printf '%s\n' "$info" | sed -n 's/^ *Device \/ Media Name: *//p' | head -n 1)
            case "$status" in
                Verified) ok="$ok${ok:+, }$d ($name)" ;;
                '' | 'Not Supported') ;;
                *) bad="$bad${bad:+, }$d ($name): $status"; count=$((count + 1)) ;;
            esac
        done
        if [ "$count" -gt 0 ]; then
            msp_finding --status FAIL --severity High --category 'Stability' --check 'Disk errors' --detail "SMART reports a failing disk: $bad." \
                --rec 'Back up the client'\''s files now (Time Machine or copy), then replace the disk or the Mac. A failing SMART status does not recover.'
        elif [ -n "$ok" ]; then
            msp_finding --status PASS --category 'Stability' --check 'Disk errors' --detail "SMART status verified: $ok.$([ "$SYSTEM_LOG" -eq 1 ] || printf '%s' ' (The system log was not searched; --include-system-log adds it.)')"
        else
            msp_finding --status INFO --category 'Stability' --check 'Disk errors' --detail 'The internal disk does not report SMART status; disk health could not be judged.'
        fi
    }
    msp_check 'Stability' 'Disk errors' check_smart

    check_log_disk() {
        # Kernel messages only (process == "kernel"), so the search does not match its own
        # command line, which "log" records too.
        local out rc lines count items
        msp_say 33 "  Searching the system log for the last $HOURS hours. This can take a minute or more..."
        out=$(msp_run_timeout 600 log show --style compact --last "${HOURS}h" \
            --predicate 'process == "kernel" AND (eventMessage CONTAINS[c] "I/O error" OR eventMessage CONTAINS[c] "media error" OR eventMessage CONTAINS[c] "disk error")' 2>&1)
        rc=$?
        if [ "$rc" -ne 0 ]; then
            [ "$rc" -eq 124 ] && { printf 'timed out\n' >&2; return 1; }
            printf '%s\n' "$(printf '%s\n' "$out" | head -n 1)" >&2
            return 1
        fi
        lines=$(printf '%s\n' "$out" | grep -E '^[0-9]{4}-[0-9]{2}-[0-9]{2} ')
        count=$(printf '%s\n' "$lines" | grep -c .)
        items=$(printf '%s\n' "$lines" | grep . | sed 's/^[^ ]* [^ ]* *[A-Za-z]* *kernel[^ ]* //' | cut -c1-90 | awk '!seen[$0]++')
        stability 'Disk errors in the system log' "$count" FAIL High 'kernel disk error message(s)' "$items" \
            'Back up the client'\''s files now, then run Disk Utility > First Aid and check the disk'\''s SMART status. Repeated I/O errors usually mean the disk or its cable is failing.'
    }
    if [ "$SYSTEM_LOG" -eq 1 ]; then
        msp_check 'Stability' 'Disk errors in the system log' check_log_disk
    fi

    check_service_crashes() {
        local list count procs
        list=$(crash_reports "$SYS_REPORTS" "$SYS_REPORTS/Retired")
        count=$(printf '%s\n' "$list" | grep -c .)
        printf '%s\n' "$list" | while IFS='|' read -r m p; do [ -n "$p" ] && event_row "$m" 'Error' 'crash report (system)' "$p"; done
        procs=$(printf '%s\n' "$list" | cut -d'|' -f2 | grep . | sort | uniq -c | sort -rn | awk '{ c = $1; $1 = ""; sub(/^ /, ""); print $0 " x" c }')
        stability 'Service failures' "$count" WARN Medium 'crash report(s) of system processes' "$procs" \
            'Update macOS. A system process that keeps crashing usually comes from a third-party extension, agent or a damaged install; escalate with the reports in /Library/Logs/DiagnosticReports.'
    }
    msp_check 'Stability' 'Service failures' check_service_crashes

    check_app_crashes() {
        local list count procs
        list=$(crash_reports "$USER_REPORTS" "$USER_REPORTS/Retired")
        count=$(printf '%s\n' "$list" | grep -c .)
        printf '%s\n' "$list" | while IFS='|' read -r m p; do [ -n "$p" ] && event_row "$m" 'Error' 'crash report (app)' "$p"; done
        procs=$(printf '%s\n' "$list" | cut -d'|' -f2 | grep . | sort | uniq -c | sort -rn | awk '{ c = $1; $1 = ""; sub(/^ /, ""); print $0 " x" c }')
        stability 'Application crashes' "$count" WARN Low 'application crash report(s)' "$procs" \
            'Update or reinstall the apps that crash most. Crashes in many different apps at once point to the system (macOS version, memory, disk).'
    }
    msp_check 'Stability' 'Application crashes' check_app_crashes

    msp_section 'All critical and error events'
    msp_finding --status INFO --category 'Events' --check 'Error events' \
        --detail "Not counted on macOS: the unified log holds thousands of routine errors a day. The checks above cover panics, shutdowns, disk health and crash reports$([ "$SYSTEM_LOG" -eq 1 ] && printf '%s' ', plus kernel disk errors from the system log' || printf '%s' '; --include-system-log adds kernel disk errors from the system log (slow)')."
else
    # =====================================================================================
    msp_section "Journal, last $HOURS hours"
    # =====================================================================================
    JOURNAL=0          # 1 = system journal readable
    KLOG=''            # kernel messages in the window (all priorities)
    PID1=''            # systemd (PID 1) messages up to warning
    check_journal() {
        if ! msp_have journalctl; then
            msp_skip 'Events' 'Journal access' 'Skipped: no systemd journal (journalctl) on this computer; journal-based checks are not run.' 'Check /var/log/syslog or /var/log/messages by hand.'
            return 0
        fi
        local hint
        hint=$(journalctl -q --no-pager -n 1 2>&1 >/dev/null)
        if printf '%s' "$hint" | grep -qiE 'not seeing messages|insufficient permissions|No journal files were opened'; then
            msp_skip 'Events' 'Journal access' 'Skipped: this account can only see its own journal messages, not the system'\''s.' \
                "$(msp_root_hint) (or add the account to the adm / systemd-journal group)"
            return 0
        fi
        JOURNAL=1
        KLOG=$(journalctl -q --no-pager -o short-iso -k --since "@$SINCE" 2>/dev/null)
        PID1=$(journalctl -q --no-pager -o short-iso _PID=1 -p 0..4 --since "@$SINCE" 2>/dev/null)
        msp_finding --status INFO --category 'Events' --check 'Journal access' --detail 'System journal readable.'
    }
    msp_check 'Events' 'Journal access' check_journal

    journal_epoch() {
        # "2026-10-19T10:00:00+0000 host ..." -> epoch
        date -d "$(printf '%s' "$1" | cut -d' ' -f1)" +%s 2>/dev/null # linux-only: date -d
    }
    skip_without_journal() {
        msp_skip 'Stability' "$1" 'Skipped: the system journal is not readable here (see Journal access).' "$(msp_root_hint)"
    }

    # =====================================================================================
    msp_section "Stability, last $HOURS hours"
    # =====================================================================================
    check_kernel_crashes() {
        local lines='' dumps='' count=0 items='' line d m
        if [ "$JOURNAL" -eq 1 ]; then
            lines=$(printf '%s\n' "$KLOG" | grep -E 'Kernel panic|Oops:|BUG: |general protection fault|soft lockup|hard LOCKUP|Machine check events logged|Hardware Error')
        fi
        # kdump (Ubuntu kdump-tools, Fedora kexec-tools) writes one folder per crash.
        for d in "$ROOT"/var/crash/*/; do
            d=${d%/}
            [ -d "$d" ] || continue
            m=$(file_mtime "$d")
            [ -n "$m" ] && [ "$m" -ge "$SINCE" ] && dumps="$dumps$(ymdhm "$m") crash dump ${d##*/}
"
        done
        [ -n "$lines" ] && count=$(printf '%s\n' "$lines" | grep -c .)
        [ -n "$dumps" ] && count=$((count + $(printf '%s' "$dumps" | grep -c .)))
        while IFS= read -r line; do
            [ -n "$line" ] || continue
            items="$items$(printf '%s' "$line" | cut -c1-16 | tr 'T' ' ') $(printf '%s' "$line" | sed 's/^[^ ]* [^ ]* [^:]*: //' | cut -c1-80)
"
            event_row "$(journal_epoch "$line")" 'Critical' 'kernel' "$(printf '%s' "$line" | sed 's/^[^ ]* [^ ]* [^:]*: //')"
        done <<EOF
$lines
EOF
        if [ "$JOURNAL" -eq 0 ] && [ -z "$dumps" ]; then skip_without_journal 'System crashes'; return 0; fi
        stability 'System crashes' "$count" FAIL High 'kernel crash message(s) or crash dump(s)' "$items$dumps" \
            'Update the system (kernel and drivers, especially graphics and Wi-Fi). Repeated kernel crashes point to drivers or failing hardware (memory, disk); escalate with journalctl -k output.'
    }
    msp_check 'Stability' 'System crashes' check_kernel_crashes

    check_shutdowns() {
        # last -x -F: a boot that ended without a shutdown shows "- crash" instead of an end time.
        local rows count=0 items='' e
        rows=$(last -x -F 2>/dev/null | awk '$1 == "reboot" && / crash/ { print $5 " " $6 " " $7 " " $8 " " $9 }')
        while IFS= read -r when; do
            [ -n "$when" ] || continue
            e=$(date -d "$when" +%s 2>/dev/null) # linux-only: date -d
            [ -n "$e" ] && [ "$e" -ge "$SINCE" ] || continue
            count=$((count + 1))
            items="${items}boot of $(ymdhm "$e") ended without a shutdown
"
            event_row "$e" 'Error' 'unexpected shutdown' 'Boot ended without a recorded shutdown (power loss, forced power-off, freeze or kernel panic).'
        done <<EOF
$rows
EOF
        stability 'Unexpected shutdowns' "$count" WARN High 'unexpected shutdown(s)' "$items" \
            'Ask the client: power cut, battery ran out, or held the power button because it froze? Freezes point to drivers, overheating or failing hardware.'
    }
    msp_check 'Stability' 'Unexpected shutdowns' check_shutdowns

    check_disk_errors() {
        [ "$JOURNAL" -eq 1 ] || { skip_without_journal 'Disk errors'; return 0; }
        local lines count items
        lines=$(printf '%s\n' "$KLOG" | grep -E 'I/O error|EXT4-fs error|EXT4-fs warning.*error|XFS \(.*\): .*(error|[Cc]orruption)|BTRFS (error|critical)|critical medium error|Medium Error|ata[0-9.]+: (failed command|exception)|nvme[0-9]+: .*(timeout|I/O|Abort|reset)|blk_update_request')
        count=$(printf '%s\n' "$lines" | grep -c .)
        items=$(printf '%s\n' "$lines" | grep . | sed 's/^[^ ]* [^ ]* [^:]*: //' | sed 's/^\[ *[0-9.]*\] //' | cut -c1-90 | awk '!seen[$0]++')
        printf '%s\n' "$lines" | while IFS= read -r line; do [ -n "$line" ] && event_row "$(journal_epoch "$line")" 'Error' 'kernel (disk)' "$(printf '%s' "$line" | sed 's/^[^ ]* [^ ]* [^:]*: //')"; done
        stability 'Disk errors' "$count" FAIL High 'disk or file system error message(s)' "$items" \
            'Back up the client'\''s files now, then check the drive (smartctl -a, or GNOME Disks > SMART Data). I/O errors usually mean the drive or its cable is failing.'
    }
    msp_check 'Stability' 'Disk errors' check_disk_errors

    check_units() {
        [ "$JOURNAL" -eq 1 ] || { skip_without_journal 'Service failures'; return 0; }
        local lines count units
        lines=$(printf '%s\n' "$PID1" | grep -E 'Failed with result|Failed to start ')
        count=$(printf '%s\n' "$lines" | grep -c .)
        units=$(printf '%s\n' "$lines" | grep . | sed -n 's/.*systemd\[1\]: \([^:]*\): Failed with result.*/\1/p; s/.*systemd\[1\]: Failed to start \(.*\)\.$/\1/p' | sort | uniq -c | sort -rn | awk '{ c = $1; $1 = ""; sub(/^ /, ""); print $0 " x" c }')
        printf '%s\n' "$lines" | while IFS= read -r line; do [ -n "$line" ] && event_row "$(journal_epoch "$line")" 'Error' 'systemd' "$(printf '%s' "$line" | sed 's/^[^ ]* [^ ]* [^:]*: //')"; done
        stability 'Service failures' "$count" WARN Medium 'service failure message(s)' "$units" \
            'Check each unit: systemctl status <unit> and journalctl -u <unit>. A service that keeps failing usually belongs to a package that needs repair, updating or removing.'
    }
    msp_check 'Stability' 'Service failures' check_units

    check_app_crashes() {
        local segv='' apport='' count=0 items
        [ "$JOURNAL" -eq 1 ] && segv=$(printf '%s\n' "$KLOG" | grep -E 'segfault at|traps: .* general protection' | sed -n 's/.*: \([^ []*\)\[[0-9]*\]: segfault at.*/\1/p; s/.*traps: \([^ []*\)\[[0-9]*\] general protection.*/\1/p')
        # Ubuntu's apport: /var/crash/_usr_bin_firefox.1000.crash -> /usr/bin/firefox
        apport=$(recent_files "$ROOT/var/crash" | awk -F'|' '$2 ~ /\.crash$/ { n = $2; sub(/\.[0-9]+\.crash$/, "", n); sub(/\.crash$/, "", n); gsub(/_/, "/", n); print n }')
        items=$(printf '%s\n%s\n' "$segv" "$apport" | grep . | sed 's|.*/||' | sort | uniq -c | sort -rn | awk '{ c = $1; $1 = ""; sub(/^ /, ""); print $0 " x" c }')
        count=$(printf '%s\n%s\n' "$segv" "$apport" | grep -c .)
        if [ "$JOURNAL" -eq 0 ] && [ -z "$apport" ]; then skip_without_journal 'Application crashes'; return 0; fi
        stability 'Application crashes' "$count" WARN Low 'application crash(es)' "$items" \
            'Update or reinstall the programs that crash most. Crashes in many different programs at once point to the system (drivers, memory, disk).'
    }
    msp_check 'Stability' 'Application crashes' check_app_crashes

    # =====================================================================================
    msp_section 'All critical and error events'
    # =====================================================================================
    check_events() {
        [ "$JOURNAL" -eq 1 ] || { msp_skip 'Events' 'Error events' 'Skipped: the system journal is not readable here (see Journal access).' "$(msp_root_hint)"; return 0; }
        local crit err warn='' total sources what='critical/error'
        crit=$(journalctl -q --no-pager -o short-iso -p 0..2 --since "@$SINCE" 2>/dev/null)
        err=$(journalctl -q --no-pager -o short-iso -p 3..3 --since "@$SINCE" 2>/dev/null)
        if [ "$WARNINGS" -eq 1 ]; then
            warn=$(journalctl -q --no-pager -o short-iso -p 4..4 --since "@$SINCE" 2>/dev/null)
            what='critical/error/warning'
        fi
        # "2026-10-19T10:00:00+0000 host ident[pid]: message" -> source "ident"
        sources=$(printf '%s\n%s\n%s\n' "$crit" "$err" "$warn" | grep -E '^[0-9]{4}-' | awk '{ s = $3; sub(/\[[0-9]+\]/, "", s); sub(/:$/, "", s); print s }' | sort | uniq -c | sort -rn)
        total=$(printf '%s\n%s\n%s\n' "$crit" "$err" "$warn" | grep -cE '^[0-9]{4}-')
        local ncrit
        ncrit=$(printf '%s\n' "$crit" | grep -cE '^[0-9]{4}-')
        printf '%s\n' "$sources" | while read -r c s; do [ -n "$s" ] && msp_data_row 'Sources' Source "$s" Count# "$c"; done
        {
            printf '%s\n' "$crit" | grep -E '^[0-9]{4}-' | sed 's/^/Critical|/'
            printf '%s\n' "$err" | grep -E '^[0-9]{4}-' | sed 's/^/Error|/'
            printf '%s\n' "$warn" | grep -E '^[0-9]{4}-' | sed 's/^/Warning|/'
        } | sort -t'|' -k2 -r | head -n 500 | while IFS='|' read -r level line; do
            event_row "$(journal_epoch "$line")" "$level" "$(printf '%s' "$line" | awk '{ s = $3; sub(/\[[0-9]+\]/, "", s); sub(/:$/, "", s); print s }')" "$(printf '%s' "$line" | sed 's/^[^ ]* [^ ]* [^:]*: //')"
        done
        local top
        top=$(printf '%s\n' "$sources" | head -n 5 | awk 'NF >= 2 { print $2 " (" $1 ")" }' | paste -sd ',' - | sed 's/,/, /g')
        msp_finding --status INFO --category 'Events' --check 'Error events' --evidence "$(msp_json_obj Total# "$total" Critical# "$ncrit" Hours# "$HOURS")" \
            --detail "$total $what journal message(s) ($ncrit critical).${top:+ Top sources: $top.}"
    }
    msp_check 'Events' 'Error events' check_events
fi

msp_complete "$OUTPUT"
exit 0
