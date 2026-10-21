#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2329  # The embedded helper defines globals and functions this script does not use; checks run through msp_check.
# get-update-compliance-macos.sh - read-only macOS update compliance check: macOS version and
# whether Apple still ships security updates for it, last macOS update installed, updates
# waiting, uptime, and settings or management profiles that stop or delay updates. The Windows
# version is Get-WindowsUpdateCompliance.ps1; Linux: get-update-compliance-linux.sh.
#
# Usage:  bash get-update-compliance-macos.sh [--online] [--output DIR] [--help]
#
# Options:
#   --online      Ask Apple's update servers now (softwareupdate --list) instead of using the
#                 result of macOS's last own check. Needs internet; can take a minute. Nothing
#                 is downloaded or installed either way.
#   --output DIR  Also save results as JSON and CSV (toolkit schema 2.0), with PendingUpdates
#                 and RecentUpdates tables.
#   --help        Show this help.
#
# Checks
#   macOS version      Version and build, compared with a built-in support table (Apple ships
#                      security updates for the current major version and the two before it).
#   Last update        The newest macOS update in /Library/Receipts/InstallHistory.plist
#                      (security data files such as XProtect are listed but not counted).
#   Pending updates    From macOS's last Software Update check (cached), or live with --online.
#   Restart / uptime   Days since the last restart.
#   Update settings    Automatic check/download/install settings, and MDM or configuration
#                      profile settings that defer updates or point at another update catalog.
#
# Examples:
#   bash get-update-compliance-macos.sh
#   bash get-update-compliance-macos.sh --online --output ~/Desktop/Audit
#
# Purpose       : Answer "is this Mac getting security updates, and is its macOS version still supported?"
# Use Case      : Home network security audits; patch tickets; onboarding.
# Scope         : This Mac only. Without --online, no network traffic.
# Risk Level    : Read-Only -- reads update records and settings; never downloads, installs or changes anything.
# Prerequisites : macOS 12+ | bash 3.2+ | root: No | --online needs internet access
# Version       : 1.1.0
# Limitations   : Apple does not publish end-of-support dates; the table below is built from
#                 Apple's security releases page (support.apple.com/en-us/100100), with the
#                 source and the day it was checked on each row; reviewed 2026-10-21.
#                 Review it every autumn when a new macOS ships. Whether this Mac's hardware
#                 can run the newest macOS is not checked. Same check names and IDs as the
#                 Windows version where the check is the same.

set -u
MSP_SCRIPT_FILE=$0

#region MSPToolkit (generated) Sections=Core
# DO NOT EDIT — regenerate with Sync-MSPEmbeddedHelper.ps1
# Source: endpoint-systems/utilities/msp-toolkit-common.sh | Sections: Core | SHA256: 7ff53c4c2280105169783fa5b4cfcc09020b95b59021da21ad657c067db1c247
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
msp__data_index() {
    # Sets MSP__DATA_IDX to the index of table NAME, creating it if needed (bash 3.2 has no
    # associative arrays). Sets a global instead of printing: $(...) would run in a subshell
    # and lose a newly created table.
    local i=0
    while [ "$i" -lt "$MSP_DATA_COUNT" ]; do
        if [ "${MSP_DATA_NAMES[$i]}" = "$1" ]; then MSP__DATA_IDX=$i; return 0; fi
        i=$((i + 1))
    done
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
ONLINE=0
while [ $# -gt 0 ]; do
    case "$1" in
        --output)
            OUTPUT=${2-}
            [ -n "$OUTPUT" ] || { printf 'Missing folder after --output\n' >&2; exit 2; }
            shift 2
            ;;
        --online) ONLINE=1; shift ;;
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
if [ "$(uname -s)" != 'Darwin' ]; then
    printf 'This script is for macOS. On Linux use get-update-compliance-linux.sh.\n' >&2
    exit 2
fi

[ -n "$OUTPUT" ] && msp_param Output "$OUTPUT"
msp_param Online "$ONLINE"
msp_init 'get-update-compliance-macos' "$SCRIPT_VERSION" 'A6' 'Read-Only' 'macOS update compliance and end-of-support check (read-only)'

ROOT=${MSP_TEST_ROOT:-}
NOW=$(date +%s)
SU_PLIST="$ROOT/Library/Preferences/com.apple.SoftwareUpdate"
MANAGED="$ROOT/Library/Managed Preferences/com.apple.SoftwareUpdate.plist"

# --- macOS support table ----------------------------------------------------------------------
# major|name|status|date|source|verified. status: current, supported, oldest (still supported,
# next to end), ended. Apple publishes no end-of-support dates, so the table is built from
# Apple's security releases page ("source"; "verified" = the day it was checked there):
#   current/supported/oldest  the version got a security release with the latest macOS.
#   ended                     date = Apple's last security release for that version.
#   oldest                    date = when Apple usually stops (around the release of the next
#                             major macOS); an estimate, so "verified" says unverified.
# Reviewed 2026-10-21: macOS 27 (Golden Gate) is current; 27.0.1, 26.7.1 and 15.8.1 shipped on
# 2026-09-28. Sonoma's last was 14.8.9 (2026-08-06); it was not in the 2026-09 releases.
# Big Sur and Catalina got one-off updates with no published CVE entries on 2026-02-02
# (11.7.11, Security Update 2026-001); their dates below are the last regular security releases.
# Each autumn: add the new major as current, move the others down, update the dates.
SUPPORT_TABLE='27|macOS Golden Gate|current||https://support.apple.com/en-us/100100|2026-10-21
26|macOS Tahoe|supported||https://support.apple.com/en-us/100100|2026-10-21
15|macOS Sequoia|oldest|2027-09|https://support.apple.com/en-us/100100|unverified
14|macOS Sonoma|ended|2026-08-06|https://support.apple.com/en-us/100100|2026-10-21
13|macOS Ventura|ended|2025-08-20|https://support.apple.com/en-us/100100|2026-10-21
12|macOS Monterey|ended|2024-07-29|https://support.apple.com/en-us/100100|2026-10-21
11|macOS Big Sur|ended|2023-09-11|https://support.apple.com/en-us/121012|2026-10-21
10|macOS 10.x|ended|2022-07-20|https://support.apple.com/en-us/121012|2026-10-21'
NEWEST_MAJOR=27

epoch_of() {
    # "2026-09-02 09:06:07 +0000" or "2026-09-02T09:10:16Z" -> seconds since 1970.
    case "$1" in
        *T*Z) date -j -u -f '%Y-%m-%dT%H:%M:%SZ' "$1" '+%s' 2>/dev/null ;;
        *) date -j -f '%Y-%m-%d %H:%M:%S %z' "$1" '+%s' 2>/dev/null ;;
    esac
}
ymd() { date -r "$1" '+%Y-%m-%d'; }

# =========================================================================================
msp_section 'macOS version and support'
# =========================================================================================
check_version() {
    local version build major row name status ended
    version=$(sw_vers -productVersion 2>/dev/null)
    build=$(sw_vers -buildVersion 2>/dev/null)
    [ -n "$version" ] || { printf 'command not found: sw_vers\n' >&2; return 1; }
    major=${version%%.*}
    local ev
    ev=$(msp_json_obj Version "$version" Build "$build" Major "$major")
    msp_finding --status INFO --category 'Lifecycle' --check 'OS version' --evidence "$ev" --detail "macOS $version (build $build)"
    row=$(printf '%s\n' "$SUPPORT_TABLE" | awk -F'|' -v m="$major" '$1 == m')
    if [ -z "$row" ] && [ "$major" -gt "$NEWEST_MAJOR" ]; then
        msp_finding --status WARN --severity Low --category 'Lifecycle' --check 'OS version support' --evidence "$ev" \
            --detail "macOS $major is newer than this script's support table (reviewed 2026-10-21)." \
            --rec 'It is almost certainly supported. Update the support table in this script.'
        return 0
    fi
    [ -n "$row" ] || row=$(printf '%s\n' "$SUPPORT_TABLE" | tail -n 1)
    IFS='|' read -r _ name status ended source verified <<EOF
$row
EOF
    ev=$(msp_json_obj Version "$version" Build "$build" Major "$major" Status "$status" Date "$ended" Source "$source" DateVerified "$verified")
    case "$status" in
        current)
            msp_finding --status PASS --category 'Lifecycle' --check 'OS version support' --evidence "$ev" --detail "$name ($version) is the current macOS version." ;;
        supported)
            msp_finding --status PASS --category 'Lifecycle' --check 'OS version support' --evidence "$ev" --detail "$name ($version) still receives security updates." ;;
        oldest)
            msp_finding --status PASS --category 'Lifecycle' --check 'OS version support' --evidence "$ev" \
                --detail "$name ($version) still receives security updates, but it is the oldest supported version; Apple usually stops around $ended when the next macOS ships." \
                --rec 'Plan the upgrade to a newer macOS (System Settings > General > Software Update) if this Mac supports it.'
            ;;
        *)
            msp_finding --status FAIL --severity Critical --category 'Lifecycle' --check 'OS version support' --evidence "$ev" \
                --detail "$name ($version) no longer receives security updates (Apple's last security update for it: $ended)." \
                --rec 'Upgrade to a supported macOS (System Settings > General > Software Update). If this Mac cannot run a supported version, plan to replace it, and until then keep browsers updated and avoid sensitive work on it.'
            ;;
    esac
}
msp_check 'Lifecycle' 'OS version support' check_version

# =========================================================================================
msp_section 'Updates installed and pending'
# =========================================================================================
check_last_install() {
    local hist="$ROOT/Library/Receipts/InstallHistory.plist" rows last='' name='' line d n p e
    # date|name|process for every install macOS recorded (XML form: the file holds dates).
    rows=$(plutil -convert xml1 -o - "$hist" 2>/dev/null | awk '
        /<dict>/ { d = ""; n = ""; p = "" }
        /<key>date<\/key>/ { getline; d = $0 }
        /<key>displayName<\/key>/ { getline; n = $0 }
        /<key>processName<\/key>/ { getline; p = $0 }
        /<\/dict>/ { gsub(/<[^>]*>|\t/, "", d); gsub(/<[^>]*>|\t/, "", n); gsub(/<[^>]*>|\t/, "", p); if (d != "") print d "|" n "|" p }')
    # The 10 newest Apple updates for the table (XProtect/MRT data files are frequent; left out).
    printf '%s\n' "$rows" | awk -F'|' '$3 ~ /softwareupdated/ && $2 !~ /XProtect|MRTConfig|Gatekeeper Compat|Compatibility Data/' | tail -n 10 |
        while IFS='|' read -r d n p; do [ -n "$d" ] && msp_data_row 'RecentUpdates' Date "$d" Name "$n" Source "$p"; done
    line=$(printf '%s\n' "$rows" | awk -F'|' '$3 ~ /softwareupdated/ && $2 ~ /^macOS|Background Security|Security Response|Rapid Security/' | tail -n 1)
    if [ -n "$line" ]; then
        last=$(epoch_of "${line%%|*}")
        name=$(printf '%s' "$line" | cut -d'|' -f2)
    fi
    if [ -z "$last" ]; then
        # No record (history file reset or unreadable): use the date the current version was installed.
        last=$(stat -f %m "$ROOT/System/Library/CoreServices/SystemVersion.plist" 2>/dev/null)
        name="macOS $(sw_vers -productVersion 2>/dev/null) (date of the installed version)"
    fi
    if [ -z "$last" ]; then
        msp_finding --status WARN --severity Medium --category 'Updates' --check 'Last update installed' \
            --detail 'macOS has no record of an update installation date.' --rec 'Open System Settings > General > Software Update and check updates are installing.'
        return 0
    fi
    local age=$(((NOW - last) / 86400)) ev
    ev=$(msp_json_obj LastInstall "$(ymd "$last")" DaysAgo# "$age" Update "$name")
    # Apple ships macOS security updates about every 4-8 weeks.
    if [ "$age" -gt 120 ]; then
        msp_finding --status FAIL --severity High --category 'Updates' --check 'Last update installed' --evidence "$ev" \
            --detail "The last macOS update ($name) was installed $(ymd "$last") ($age days ago). Several security releases are likely missing." \
            --rec 'Install all updates (System Settings > General > Software Update) and restart.'
    elif [ "$age" -gt 75 ]; then
        msp_finding --status WARN --severity Medium --category 'Updates' --check 'Last update installed' --evidence "$ev" \
            --detail "The last macOS update ($name) was installed $(ymd "$last") ($age days ago); a recent security release may be missing." \
            --rec 'Check System Settings > General > Software Update and install what is offered.'
    else
        msp_finding --status PASS --category 'Updates' --check 'Last update installed' --evidence "$ev" --detail "$name, $(ymd "$last") ($age days ago)."
    fi
}
msp_check 'Updates' 'Last update installed' check_last_install

check_scan() {
    local last epoch
    last=$(defaults read "$SU_PLIST" LastFullSuccessfulDate 2>/dev/null)
    [ -n "$last" ] || last=$(defaults read "$SU_PLIST" LastSuccessfulDate 2>/dev/null)
    [ -n "$last" ] && epoch=$(epoch_of "$last")
    if [ -z "${epoch:-}" ]; then
        msp_finding --status WARN --severity Medium --category 'Updates' --check 'Last update scan' \
            --detail 'macOS has no record of a successful check for updates.' --rec 'Open System Settings > General > Software Update so it checks.'
        return 0
    fi
    local age=$(((NOW - epoch) / 86400))
    if [ "$age" -gt 14 ]; then
        msp_finding --status WARN --severity Medium --category 'Updates' --check 'Last update scan' \
            --detail "macOS last checked for updates successfully on $(ymd "$epoch") ($age days ago). It normally checks daily." \
            --rec 'Open Software Update so it checks; if it fails, check the internet connection and the update settings below.'
    else
        msp_finding --status PASS --category 'Updates' --check 'Last update scan' --detail "$(date -r "$epoch" '+%Y-%m-%d %H:%M') ($age day(s) ago)."
    fi
}
msp_check 'Updates' 'Last update scan' check_scan

check_pending() {
    local names source major
    major=$(sw_vers -productVersion 2>/dev/null | cut -d. -f1)
    if [ "$ONLINE" -eq 1 ]; then
        printf '  Asking Apple'\''s update servers (softwareupdate --list; can take a minute)...\n'
        # "* Label: ..." lines, then "Title: <name>, Version: ..., Recommended: YES, Action: restart".
        names=$(msp_run_timeout 300 softwareupdate --list 2>&1 | sed -n 's/^[[:space:]]*Title: \([^,]*\),.*/\1/p')
        source='Apple update servers, just now'
    else
        names=$(defaults read "$SU_PLIST" RecommendedUpdates 2>/dev/null | sed -n 's/.*"Display Name" = "\{0,1\}\([^";]*\)"\{0,1\};.*/\1/p' | awk '!seen[$0]++')
        source="macOS's last check"
    fi
    local security='' upgrades='' others='' name ver
    while IFS= read -r name; do
        [ -n "$name" ] || continue
        msp_data_row 'PendingUpdates' Title "$name" Source "$source"
        printf '    - %s\n' "$name"
        case "$name" in
            *macOS*)
                ver=$(printf '%s' "$name" | grep -oE '[0-9]+(\.[0-9]+)+' | head -n 1 | cut -d. -f1)
                if [ "$ver" = "$major" ]; then security="$security${security:+; }$name"; else upgrades="$upgrades${upgrades:+; }$name"; fi
                ;;
            *'Security Response'* | *'Background Security'* | *Safari*) security="$security${security:+; }$name" ;;
            *) others="$others${others:+; }$name" ;;
        esac
    done <<EOF
$names
EOF
    if [ -z "$security$upgrades$others" ]; then
        msp_finding --status PASS --category 'Updates' --check 'Pending updates' --detail "None. Source: $source."
    fi
    if [ -n "$security" ]; then
        msp_finding --status WARN --severity High --category 'Updates' --check 'Pending security updates' \
            --detail "Security update(s) waiting: $security. Source: $source." \
            --rec 'Install them now: System Settings > General > Software Update, then restart.'
    fi
    if [ -n "$others" ]; then
        msp_finding --status INFO --category 'Updates' --check 'Other pending updates' --detail "$others. Source: $source."
    fi
    if [ -n "$upgrades" ]; then
        msp_finding --status INFO --category 'Updates' --check 'Major macOS upgrade available' \
            --detail "$upgrades is offered. Optional while the installed version is supported (see above)."
    fi
    if [ "$ONLINE" -eq 0 ]; then
        msp_finding --status INFO --category 'Updates' --check 'Pending updates source' \
            --detail 'Based on macOS'\''s own last check. Re-run with --online for a live check.'
    fi
}
msp_check 'Updates' 'Pending updates' check_pending

check_uptime() {
    local boot days
    # "{ sec = 1792190174, usec = 290649 } ...": the first number is the boot time.
    boot=$(sysctl -n kern.boottime 2>/dev/null | sed -n 's/^{ *sec = \([0-9]*\),.*/\1/p')
    [ -n "$boot" ] || { printf 'Could not read the boot time\n' >&2; return 1; }
    days=$(((NOW - boot) / 86400))
    if [ "$days" -gt 30 ]; then
        msp_finding --status WARN --severity Low --category 'Updates' --check 'Uptime' \
            --detail "The Mac has not restarted for $days days. Some updates only finish after a restart." \
            --rec 'Restart the Mac (Apple menu > Restart) at a convenient time.'
    else
        msp_finding --status PASS --category 'Updates' --check 'Uptime' --detail "Restarted $days day(s) ago."
    fi
}
msp_check 'Updates' 'Uptime' check_uptime

# =========================================================================================
msp_section 'Update settings'
# =========================================================================================
check_settings() {
    # Keys that are not set mean the macOS default, which is on.
    local auto_check download critical config macos found=0
    auto_check=$(defaults read "$SU_PLIST" AutomaticCheckEnabled 2>/dev/null)
    download=$(defaults read "$SU_PLIST" AutomaticDownload 2>/dev/null)
    critical=$(defaults read "$SU_PLIST" CriticalUpdateInstall 2>/dev/null)
    config=$(defaults read "$SU_PLIST" ConfigDataInstall 2>/dev/null)
    macos=$(defaults read "$SU_PLIST" AutomaticallyInstallMacOSUpdates 2>/dev/null)
    if [ "$auto_check" = '0' ]; then
        found=1
        msp_finding --status FAIL --severity High --category 'Policy' --check 'Automatic updates' \
            --detail 'Automatic checking for updates is turned off, so the Mac does not look for security updates.' \
            --rec 'System Settings > General > Software Update > Automatic updates (i) > turn on "Check for updates".'
    elif [ "$critical" = '0' ] || [ "$config" = '0' ]; then
        found=1
        msp_finding --status WARN --severity High --category 'Policy' --check 'Automatic update mode' \
            --detail 'Security responses / system data files are not installed automatically.' \
            --rec 'Turn on "Install Security Responses and system files" in the Automatic updates settings.'
    elif [ "$download" = '0' ] || [ "$macos" = '0' ]; then
        found=1
        msp_finding --status INFO --category 'Policy' --check 'Automatic update mode' \
            --detail 'macOS updates are not downloaded/installed automatically; someone has to install them.' \
            --rec 'On a home Mac, turning on "Install macOS updates" is safest.'
    fi
    # Settings pushed by MDM or a configuration profile.
    if [ -f "$MANAGED" ]; then
        local flat catalog delay
        flat=$(plutil -convert json -o - "$MANAGED" 2>/dev/null | msp_json_flatten -)
        catalog=$(printf '%s\n' "$flat" | awk -F'\t' '$1 == ".CatalogURL" { print $2 }')
        delay=$(printf '%s\n' "$flat" | awk -F'\t' '$1 == ".enforcedSoftwareUpdateDelay" || $1 == ".enforcedSoftwareUpdateMinorOSDeferredInstallDelay" { print $2; exit }')
        if [ -n "$catalog" ]; then
            found=1
            msp_finding --status WARN --severity Medium --category 'Policy' --check 'Update server' \
                --detail "A management profile points Software Update at another catalog: $catalog. Away from that network, updates may not arrive." \
                --rec 'If this is a personal Mac or the organization no longer manages it, remove the profile (escalate first: it may be a work device).'
        fi
        if [ -n "$delay" ]; then
            found=1
            local status=INFO
            [ "$delay" -gt 14 ] 2>/dev/null && status=WARN
            msp_finding --status "$status" --severity Low --category 'Policy' --check 'Security update delay' \
                --detail "A management profile defers updates by $delay day(s)." --rec 'On a home Mac, keep the deferral at 0-7 days.'
        fi
    fi
    if [ "$found" -eq 0 ]; then
        msp_finding --status PASS --category 'Policy' --check 'Update policies' --detail 'Automatic updates are on and no profile delays them (normal for a home Mac).'
    fi
}
msp_check 'Policy' 'Update policies' check_settings

msp_complete "$OUTPUT"
exit 0
