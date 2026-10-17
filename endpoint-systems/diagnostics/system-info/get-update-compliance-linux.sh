#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2329  # The embedded helper defines globals and functions this script does not use; checks run through msp_check.
# get-update-compliance-linux.sh - read-only Linux update compliance check: distribution
# version and its end of security support, last package update installed, updates waiting,
# restart needed, and settings that stop or delay updates. The Windows version is
# Get-WindowsUpdateCompliance.ps1; macOS: get-update-compliance-macos.sh.
#
# Usage:  bash get-update-compliance-linux.sh [--online] [--output DIR] [--help]
#
# Options:
#   --online      Refresh the package lists from the distribution's servers into a TEMPORARY
#                 folder (apt) or the user cache (dnf) and check for updates against them, and
#                 ask the Snap Store for snap updates. Needs internet. The system's own package
#                 lists are not changed and nothing is downloaded or installed.
#   --output DIR  Also save results as JSON and CSV (toolkit schema 2.0), with a PendingUpdates table.
#   --help        Show this help.
#
# Checks
#   OS version       /etc/os-release, compared with a built-in support table (Ubuntu, Debian,
#                    Fedora, RHEL / Rocky / AlmaLinux, CentOS Stream, Linux Mint, Pop!_OS).
#   Last update      Newest package installation (dpkg log / rpm database).
#   Pending updates  apt-get -s / dnf -C against the LOCAL package lists (as of their last
#                    refresh, shown), or live with --online.
#   Restart          /var/run/reboot-required, needs-restarting, or a newer kernel installed
#                    than the one running; uptime.
#   Update settings  unattended-upgrades / dnf-automatic, held packages, held snaps.
#
# Examples:
#   bash get-update-compliance-linux.sh
#   bash get-update-compliance-linux.sh --online --output ~/Audit
#
# Purpose       : Answer "is this computer getting security updates, and is its Linux version still supported?"
# Use Case      : Home network security audits; patch tickets; onboarding.
# Scope         : This computer only. Without --online, no network traffic.
# Risk Level    : Read-Only -- reads package records and settings; never installs, removes or changes anything.
# Prerequisites : bash 3.2+ | apt (Debian/Ubuntu family) or dnf (Fedora/RHEL family) | root: No
# Version       : 1.0.0
# Limitations   : The support table is built in (reviewed 2026-10; dates as published by each
#                 project, LTS/ESM paid extensions noted but not detected). Review it every
#                 April and October. Other distributions are reported as not in the table.
#                 Flatpak updates are not checked. MSP_TEST_ROOT (development tests only)
#                 prefixes the files read.

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

SCRIPT_VERSION='1.0.0'
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
if [ "$(uname -s)" != 'Linux' ]; then
    printf 'This script is for Linux. On macOS use get-update-compliance-macos.sh.\n' >&2
    exit 2
fi

[ -n "$OUTPUT" ] && msp_param Output "$OUTPUT"
msp_param Online "$ONLINE"
msp_init 'get-update-compliance-linux' "$SCRIPT_VERSION" 'A6' 'Read-Only' 'Linux update compliance and end-of-support check (read-only)'

ROOT=${MSP_TEST_ROOT:-}
NOW=$(date +%s)
PKG=''
if msp_have apt-get; then PKG='apt'; elif msp_have dnf; then PKG='dnf'; fi

# --- Support table ----------------------------------------------------------------------------
# os-release ID|VERSION_ID (or its major)|name|end of security updates|note. Reviewed 2026-10.
# Dates as published by each project (Ubuntu: end of standard support; Debian: end of LTS;
# Fedora: about 4 weeks after release N+2; RHEL family: end of maintenance). Update every
# April and October, and whenever a run reports a version as not in the table.
SUPPORT_TABLE='ubuntu|20.04|Ubuntu 20.04 LTS|2025-05-31|Paid Ubuntu Pro (ESM) can extend security updates to 2030.
ubuntu|22.04|Ubuntu 22.04 LTS|2027-06-01|Ubuntu Pro (free for personal use) extends this to 2032.
ubuntu|24.04|Ubuntu 24.04 LTS|2029-05-31|Ubuntu Pro (free for personal use) extends this to 2034.
ubuntu|26.04|Ubuntu 26.04 LTS|2031-05-31|
ubuntu|25.04|Ubuntu 25.04|2026-01-15|Interim release (9 months of support).
ubuntu|25.10|Ubuntu 25.10|2026-07-09|Interim release (9 months of support).
ubuntu|26.10|Ubuntu 26.10|2027-07-15|Interim release (9 months of support).
pop|22.04|Pop!_OS 22.04|2027-06-01|Follows Ubuntu 22.04.
pop|24.04|Pop!_OS 24.04|2029-05-31|Follows Ubuntu 24.04.
debian|11|Debian 11 (bullseye)|2026-08-31|Including the Debian LTS period.
debian|12|Debian 12 (bookworm)|2028-06-30|Including the Debian LTS period.
debian|13|Debian 13 (trixie)|2030-06-30|Including the Debian LTS period.
fedora|42|Fedora 42|2026-05-13|
fedora|43|Fedora 43|2026-12-09|
fedora|44|Fedora 44|2027-05-19|
fedora|45|Fedora 45|2027-12-08|
rhel|8|Red Hat Enterprise Linux 8|2029-05-31|
rhel|9|Red Hat Enterprise Linux 9|2032-05-31|
rhel|10|Red Hat Enterprise Linux 10|2035-05-31|
rocky|8|Rocky Linux 8|2029-05-31|
rocky|9|Rocky Linux 9|2032-05-31|
rocky|10|Rocky Linux 10|2035-05-31|
almalinux|8|AlmaLinux 8|2029-05-31|
almalinux|9|AlmaLinux 9|2032-05-31|
almalinux|10|AlmaLinux 10|2035-05-31|
centos|7|CentOS 7|2024-06-30|
centos|9|CentOS Stream 9|2027-05-31|
centos|10|CentOS Stream 10|2030-01-01|
linuxmint|20|Linux Mint 20|2025-04-30|
linuxmint|21|Linux Mint 21|2027-04-30|
linuxmint|22|Linux Mint 22|2029-04-30|'

days_until() { printf '%s' $((($(date -d "$1" +%s) - NOW) / 86400)); } # linux-only: date -d
ymd() { date -d "@$1" '+%Y-%m-%d'; }                                     # linux-only: date -d

# =========================================================================================
msp_section 'Linux version and support'
# =========================================================================================
check_version() {
    local release="$ROOT/etc/os-release" id version pretty major row name end note
    [ -r "$release" ] || { printf 'No such file or directory: /etc/os-release\n' >&2; return 1; }
    id=$(sed -n 's/^ID=//p' "$release" | tr -d '"' | head -n 1)
    version=$(sed -n 's/^VERSION_ID=//p' "$release" | tr -d '"' | head -n 1)
    pretty=$(sed -n 's/^PRETTY_NAME=//p' "$release" | tr -d '"' | head -n 1)
    major=${version%%.*}
    local ev
    ev=$(msp_json_obj Id "$id" Version "$version" PrettyName "$pretty" Kernel "$(uname -r)")
    msp_finding --status INFO --category 'Lifecycle' --check 'OS version' --evidence "$ev" --detail "${pretty:-$id $version} (kernel $(uname -r))"
    row=$(printf '%s\n' "$SUPPORT_TABLE" | awk -F'|' -v i="$id" -v v="$version" '$1 == i && $2 == v { print; exit }')
    [ -n "$row" ] || row=$(printf '%s\n' "$SUPPORT_TABLE" | awk -F'|' -v i="$id" -v v="$major" '$1 == i && $2 == v { print; exit }')
    if [ -z "$row" ]; then
        local hint='Check the distribution'\''s release page for its end-of-support date, and add it to this script'\''s support table.'
        msp_finding --status WARN --severity Low --category 'Lifecycle' --check 'OS version support' --evidence "$ev" \
            --detail "${pretty:-$id $version} is not in this script's support table (reviewed 2026-10), so its end-of-support date is unknown here." \
            --rec "$hint"
        return 0
    fi
    IFS='|' read -r _ _ name end note <<EOF
$row
EOF
    local left
    left=$(days_until "$end")
    ev=$(msp_json_obj Id "$id" Version "$version" EndOfSupport "$end" Note "$note")
    if [ "$left" -lt 0 ]; then
        msp_finding --status FAIL --severity Critical --category 'Lifecycle' --check 'OS version support' --evidence "$ev" \
            --detail "$name reached end of security support on $end and no longer receives security updates.${note:+ $note}" \
            --rec 'Upgrade to a supported release (for Ubuntu: Software Updater offers the next LTS; Fedora: dnf system-upgrade), after a backup.'
    elif [ "$left" -le 90 ]; then
        msp_finding --status WARN --severity High --category 'Lifecycle' --check 'OS version support' --evidence "$ev" \
            --detail "$name reaches end of security support on $end ($left days).${note:+ $note}" \
            --rec 'Plan the upgrade to the next supported release before that date.'
    else
        msp_finding --status PASS --category 'Lifecycle' --check 'OS version support' --evidence "$ev" \
            --detail "$name is supported until $end.${note:+ $note}"
    fi
}
msp_check 'Lifecycle' 'OS version support' check_version

# =========================================================================================
msp_section 'Updates installed and pending'
# =========================================================================================
check_last_install() {
    local last=''
    if [ "$PKG" = 'apt' ] || [ -f "$ROOT/var/log/dpkg.log" ]; then
        # "2026-10-01 12:00:00 status installed <pkg> <version>" in dpkg.log (rotated logs too).
        local line
        line=$(cat "$ROOT/var/log/dpkg.log" "$ROOT/var/log/dpkg.log.1" 2>/dev/null | awk '$3 == "status" && $4 == "installed" { print $1 " " $2 }' | sort | tail -n 1)
        [ -n "$line" ] && last=$(date -d "$line" +%s 2>/dev/null) # linux-only: date -d
        [ -n "$last" ] || last=$(stat -c %Y "$ROOT/var/lib/dpkg/status" 2>/dev/null)
    elif msp_have rpm; then
        last=$(rpm -qa --qf '%{INSTALLTIME}\n' 2>/dev/null | sort -n | tail -n 1)
    fi
    if [ -z "$last" ]; then
        msp_finding --status WARN --severity Medium --category 'Updates' --check 'Last update installed' \
            --detail 'No package installation date could be found.' --rec 'Check that updates are being installed (Software Updater, apt or dnf history).'
        return 0
    fi
    local age=$(((NOW - last) / 86400)) ev
    ev=$(msp_json_obj LastInstall "$(ymd "$last")" DaysAgo# "$age")
    if [ "$age" -gt 75 ]; then
        msp_finding --status FAIL --severity High --category 'Updates' --check 'Last update installed' --evidence "$ev" \
            --detail "No package has been installed or updated since $(ymd "$last") ($age days ago). Security updates are certainly missing." \
            --rec 'Install updates now (Software Updater, sudo apt upgrade, or sudo dnf upgrade) and restart.'
    elif [ "$age" -gt 45 ]; then
        msp_finding --status WARN --severity Medium --category 'Updates' --check 'Last update installed' --evidence "$ev" \
            --detail "The last package update was $(ymd "$last") ($age days ago)." --rec 'Install pending updates.'
    else
        msp_finding --status PASS --category 'Updates' --check 'Last update installed' --evidence "$ev" --detail "$(ymd "$last") ($age days ago)."
    fi
}
msp_check 'Updates' 'Last update installed' check_last_install

TMP_APT=''
check_pending() {
    if [ -z "$PKG" ]; then
        msp_skip 'Updates' 'Pending updates' 'Skipped: no apt or dnf package manager found; other distributions are not covered yet.' 'Check updates with the distribution'\''s own tool.'
        return 0
    fi
    local refreshed='' as_of='never' source out rc total=0 security=0 names='' sec_names=''
    if [ "$PKG" = 'apt' ]; then
        local lists="$ROOT/var/lib/apt/lists" opts=''
        if [ "$ONLINE" -eq 1 ]; then
            # Fresh lists in a temporary folder: the system's own lists are left untouched.
            TMP_APT="${MSP_WORK_DIR:-/tmp}/apt"
            mkdir -p "$TMP_APT/lists/partial" "$TMP_APT/cache/archives/partial"
            printf '  Refreshing package lists into a temporary folder (needs internet)...\n'
            msp_run_timeout 300 apt-get -q update -o Debug::NoLocking=1 -o Dir::State::Lists="$TMP_APT/lists" -o Dir::Cache="$TMP_APT/cache" >/dev/null 2>"$TMP_APT/err"
            rc=$?
            if [ "$rc" -ne 0 ]; then printf 'apt-get update failed: %s\n' "$(head -n 1 "$TMP_APT/err")" >&2; return 1; fi
            lists="$TMP_APT/lists"
            opts="-o Dir::State::Lists=$TMP_APT/lists -o Dir::Cache=$TMP_APT/cache"
            source='package lists refreshed just now'
        else
            refreshed=$(for f in "$lists"/*_InRelease "$lists"/*_Release "$ROOT/var/lib/apt/periodic/update-success-stamp"; do [ -e "$f" ] && stat -c %Y "$f"; done 2>/dev/null | sort -n | tail -n 1)
            [ -n "$refreshed" ] && as_of=$(date -d "@$refreshed" '+%Y-%m-%d %H:%M') # linux-only: date -d
            source="local package lists as of $as_of"
        fi
        # Simulation only (-s): installs nothing.
        # shellcheck disable=SC2086  # $opts is a list of options
        out=$(apt-get -s -o Debug::NoLocking=1 $opts dist-upgrade 2>/dev/null)
        names=$(printf '%s\n' "$out" | awk '/^Inst / { print $2 }')
        sec_names=$(printf '%s\n' "$out" | awk '/^Inst / && /-security/ { print $2 }')
    else
        local flag='-C'
        source='dnf cache'
        if [ "$ONLINE" -eq 1 ]; then flag='--refresh'; source='repositories, just now'; printf '  Asking the repositories (needs internet)...\n'; fi
        out=$(msp_run_timeout 300 dnf -q "$flag" check-update 2>&1)
        rc=$?
        if [ "$rc" -ne 0 ] && [ "$rc" -ne 100 ]; then printf 'dnf could not check: %s\n' "$(printf '%s' "$out" | head -n 1)" >&2; return 1; fi
        names=$(printf '%s\n' "$out" | awk 'NF == 3 && $1 ~ /\./ { print $1 }')
        sec_names=$(dnf -q "$flag" updateinfo list --security 2>/dev/null | awk 'NF >= 3 { print $3 }' | sort -u)
        refreshed=$(for f in "$ROOT"/var/cache/dnf/*/repodata/repomd.xml "$ROOT"/var/cache/libdnf5/*/repodata/repomd.xml; do [ -e "$f" ] && stat -c %Y "$f"; done 2>/dev/null | sort -n | tail -n 1)
        [ -n "$refreshed" ] && [ "$ONLINE" -eq 0 ] && source="dnf cache as of $(date -d "@$refreshed" '+%Y-%m-%d %H:%M')" # linux-only: date -d
    fi
    [ -n "$names" ] && total=$(printf '%s\n' "$names" | grep -c .)
    [ -n "$sec_names" ] && security=$(printf '%s\n' "$sec_names" | grep -c .)
    printf '%s\n' "$names" | while IFS= read -r n; do
        [ -n "$n" ] || continue
        local is_sec=false
        printf '%s\n' "$sec_names" | grep -qx "$n" && is_sec=true
        msp_data_row 'PendingUpdates' Package "$n" IsSecurity# "$is_sec" Source "$source"
    done
    # Last refresh of the lists (same check name as Windows' last update scan).
    if [ "$ONLINE" -eq 0 ]; then
        if [ -z "$refreshed" ] || [ $(((NOW - refreshed) / 86400)) -gt 14 ]; then
            msp_finding --status WARN --severity Medium --category 'Updates' --check 'Last update scan' \
                --detail "The package lists were last refreshed: ${as_of}." \
                --rec 'Let Software Updater check, or run sudo apt update / sudo dnf check-update; if it fails, check the internet connection and repository settings.'
        else
            msp_finding --status PASS --category 'Updates' --check 'Last update scan' --detail "Package lists refreshed $(date -d "@$refreshed" '+%Y-%m-%d %H:%M')." # linux-only: date -d
        fi
    fi
    if [ "$total" -eq 0 ]; then
        msp_finding --status PASS --category 'Updates' --check 'Pending updates' --detail "None. Source: $source."
    else
        if [ "$security" -gt 0 ]; then
            msp_finding --status WARN --severity High --category 'Updates' --check 'Pending security updates' \
                --detail "$security security update(s) waiting: $(printf '%s\n' "$sec_names" | head -n 8 | paste -sd ',' - | sed 's/,/, /g'). Source: $source." \
                --rec 'Install them now (Software Updater, sudo apt upgrade, or sudo dnf upgrade --security), then restart if asked.' \
                --evidence "$(msp_json_obj SecurityPending# "$security" TotalPending# "$total")"
        fi
        if [ $((total - security)) -gt 0 ]; then
            msp_finding --status INFO --category 'Updates' --check 'Other pending updates' --detail "$((total - security)) other update(s) available. Source: $source."
        fi
    fi
    if [ "$ONLINE" -eq 0 ]; then
        msp_finding --status INFO --category 'Updates' --check 'Pending updates source' --detail "Based on the $source. Re-run with --online for a live check."
    fi
    if [ "$ONLINE" -eq 1 ] && msp_have snap; then
        local snaps
        snaps=$(msp_run_timeout 120 snap refresh --list 2>/dev/null | awk 'NR > 1 { print $1 }' | paste -sd ',' - | sed 's/,/, /g')
        [ -n "$snaps" ] && msp_finding --status INFO --category 'Updates' --check 'Snap updates' --detail "Snap updates available (snaps refresh themselves automatically): $snaps."
    fi
    return 0
}
msp_check 'Updates' 'Pending updates' check_pending

check_restart() {
    local reasons='' running newest uptime days
    if [ -f "$ROOT/var/run/reboot-required" ] || [ -f "$ROOT/run/reboot-required" ]; then
        local pkgs
        pkgs=$(cat "$ROOT/var/run/reboot-required.pkgs" "$ROOT/run/reboot-required.pkgs" 2>/dev/null | sort -u | head -n 5 | paste -sd ',' - | sed 's/,/, /g')
        reasons="the system asked for a restart${pkgs:+ (for $pkgs)}"
    fi
    if [ -z "$reasons" ] && msp_have needs-restarting; then
        needs-restarting -r >/dev/null 2>&1
        [ $? -eq 1 ] && reasons='needs-restarting reports updated core packages'
    fi
    # A newer kernel installed than the one running also means a restart is due.
    running=$(uname -r)
    newest=$(for k in "$ROOT"/boot/vmlinuz-*; do [ -e "$k" ] && printf '%s\n' "${k##*/vmlinuz-}"; done | grep -v rescue | sort -V | tail -n 1)
    if [ -n "$newest" ] && [ "$newest" != "$running" ] && [ "$(printf '%s\n%s\n' "$running" "$newest" | sort -V | tail -n 1)" = "$newest" ]; then
        reasons="$reasons${reasons:+; }kernel $newest is installed but $running is running"
    fi
    uptime=$(cut -d. -f1 "$ROOT/proc/uptime" 2>/dev/null)
    days=$((${uptime:-0} / 86400))
    if [ -n "$reasons" ]; then
        msp_finding --status WARN --severity Medium --category 'Updates' --check 'Restart pending' \
            --detail "A restart is needed to finish updates: $reasons. Up $days day(s)." \
            --rec 'Restart the computer at a convenient time (with the client'\''s agreement).'
    else
        msp_finding --status PASS --category 'Updates' --check 'Restart pending' --detail "No restart pending. Up $days day(s)."
    fi
    if [ "$days" -gt 30 ]; then
        msp_finding --status WARN --severity Low --category 'Updates' --check 'Uptime' \
            --detail "The computer has not restarted for $days days; kernel and library fixes only take effect after a restart." \
            --rec 'Restart it at a convenient time.'
    fi
}
msp_check 'Updates' 'Restart pending' check_restart

# =========================================================================================
msp_section 'Update settings'
# =========================================================================================
conf_value() {
    local key=$1
    shift
    cat "$@" 2>/dev/null | sed -n "s/^[[:space:]]*${key}[[:space:]]*\"\{0,1\}\([^\";]*\)\"\{0,1\}[[:space:]]*;\{0,1\}[[:space:]]*$/\1/p" | tail -n 1
}

check_settings() {
    local found=0
    if [ "$PKG" = 'apt' ]; then
        local lists unattended
        lists=$(conf_value 'APT::Periodic::Update-Package-Lists' "$ROOT"/etc/apt/apt.conf.d/*)
        unattended=$(conf_value 'APT::Periodic::Unattended-Upgrade' "$ROOT"/etc/apt/apt.conf.d/*)
        if [ "$lists" = '0' ]; then
            found=1
            msp_finding --status WARN --severity Medium --category 'Policy' --check 'Automatic updates' \
                --detail 'Automatic refresh of the package lists is turned off (APT::Periodic::Update-Package-Lists "0"), so updates are only found when someone checks by hand.' \
                --rec 'Software & Updates > Updates > "Automatically check for updates: Daily".'
        elif [ "$unattended" != '1' ] || [ ! -e "$ROOT/usr/bin/unattended-upgrade" ]; then
            found=1
            msp_finding --status INFO --category 'Policy' --check 'Automatic update mode' \
                --detail 'Security updates are found automatically but not installed automatically (unattended-upgrades off).' \
                --rec 'Software & Updates > Updates > "When there are security updates: Download and install automatically".'
        fi
        if msp_have apt-mark; then
            local held
            held=$(apt-mark showhold 2>/dev/null | paste -sd ',' - | sed 's/,/, /g')
            if [ -n "$held" ]; then
                found=1
                msp_finding --status WARN --severity Low --category 'Policy' --check 'Held packages' \
                    --detail "These packages are held back and never updated: $held." \
                    --rec 'Ask why; release the hold (sudo apt-mark unhold <package>) unless it is deliberate.'
            fi
        fi
    elif [ "$PKG" = 'dnf' ]; then
        local t on=''
        for t in dnf-automatic-install.timer dnf-automatic.timer dnf5-automatic.timer; do
            if msp_have systemctl && [ "$(systemctl is-enabled "$t" 2>/dev/null)" = 'enabled' ]; then on=$t; break; fi
        done
        if [ -z "$on" ]; then
            found=1
            msp_finding --status INFO --category 'Policy' --check 'Automatic update mode' \
                --detail 'dnf-automatic is not enabled: updates install only when someone runs them (or through GNOME Software).' \
                --rec 'For unattended security updates: sudo dnf install dnf-automatic && sudo systemctl enable --now dnf-automatic-install.timer.'
        fi
        if [ -s "$ROOT/etc/dnf/plugins/versionlock.list" ]; then
            found=1
            msp_finding --status WARN --severity Low --category 'Policy' --check 'Held packages' \
                --detail "Packages are version-locked (never updated): $(grep -v '^#' "$ROOT/etc/dnf/plugins/versionlock.list" | head -n 5 | paste -sd ',' - | sed 's/,/, /g')." \
                --rec 'Ask why; remove the lock (sudo dnf versionlock delete <package>) unless it is deliberate.'
        fi
    fi
    if msp_have snap; then
        # Asks the local snapd only (no network).
        local hold
        hold=$(snap refresh --time 2>/dev/null | sed -n 's/^hold: *//p')
        if [ -n "$hold" ] && [ "$hold" != 'n/a' ]; then
            found=1
            msp_finding --status WARN --severity Low --category 'Policy' --check 'Updates paused' \
                --detail "Snap updates are held until $hold." --rec 'Remove the hold (sudo snap refresh --unhold) unless it is deliberate.'
        fi
    fi
    if [ "$found" -eq 0 ]; then
        msp_finding --status PASS --category 'Policy' --check 'Update policies' --detail 'Updates are checked and installed automatically; nothing is held back.'
    fi
}
msp_check 'Policy' 'Update policies' check_settings

msp_complete "$OUTPUT"
exit 0
