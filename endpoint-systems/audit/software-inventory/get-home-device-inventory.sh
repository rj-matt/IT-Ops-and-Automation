#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2329  # The embedded helper defines globals and functions this script does not use; checks run through msp_check.
# get-home-device-inventory.sh - read-only inventory of a Mac or Linux computer: hardware and OS,
# user accounts with last login, and installed software, flagging remote-access tools and
# peer-to-peer (torrent) software for the client to confirm. The Windows version is
# Get-HomeDeviceInventory.ps1 (same checks and finding IDs).
#
# Usage:  bash get-home-device-inventory.sh [--approved-remote-tool NAME[,NAME...]]
#                                           [--stale-account-days N] [--all-users] [--output DIR]
#
# Options:
#   --approved-remote-tool LIST  Remote-access tools the MSP or client uses on purpose (comma
#                                separated). Matching tools are INFO, not WARN. REPLACES
#                                approved-remote-tools.txt (next to this script) for this run.
#   --stale-account-days N       Accounts not used for N days are flagged (14-3650, default 90).
#   --all-users                  macOS: also list the apps in every other user's ~/Applications.
#                                Needs root (sudo). Linux packages are already system-wide.
#   --output DIR                 Also save results as JSON and CSV (toolkit schema 2.0), with
#                                Device, Users, Profiles, Software and FlaggedSoftware tables.
#   --help                       Show this help.
#
# Device    Maker, model, serial number (Linux: sudo), OS and version, CPU, memory, startup disk
#           space, last restart, and management (MDM / directory binding / realm join).
# Users     Local accounts (UID 500+ on macOS, 1000+ on Linux) with last login and admin rights;
#           home folders and when each was last used; unused accounts flagged. With sudo on
#           Linux, accounts allowed to log in with an empty password are flagged.
# Software  macOS: apps in /Applications and the user's ~/Applications (each with one folder level
#           below it; every user's with --all-users). Linux: dpkg/rpm packages, snaps and
#           Flatpaks. Flags remote-access tools (TeamViewer, AnyDesk, RustDesk, VNC ...;
#           scammers install these) and peer-to-peer clients. Running processes are checked
#           too, because portable remote tools run without being installed.
#
# Examples:
#   bash get-home-device-inventory.sh
#   bash get-home-device-inventory.sh --approved-remote-tool Kaseya,ScreenConnect --output ~/Desktop/Audit
#   sudo bash get-home-device-inventory.sh --all-users --output ~/Desktop/Audit
#
# Purpose       : Know what this computer is, who uses it, and what is installed on it.
# Use Case      : Home network security audits; onboarding; "someone has been on my computer" tickets.
# Scope         : This computer only. No network scanning.
# Risk Level    : Read-Only -- reads system information, account lists, the app/package lists and
#                 the process list; changes nothing.
# Prerequisites : macOS 12+ or Linux | bash 3.2+ | root: No (Linux: sudo adds serial number and
#                 empty-password check; macOS: sudo with --all-users adds other users' apps)
# Version       : 1.1.1
# Limitations   : macOS apps outside /Applications and ~/Applications (and one folder level
#                 below them) and portable programs that are not running are not listed.
#                 Without --all-users as root, other users' ~/Applications are not listed.
#                 Linux: other users' per-user Flatpaks are not listed. Last login comes from the login records (wtmp), which rotate.
#                 Name matching can miss renamed tools. MSP_TEST_ROOT (development tests only)
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

SCRIPT_VERSION='1.1.1'
OUTPUT=''
APPROVED=''
APPROVED_GIVEN=0
STALE_DAYS=90
ALL_USERS=0
while [ $# -gt 0 ]; do
    case "$1" in
        --output)
            OUTPUT=${2-}
            [ -n "$OUTPUT" ] || { printf 'Missing folder after --output\n' >&2; exit 2; }
            shift 2
            ;;
        --all-users) ALL_USERS=1; shift ;;
        --approved-remote-tool) APPROVED=$(printf '%s' "${2-}" | tr ',' '\n' | sed 's/^ *//; s/ *$//' | grep .); APPROVED_GIVEN=1; shift 2 ;;
        --stale-account-days)
            STALE_DAYS=${2-}
            case "$STALE_DAYS" in '' | *[!0-9]*) printf -- '--stale-account-days needs 14-3650\n' >&2; exit 2 ;; esac
            if [ "$STALE_DAYS" -lt 14 ] || [ "$STALE_DAYS" -gt 3650 ]; then printf -- '--stale-account-days needs 14-3650\n' >&2; exit 2; fi
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
[ "$APPROVED_GIVEN" -eq 1 ] && msp_param ApprovedRemoteTool "$(printf '%s\n' "$APPROVED" | paste -sd ',' -)"
msp_param StaleAccountDays "$STALE_DAYS"
[ "$ALL_USERS" -eq 1 ] && msp_param AllUsers 1
msp_init 'get-home-device-inventory' "$SCRIPT_VERSION" 'A8' 'Read-Only' 'Device, user and software inventory (read-only)' \
    'serial number and empty-password check (Linux); other users'' apps (--all-users, macOS)'

ROOT=${MSP_TEST_ROOT:-}
NOW=$(date +%s)
HERE=$(cd "$(dirname "$0")" 2>/dev/null && pwd)

file_mtime() {
    if [ "$MSP_PLATFORM" = 'macOS' ]; then stat -f %m "$1" 2>/dev/null; else stat -c %Y "$1" 2>/dev/null; fi # linux-only: stat -c
}
ymd() {
    if [ "$MSP_PLATFORM" = 'macOS' ]; then date -r "$1" '+%Y-%m-%d'; else date -d "@$1" '+%Y-%m-%d'; fi # linux-only: date -d
}

# --- Approved remote tools ----------------------------------------------------------------------
APPROVED_FILE="$HERE/approved-remote-tools.txt"
APPROVED_SOURCE='--approved-remote-tool'
if [ "$APPROVED_GIVEN" -eq 0 ]; then
    APPROVED_SOURCE=$APPROVED_FILE
    if [ -f "$APPROVED_FILE" ]; then
        APPROVED=$(sed 's/^[[:space:]]*//; s/[[:space:]]*$//' "$APPROVED_FILE" | grep -v '^#' | grep .)
    else
        APPROVED_SOURCE="$APPROVED_FILE - file not found"
    fi
fi
APPROVED_TEXT=$(printf '%s\n' "$APPROVED" | paste -sd ',' - | sed 's/,/, /g')
[ -n "$APPROVED_TEXT" ] || APPROVED_TEXT='none'
msp_finding --status INFO --category 'Setup' --check 'Approved remote tools' --detail "$APPROVED_TEXT (from $APPROVED_SOURCE)" \
    --evidence "$(msp_json_obj Source "$APPROVED_SOURCE" Tools "$APPROVED_TEXT")"

is_approved() {
    local a
    while IFS= read -r a; do
        [ -n "$a" ] || continue
        printf '%s' "$1" | grep -iqF -- "$a" && return 0
    done <<EOF
$APPROVED
EOF
    return 1
}

# Remote-access tools: Name (same as the Windows version, so IDs match)#installed-name pattern
# (ERE, case-insensitive)#process-name pattern (ERE on the process name). "#" separates the
# fields because the patterns use "|".
REMOTE_TOOLS='TeamViewer#teamviewer#^TeamViewer|^teamviewerd
AnyDesk#anydesk#^AnyDesk$|^anydesk$
RustDesk#rustdesk#^[Rr]ust[Dd]esk$
HopToDesk#hoptodesk#^[Hh]op[Tt]o[Dd]esk$
Splashtop#splashtop#^Splashtop|^SRFeature|^SRStreamer
LogMeIn / GoTo#logmein|goto ?(assist|resolve|mypc|opener)#^LogMeIn|^GoTo
ConnectWise ScreenConnect#screenconnect|connectwise ?control|connectwisecontrol#^connectwisecontrol|^ScreenConnect
Chrome Remote Desktop#chrome[ -]remote[ -]desktop#^remoting_me2me_host|^ChromeRemoteDesktopHost|^remoting_host
VNC (UltraVNC/TightVNC/RealVNC/TigerVNC)#realvnc|vnc ?server|vnc ?viewer|tigervnc|tightvnc|x11vnc#^vncserver|^vncagent|^Xvnc|^x11vnc|^vncserverui
Supremo#supremo#^Supremo
Remote Utilities#remote utilities#^rutserv
RemotePC#remotepc#^RemotePC
Zoho Assist#zoho ?assist#^ZohoAssist|^ZA_
DWService#dwagent|dwservice#^dwagent|^dwagsvc
SimpleHelp#simplehelp#^SimpleHelp|^SimpleService
MeshCentral agent#mesh ?agent|meshcentral#^meshagent|^MeshAgent
NoMachine#nomachine#^nxserver|^nxnode|^nxd$
Parsec#^parsec#^parsecd
Getscreen.me#getscreen#^getscreen
Jump Desktop#jump desktop#^Jump Desktop Connect
BeyondTrust / Bomgar#beyondtrust|bomgar#^bomgar
Atera#atera#^AteraAgent
NinjaOne#ninjarmm|ninjaone#^ninjarmm|^NinjaRMMAgent
N-able / Take Control#n-able|n-central|take control|solarwinds msp#^BASupSrvc|^TakeControl
Kaseya#kaseya#^AgentMon|^KaseyaAgent
Datto RMM#datto rmm|centrastage|aemagent#^AEMAgent
Action1#action1#^action1_agent'
P2P_PATTERN='utorrent|bittorrent|qbittorrent|vuze|azureus|deluge|transmission|bitcomet|tixati|frostwire|emule|amule|limewire|shareaza|soulseek|biglybt|webtorrent|popcorn time|halite|ktorrent|fragments|motrix'

# =========================================================================================
msp_section 'Device'
# =========================================================================================
check_device() {
    local maker='' model='' serial='' os version='' cpu='' mem='' disk_total='' disk_free='' free_pct='' boot='' join=''
    os=$MSP_OS_VERSION
    if [ "$MSP_PLATFORM" = 'macOS' ]; then
        local hw
        hw=$(system_profiler SPHardwareDataType 2>/dev/null)
        maker='Apple'
        model="$(printf '%s\n' "$hw" | sed -n 's/^ *Model Name: //p' | head -n 1) ($(printf '%s\n' "$hw" | sed -n 's/^ *Model Identifier: //p' | head -n 1))"
        serial=$(printf '%s\n' "$hw" | sed -n 's/^ *Serial Number (system): //p' | head -n 1)
        cpu=$(printf '%s\n' "$hw" | sed -n 's/^ *Chip: //p; s/^ *Processor Name: //p' | head -n 1)
        mem=$(printf '%s\n' "$hw" | sed -n 's/^ *Memory: //p' | head -n 1)
        version="build $(sw_vers -buildVersion 2>/dev/null)"
        boot=$(sysctl -n kern.boottime 2>/dev/null | sed -n 's/^{ *sec = \([0-9]*\),.*/\1/p')
        local mdm ad
        mdm=$(profiles status -type enrollment 2>/dev/null | grep -q 'MDM enrollment: Yes' && printf 'MDM managed')
        ad=$(dsconfigad -show 2>/dev/null | sed -n 's/^ *Active Directory Domain *= *//p')
        join='Not managed'
        [ -n "$mdm" ] && join=$mdm
        [ -n "$ad" ] && join="$join; Active Directory: $ad"
    else
        maker=$(cat "$ROOT/sys/class/dmi/id/sys_vendor" 2>/dev/null)
        model=$(cat "$ROOT/sys/class/dmi/id/product_name" 2>/dev/null)
        serial=$(cat "$ROOT/sys/class/dmi/id/product_serial" 2>/dev/null)
        [ -n "$serial" ] || { msp_is_root || serial='(needs sudo)'; }
        cpu=$(awk -F: '/^model name/ { sub(/^ */, "", $2); print $2; exit }' "$ROOT/proc/cpuinfo" 2>/dev/null)
        [ -n "$cpu" ] || cpu=$(lscpu 2>/dev/null | awk -F: '/^Model name/ { sub(/^ */, "", $2); print $2; exit }')
        mem=$(awk '/^MemTotal:/ { printf "%.1f GB", $2 / 1048576 }' "$ROOT/proc/meminfo" 2>/dev/null)
        version="kernel $(uname -r)"
        local up
        up=$(cut -d. -f1 "$ROOT/proc/uptime" 2>/dev/null)
        [ -n "$up" ] && boot=$((NOW - up))
        join='Workgroup (not joined)'
        if msp_have realm; then
            local realm
            realm=$(realm list --name-only 2>/dev/null | head -n 1)
            [ -n "$realm" ] && join="Domain (realm): $realm"
        fi
    fi
    # Startup disk: size and free space (1K blocks).
    local df_line
    df_line=$(df -k / 2>/dev/null | awk 'NR == 2 { print $2, $4 }')
    if [ -n "$df_line" ]; then
        disk_total=$((${df_line% *} / 1048576))
        disk_free=$((${df_line#* } / 1048576))
        [ "${df_line% *}" -gt 0 ] && free_pct=$((100 * ${df_line#* } / ${df_line% *}))
    fi
    # macOS: the data volume holds the free space; "/" is the sealed system snapshot.
    if [ "$MSP_PLATFORM" = 'macOS' ]; then
        df_line=$(df -k /System/Volumes/Data 2>/dev/null | awk 'NR == 2 { print $2, $4 }')
        if [ -n "$df_line" ]; then
            disk_free=$((${df_line#* } / 1048576))
            [ "${df_line% *}" -gt 0 ] && free_pct=$((100 * ${df_line#* } / ${df_line% *}))
        fi
    fi
    local boot_text=''
    [ -n "$boot" ] && boot_text=$(ymd "$boot")
    printf '  Computer      : %s\n  Maker / model : %s %s\n  Serial number : %s\n  OS            : %s (%s)\n  CPU           : %s\n  Memory        : %s\n  Startup disk  : %s GB, %s GB free\n  Last restart  : %s\n  Management    : %s\n' \
        "$MSP_HOST" "$maker" "$model" "${serial:-unknown}" "$os" "$version" "${cpu:-unknown}" "${mem:-unknown}" "$disk_total" "$disk_free" "$boot_text" "$join"
    msp_data_row 'Device' ComputerName "$MSP_HOST" Manufacturer "$maker" Model "$model" SerialNumber "$serial" OS "$os" Version "$version" \
        CPU "$cpu" Memory "$mem" SystemDriveGB "$disk_total" SystemFreeGB "$disk_free" LastBoot "$boot_text" JoinType "$join"
    msp_finding --status INFO --category 'Device' --check 'Device' \
        --detail "$maker $model (S/N ${serial:-unknown}); $os ($version); ${mem:-unknown memory}; $join" \
        --evidence "$(msp_json_obj Manufacturer "$maker" Model "$model" SerialNumber "$serial" OS "$os")"
    if [ -n "$free_pct" ] && [ "$free_pct" -lt 10 ]; then
        msp_finding --status WARN --severity Low --category 'Device' --check 'System drive space' \
            --detail "The startup disk has $disk_free GB free ($free_pct%). Updates can fail with little free space." \
            --rec 'Free up space (macOS: System Settings > General > Storage; Linux: Disk Usage Analyzer, or remove old snaps/flatpaks).'
    fi
}
msp_check 'Device' 'Device details' check_device

# =========================================================================================
msp_section 'User accounts'
# =========================================================================================
last_login() {
    # Most recent login of a user from wtmp, as epoch (empty if none recorded).
    local line
    if [ "$MSP_PLATFORM" = 'macOS' ]; then
        # The host column is empty for local logins, so find the date by its weekday.
        line=$(last -1 "$1" 2>/dev/null | awk '$1 != "wtmp" { for (i = 2; i <= NF - 3; i++) if ($i ~ /^(Mon|Tue|Wed|Thu|Fri|Sat|Sun)$/) { print $i, $(i + 1), $(i + 2), $(i + 3); exit } }')
        [ -n "$line" ] || return 0
        # "Mon Oct 16 15:36" has no year: assume the most recent one not in the future.
        local y e
        y=$(date '+%Y')
        e=$(date -j -f '%a %b %d %H:%M %Y' "$line $y" '+%s' 2>/dev/null)
        [ -n "$e" ] && [ "$e" -gt "$NOW" ] && e=$(date -j -f '%a %b %d %H:%M %Y' "$line $((y - 1))" '+%s' 2>/dev/null)
        printf '%s' "$e"
    else
        line=$(last -F -1 "$1" 2>/dev/null | awk '$1 != "wtmp" { for (i = 2; i <= NF - 4; i++) if ($i ~ /^(Mon|Tue|Wed|Thu|Fri|Sat|Sun)$/) { print $i, $(i + 1), $(i + 2), $(i + 3), $(i + 4); exit } }')
        [ -n "$line" ] && date -d "$line" '+%s' 2>/dev/null # linux-only: date -d
    fi
    return 0
}

ADMIN_USERS=''
USER_ROWS=''   # name|fullname|uid|home|admin|lastlogin(epoch)
check_users() {
    local name uid home full admin last
    if [ "$MSP_PLATFORM" = 'macOS' ]; then
        ADMIN_USERS=$(dscl . -read /Groups/admin GroupMembership 2>/dev/null | sed 's/^GroupMembership://')
        while read -r name uid; do
            [ -n "$name" ] || continue
            case "$name" in _* | root | daemon | nobody) continue ;; esac
            [ "$uid" -ge 500 ] 2>/dev/null || continue
            home=$(dscl . -read "/Users/$name" NFSHomeDirectory 2>/dev/null | awk '{ print $2 }')
            full=$(dscl . -read "/Users/$name" RealName 2>/dev/null | sed 's/^RealName://' | tr '\n' ' ' | sed 's/^ *//; s/ *$//')
            USER_ROWS="$USER_ROWS$name|$full|$uid|$home
"
        done <<EOF
$(dscl . -list /Users UniqueID 2>/dev/null)
EOF
    else
        ADMIN_USERS=$(for g in sudo wheel admin; do getent group "$g" 2>/dev/null | cut -d: -f4 | tr ',' ' '; done)
        while IFS=: read -r name _ uid _ full home shell; do
            [ -n "$name" ] || continue
            [ "$uid" -ge 1000 ] 2>/dev/null && [ "$uid" -lt 60000 ] || continue
            case "$shell" in */nologin | */false) continue ;; esac
            USER_ROWS="$USER_ROWS$name|${full%%,*}|$uid|$home
"
        done <<EOF
$(getent passwd 2>/dev/null)
EOF
    fi
    local count=0 list='' row
    while IFS='|' read -r name full uid home; do
        [ -n "$name" ] || continue
        admin=false
        case " $(printf '%s' "$ADMIN_USERS" | tr '\n' ' ') " in *" $name "*) admin=true ;; esac
        last=$(last_login "$name")
        local last_text=''
        [ -n "$last" ] && last_text=$(ymd "$last")
        count=$((count + 1))
        list="$list${list:+, }$name$([ "$admin" = true ] && printf ' (admin)')"
        msp_data_row 'Users' Name "$name" FullName "$full" Enabled# true IsAdmin# "$admin" LastLogon "$last_text" UID "$uid" Home "$home"
        if [ -n "$last" ]; then
            local idle=$(((NOW - last) / 86400))
            if [ "$idle" -gt "$STALE_DAYS" ]; then
                msp_finding --status WARN --severity Low --category 'Users' --check "Account \"$name\" unused" \
                    --detail "Account \"$name\" last signed in $last_text ($idle days ago)." \
                    --rec 'If nobody uses this account, disable or remove it (with the client'\''s agreement).'
            fi
        fi
    done <<EOF
$USER_ROWS
EOF
    msp_finding --status INFO --category 'Users' --check 'Local accounts' --detail "$count local account(s): ${list:-none}"
}
msp_check 'Users' 'Local accounts' check_users

check_empty_passwords() {
    # Empty password field in /etc/shadow = login without a password. Only the status is read.
    local name status found=0
    while IFS='|' read -r name _ _ _; do
        [ -n "$name" ] || continue
        status=$(passwd -S "$name" 2>/dev/null | awk '{ print $2 }')
        if [ "$status" = 'NP' ]; then
            found=1
            msp_finding --status WARN --severity Low --category 'Users' --check "Account \"$name\" password" \
                --detail "Account \"$name\" has no password: anyone at the computer can log in as it." \
                --rec 'Set a password for the account (with the client), or lock it if unused.'
        fi
    done <<EOF
$USER_ROWS
EOF
    [ "$found" -eq 1 ] || msp_finding --status PASS --category 'Users' --check 'Account passwords' --detail 'Every local account has a password or is locked.'
}
if [ "$MSP_PLATFORM" = 'Linux' ]; then
    msp_check --root 'Password status is only readable by root.' 'Users' 'Account passwords' check_empty_passwords
fi

check_profiles() {
    local base dir name count=0 list='' used owner
    base="$ROOT/Users"
    [ "$MSP_PLATFORM" = 'Linux' ] && base="$ROOT/home"
    for dir in "$base"/*/; do
        dir=${dir%/}
        [ -d "$dir" ] || continue
        name=${dir##*/}
        case "$name" in Shared | Guest | .* | lost+found) continue ;; esac
        used=$(file_mtime "$dir")
        owner='(account no longer exists)'
        printf '%s' "$USER_ROWS" | awk -F'|' -v h="${dir#"$ROOT"}" -v n="$name" '$4 == h || $1 == n { f = 1 } END { exit !f }' && owner=$name
        count=$((count + 1))
        list="$list${list:+, }$name"
        msp_data_row 'Profiles' Account "$owner" Path "${dir#"$ROOT"}" LastUsed "$([ -n "$used" ] && ymd "$used")"
        if [ "$owner" = '(account no longer exists)' ]; then
            msp_finding --status INFO --category 'Users' --check 'Orphaned profiles' --detail "Home folder ${dir#"$ROOT"} has no matching account and uses disk space."
        fi
    done
    msp_finding --status INFO --category 'Users' --check 'User profiles' --detail "$count home folder(s): ${list:-none}"
}
msp_check 'Users' 'User profiles' check_profiles

# =========================================================================================
msp_section 'Installed software'
# =========================================================================================
SOFTWARE="${MSP_WORK_DIR:-${TMPDIR:-/tmp}}/software.txt"   # Name|Version|Scope|InstallDate
: >"$SOFTWARE"

# macOS: users whose ~/Applications is listed, as name|home. The signed-in user (the one who ran
# sudo, under sudo) always; every other local account with --all-users as root.
SELF=${SUDO_USER:-$MSP_USER}
SELF_HOME=''
[ "$MSP_PLATFORM" = 'macOS' ] && SELF_HOME=$(dscl . -read "/Users/$SELF" NFSHomeDirectory 2>/dev/null | awk '{ print $2 }')
[ -n "$SELF_HOME" ] || SELF_HOME=$HOME
APP_HOMES="$SELF|$SELF_HOME"
if [ "$ALL_USERS" -eq 1 ]; then
    if [ "$MSP_PLATFORM" = 'macOS' ]; then
        add_other_homes() {
            local name home count=0
            while IFS='|' read -r name _ _ home; do
                [ -n "$name" ] && [ "$name" != "$SELF" ] && [ -n "$home" ] || continue
                APP_HOMES="$APP_HOMES
$name|$home"
                count=$((count + 1))
            done <<EOF
$USER_ROWS
EOF
            msp_finding --status INFO --category 'Software' --check "Other users' software" --detail "Also listing the apps in $count other user(s)' ~/Applications."
        }
        msp_check --root "Other users' home folders are protected; only /Applications and your own ~/Applications are listed." 'Software' "Other users' software" add_other_homes
    else
        msp_finding --status INFO --category 'Software' --check "Other users' software" \
            --detail 'Packages, snaps and system Flatpaks are installed for all users, so --all-users adds nothing on Linux. Other users'\'' per-user Flatpaks are not listed.'
    fi
fi

list_mac_apps() {
    # list_mac_apps FOLDER SCOPE - apps in FOLDER and one level below it (e.g. /Applications/Utilities).
    local app v
    for app in "$1"/*.app "$1"/*/*.app; do
        [ -f "$app/Contents/Info.plist" ] || continue
        v=$(defaults read "$app/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null)
        printf '%s|%s|%s|%s\n' "$(basename "$app" .app)" "$v" "$2" "$(ymd "$(file_mtime "$app")")"
    done
}
list_software() {
    if [ "$MSP_PLATFORM" = 'macOS' ]; then
        local name home
        list_mac_apps "$ROOT/Applications" 'All users'
        while IFS='|' read -r name home; do
            [ -n "$name" ] && [ -n "$home" ] && list_mac_apps "$ROOT$home/Applications" "User: $name"
        done <<EOF
$APP_HOMES
EOF
    else
        if msp_have dpkg-query; then
            dpkg-query -W -f '${Package}|${Version}|package|\n' 2>/dev/null
        elif msp_have rpm; then
            rpm -qa --qf '%{NAME}|%{VERSION}|package|%{INSTALLTIME:date}\n' 2>/dev/null
        fi
        if msp_have snap; then snap list 2>/dev/null | awk 'NR > 1 { print $1 "|" $2 "|snap|" }'; fi
        if msp_have flatpak; then flatpak list --app --columns=name,version,installation 2>/dev/null | awk -F'\t' '{ print $1 "|" $2 "|flatpak (" $3 ")|" }'; fi
    fi
}
check_software() {
    list_software >"$SOFTWARE"
    local count name v scope d
    count=$(grep -c . "$SOFTWARE")
    while IFS='|' read -r name v scope d; do
        [ -n "$name" ] && msp_data_row 'Software' Name "$name" Version "$v" Scope "$scope" InstallDate "$d"
    done <"$SOFTWARE"
    local what='app(s) in /Applications and ~/Applications'
    [ "$MSP_PLATFORM" = 'Linux' ] && what='package(s), snaps and Flatpaks'
    msp_finding --status INFO --category 'Software' --check 'Installed software' --detail "$count $what."
}
msp_check 'Software' 'Installed software' check_software

check_flagged() {
    local procs flagged=0 tool pattern ppattern installed running newest
    # On macOS, programs under /System, /usr and /Library/Apple are part of macOS (protected by
    # SIP), never third-party tools: Apple's own "parsecd" would otherwise look like Parsec.
    procs=$(ps -axo comm= 2>/dev/null | { if [ "$MSP_PLATFORM" = 'macOS' ]; then grep -vE '^/(System|usr|Library/Apple)/'; else cat; fi; } | sed 's|.*/||' | sort -u)
    while IFS='#' read -r tool pattern ppattern; do
        [ -n "$tool" ] || continue
        installed=$(grep -iE "^[^|]*($pattern)" "$SOFTWARE" | head -n 5)
        running=$(printf '%s\n' "$procs" | grep -E "$ppattern" | head -n 3 | paste -sd ',' - | sed 's/,/, /g')
        [ -n "$installed" ] || [ -n "$running" ] || continue
        flagged=$((flagged + 1))
        local where='' versions newest_epoch='' dt
        versions=$(printf '%s\n' "$installed" | awk -F'|' 'NF { print $1 " " $2 }' | paste -sd ';' - | sed 's/;/; /g')
        [ -n "$installed" ] && where="installed: $versions"
        [ -n "$running" ] && where="$where${where:+; }running now: $running"
        [ -n "$installed" ] || where="$where; NOT installed - a portable copy is running"
        newest=$(printf '%s\n' "$installed" | awk -F'|' '$4 != "" { print $4 }' | sort | tail -n 1)
        msp_data_row 'FlaggedSoftware' Type 'Remote access' Tool "$tool" Detail "$where" InstallDate "$newest" Running# "$([ -n "$running" ] && echo true || echo false)"
        local check="Remote-access tool: $tool" ev
        ev=$(msp_json_obj Tool "$tool" Installed "$versions" Running# "$([ -n "$running" ] && echo true || echo false)" InstallDate "$newest")
        if is_approved "$tool" || printf '%s\n' "$installed" | while IFS='|' read -r n _; do [ -n "$n" ] && is_approved "$n" && exit 0; done; then
            msp_finding --status INFO --category 'Software' --check "$check" --evidence "$ev" --detail "$where (approved remote tool)."
            continue
        fi
        local sev='Medium' why='Remote-access software lets someone control this computer. Fine if the client or their IT uses it; tech-support scammers install it too.'
        local recent=0
        if [ -n "$newest" ]; then
            if [ "$MSP_PLATFORM" = 'macOS' ]; then dt=$(date -j -f '%Y-%m-%d' "$newest" '+%s' 2>/dev/null); else dt=$(date -d "$newest" '+%s' 2>/dev/null); fi # linux-only: date -d
            [ -n "$dt" ] && [ $(((NOW - dt) / 86400)) -le 30 ] && recent=1
        fi
        if [ "$recent" -eq 1 ] || { [ -z "$installed" ] && [ -n "$running" ]; }; then
            sev='High'
            why='Installed (or updated) in the last 30 days, or running without being installed - both are typical of a tech-support scam.'
        fi
        msp_finding --status WARN --severity "$sev" --category 'Software' --check "$check" --evidence "$ev" \
            --detail "$where. $why" \
            --rec 'Ask the client who installed it and whether they still use it. If nobody knows, uninstall it, change the client'\''s important passwords, and check bank accounts (escalate as a possible scam).'
    done <<EOF
$REMOTE_TOOLS
EOF
    local p2p name v scope d
    p2p=$(grep -iE "^[^|]*($P2P_PATTERN)" "$SOFTWARE")
    while IFS='|' read -r name v scope d; do
        [ -n "$name" ] || continue
        flagged=$((flagged + 1))
        local is_running=false
        printf '%s\n' "$procs" | grep -iqE "$P2P_PATTERN" && is_running=true
        msp_data_row 'FlaggedSoftware' Type 'Peer-to-peer' Tool "$name" Detail "version $v, $scope" InstallDate "$d" Running# "$is_running"
        # Ubuntu Desktop installs Transmission by default; unused, it is not a concern.
        if [ "$MSP_PLATFORM" = 'Linux' ] && printf '%s' "$name" | grep -q '^transmission' && [ "$is_running" = 'false' ]; then
            msp_finding --status INFO --category 'Software' --check "Peer-to-peer software: $name" \
                --detail "$name $v is installed (part of the default Ubuntu desktop) and not running." \
                --rec 'Remove it if the client never uses torrents: sudo apt remove transmission-gtk.'
            continue
        fi
        msp_finding --status WARN --severity Low --category 'Software' --check "Peer-to-peer software: $name" \
            --detail "$name $v is installed. Torrent downloads are a common source of malware, and sharing can expose personal folders or trigger copyright notices from the ISP." \
            --rec 'Confirm the client uses it. If not, uninstall it. If yes, make sure it only shares its own download folder.' \
            --evidence "$(msp_json_obj Name "$name" Version "$v" InstallDate "$d")"
    done <<EOF
$p2p
EOF
    if [ -z "$p2p" ] && printf '%s\n' "$procs" | grep -iqE "$P2P_PATTERN"; then
        flagged=$((flagged + 1))
        msp_finding --status WARN --severity Low --category 'Software' --check 'Peer-to-peer software running' \
            --detail "A torrent/P2P program is running without being installed: $(printf '%s\n' "$procs" | grep -iE "$P2P_PATTERN" | paste -sd ',' - | sed 's/,/, /g')." \
            --rec 'Confirm the client uses it; if not, close it and delete the portable copy.'
    fi
    if [ "$flagged" -eq 0 ]; then
        msp_finding --status PASS --category 'Software' --check 'Remote-access and P2P software' --detail 'No remote-access tools or peer-to-peer software found (installed or running).'
    fi
}
msp_check 'Software' 'Remote-access and P2P software' check_flagged

msp_complete "$OUTPUT"
exit 0
