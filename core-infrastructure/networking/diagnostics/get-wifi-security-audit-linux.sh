#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2329  # The embedded helper defines globals and functions this script does not use; checks run through msp_check.
# get-wifi-security-audit-linux.sh - read-only Wi-Fi security audit of a Linux computer that
# uses NetworkManager: the network it is on, saved Wi-Fi connections and nearby networks,
# flagging open, WEP and WPA (v1) / TKIP security. Wi-Fi passwords are never read.
#
# Usage:  bash get-wifi-security-audit-linux.sh [--home-ssid NAME] [--output DIR] [--help]
#
# Options:
#   --home-ssid NAME  Name of the client's home Wi-Fi, so it is rated from the nearby scan when
#                     the computer is wired or elsewhere, and checked for look-alike networks.
#   --output DIR      Also save results as JSON and CSV (toolkit schema 2.0).
#   --help            Show this help.
#
# Sources (all local; no new Wi-Fi scan is started):
#   Current connection and nearby networks  nmcli device wifi list --rescan no (NetworkManager's
#                                           last scan)
#   Saved connections                       nmcli connection show: key management, WPA protocol,
#                                           pairwise cipher and autoconnect. --show-secrets is
#                                           NEVER used, so passwords are not read.
#
# Ratings: WPA3 (SAE), WPA2 with AES (CCMP), Enhanced Open (OWE) = good. WPA (v1) or TKIP =
# weak. WEP or no security = insecure.
#
# Examples:
#   bash get-wifi-security-audit-linux.sh
#   bash get-wifi-security-audit-linux.sh --home-ssid "Smith-Home" --output ~/Audit
#
# Purpose       : Confirm the home Wi-Fi is encrypted properly and the computer won't auto-join unsafe networks.
# Use Case      : Home network security audits; travelling users; "slow/unsafe Wi-Fi" tickets.
# Scope         : This computer's Wi-Fi interfaces and saved connections; nearby networks from the last scan.
# Risk Level    : Read-Only -- reads Wi-Fi status only. Never reads Wi-Fi passwords; changes nothing.
# Prerequisites : bash 3.2+ | NetworkManager (nmcli) | root: No
# Version       : 1.0.0
# Limitations   : Systems without NetworkManager (iwd, wpa_supplicant alone, netplan servers)
#                 are reported as SKIPPED. Saved connections owned by another user may hide
#                 their settings from a normal user. Router-side settings are checked by the A7
#                 router script. Same check names and IDs as Get-WiFiSecurityAudit.ps1.

set -u
MSP_SCRIPT_FILE=$0

#region MSPToolkit (generated) Sections=Core
# DO NOT EDIT — regenerate with Sync-MSPEmbeddedHelper.ps1
# Source: endpoint-systems/utilities/msp-toolkit-common.sh | Sections: Core | SHA256: c93b8ebd85f2eb4e3d0aa030462f76b8d1669d19cefeb05aef9939d0932e03fc
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
HOME_SSID=''
while [ $# -gt 0 ]; do
    case "$1" in
        --output)
            OUTPUT=${2-}
            [ -n "$OUTPUT" ] || { printf 'Missing folder after --output\n' >&2; exit 2; }
            shift 2
            ;;
        --home-ssid)
            HOME_SSID=${2-}
            [ -n "$HOME_SSID" ] || { printf 'Missing name after --home-ssid\n' >&2; exit 2; }
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
if [ "$(uname -s)" != 'Linux' ]; then
    printf 'This script is for Linux. On macOS use get-wifi-security-audit-macos.sh.\n' >&2
    exit 2
fi

[ -n "$OUTPUT" ] && msp_param Output "$OUTPUT"
[ -n "$HOME_SSID" ] && msp_param HomeSsid "$HOME_SSID"
msp_init 'get-wifi-security-audit-linux' "$SCRIPT_VERSION" 'A3' 'Read-Only' 'Wi-Fi security audit (read-only; passwords are never read)'

scan_rating() {
    # scan_rating SECURITY -> "Level|Label" for nmcli's SECURITY column ("WPA2", "WPA1 WPA2",
    # "WPA3", "WPA2 WPA3", "WEP", "OWE", "WPA2 802.1X", or empty for open).
    case "$1" in
        '' | '--') printf 'Insecure|Open (no encryption)' ;;
        *OWE*) printf 'Good|Enhanced Open (encrypted, no password)' ;;
        *WEP*) printf 'Insecure|WEP (crackable in minutes)' ;;
        *WPA1*) printf 'Weak|%s (allows original WPA, outdated)' "$1" ;;
        *WPA2* | *WPA3*) printf 'Good|%s' "$1" ;;
        *) printf 'Unknown|%s' "$1" ;;
    esac
}

profile_rating() {
    # profile_rating KEY_MGMT PROTO PAIRWISE WEP_TYPE -> "Level|Label" for a saved connection.
    local km=$1 proto=$2 pairwise=$3
    case "$km" in
        '' | none)
            if [ -n "$4" ] && [ "$4" != '0' ] && [ "$4" != 'unknown' ]; then printf 'Insecure|WEP (crackable in minutes)'
            elif [ "$km" = 'none' ]; then printf 'Insecure|WEP (crackable in minutes)'
            else printf 'Insecure|Open (no encryption)'; fi
            ;;
        ieee8021x) printf 'Insecure|Dynamic WEP (802.1X, outdated)' ;;
        owe) printf 'Good|Enhanced Open (encrypted, no password)' ;;
        sae) printf 'Good|WPA3 Personal (SAE)' ;;
        wpa-psk | wpa-eap | wpa-eap-suite-b-192)
            case "$pairwise" in *tkip*) printf 'Weak|%s with TKIP (outdated cipher)' "$km"; return ;; esac
            case "$proto" in *wpa*) case "$proto" in *rsn*) ;; *) printf 'Weak|%s, original WPA only (outdated)' "$km"; return ;; esac ;; esac
            printf 'Good|%s (WPA2/AES)' "$km"
            ;;
        *) printf 'Unknown|%s' "$km" ;;
    esac
}

rank() {
    case "$1" in Insecure) printf 0 ;; Weak) printf 1 ;; Unknown) printf 2 ;; *) printf 3 ;; esac
}

nm_split() {
    # nmcli -t escapes ":" inside values as "\:"; turn the field separator into "|" instead.
    awk '{ gsub(/\\:/, "\001"); gsub(/:/, "|"); gsub(/\001/, ":"); print }'
}

# =========================================================================================
msp_section 'Wi-Fi adapter'
# =========================================================================================
WIFI_OK=0
SCAN_FILE="${MSP_WORK_DIR:-${TMPDIR:-/tmp}}/wifi-scan.txt"
check_adapter() {
    if ! msp_have nmcli; then
        msp_skip 'Adapter' 'Wi-Fi adapter' 'Skipped: NetworkManager (nmcli) is not installed, so Wi-Fi settings cannot be read the supported way.' \
            'On systems using iwd or wpa_supplicant directly, check the Wi-Fi security by hand (iwctl station <dev> show / wpa_cli status).'
        return 0
    fi
    local devs
    devs=$(nmcli -t -f DEVICE,TYPE,STATE device status 2>/dev/null | nm_split | awk -F'|' '$2 == "wifi" { print $1 " (" $3 ")" }' | paste -sd ',' - | sed 's/,/, /g')
    if [ -z "$devs" ]; then
        msp_finding --status INFO --category 'Adapter' --check 'Wi-Fi adapter' --detail 'No Wi-Fi interface found. Wi-Fi checks of the current connection do not apply.'
        return 0
    fi
    # Fields of NetworkManager's last scan; --rescan no keeps the radio from scanning again.
    nmcli -t -f IN-USE,SSID,BSSID,SECURITY,CHAN,FREQ,SIGNAL device wifi list --rescan no 2>/dev/null | nm_split >"$SCAN_FILE"
    WIFI_OK=1
    msp_finding --status INFO --category 'Adapter' --check 'Wi-Fi adapter' --detail "$devs"
}
msp_check 'Adapter' 'Wi-Fi adapter' check_adapter

CONNECTED_NAME=''
CONNECTED_LEVEL=''
if [ "$WIFI_OK" -eq 1 ]; then
    # =====================================================================================
    msp_section 'Current connection'
    # =====================================================================================
    check_current() {
        local row inuse ssid bssid sec chan freq sig rating level label
        row=$(awk -F'|' '$1 == "*"' "$SCAN_FILE" | head -n 1)
        if [ -z "$row" ]; then
            local detail='This computer is not connected to Wi-Fi.'
            if [ -n "$HOME_SSID" ]; then detail="$detail The home network \"$HOME_SSID\" is rated from the nearby scan below."
            else detail="$detail Use --home-ssid \"<name>\" to rate the home network from the nearby scan."; fi
            msp_finding --status INFO --category 'Connection' --check 'Current Wi-Fi connection' --detail "$detail"
            return 0
        fi
        IFS='|' read -r inuse ssid bssid sec chan freq sig <<EOF
$row
EOF
        rating=$(scan_rating "$sec")
        level=${rating%%|*}
        label=${rating#*|}
        CONNECTED_NAME=$ssid
        CONNECTED_LEVEL=$level
        local where="\"$ssid\" ($freq, channel $chan, signal $sig%)"
        local ev
        ev=$(msp_json_obj SSID "$ssid" Security "$sec" Channel "$chan" Frequency "$freq" Signal "$sig")
        case "$level" in
            Good)
                msp_finding --status PASS --category 'Connection' --check 'Current Wi-Fi security' --evidence "$ev" --detail "$where: $label"
                case "$sec" in *WPA3* | *OWE*) ;; *)
                    msp_finding --status INFO --category 'Connection' --check 'WPA3 available?' \
                        --detail 'WPA2 is acceptable. If the router and all devices support it, WPA3 (or WPA2/WPA3 mixed) is stronger.' ;;
                esac
                ;;
            Weak)
                msp_finding --status FAIL --severity High --category 'Connection' --check 'Current Wi-Fi security' --evidence "$ev" \
                    --detail "$where: $label" --rec 'In the router'\''s Wi-Fi settings choose WPA2-AES (or WPA2/WPA3) and set a long passphrase.'
                ;;
            Insecure)
                msp_finding --status FAIL --severity Critical --category 'Connection' --check 'Current Wi-Fi security' --evidence "$ev" \
                    --detail "$where: $label. Anyone nearby can join or read traffic." \
                    --rec 'If this is the home network: switch the router to WPA2-AES or WPA3 with a long passphrase now. If public: use a VPN and avoid sensitive work.'
                ;;
            *)
                msp_finding --status WARN --severity Low --category 'Connection' --check 'Current Wi-Fi security' --evidence "$ev" \
                    --detail "$where: could not classify \"$sec\"." --rec 'Check the router'\''s Wi-Fi security setting manually.'
                ;;
        esac
    }
    msp_check 'Connection' 'Current Wi-Fi connection' check_current
fi

# =========================================================================================
msp_section 'Saved Wi-Fi connections'
# =========================================================================================
check_saved() {
    msp_have nmcli || return 0
    local names name total=0 good=0 fields km proto pairwise wep auto ssid rating level label
    names=$(nmcli -t -f NAME,TYPE connection show 2>/dev/null | nm_split | awk -F'|' '$2 == "802-11-wireless" { print $1 }')
    if [ -z "$names" ]; then
        msp_finding --status INFO --category 'Profiles' --check 'Saved Wi-Fi profiles' --detail 'No saved Wi-Fi connections.'
        return 0
    fi
    while IFS= read -r name; do
        [ -n "$name" ] || continue
        # Settings only; secrets would need --show-secrets, which is never used.
        fields=$(nmcli -t -f 802-11-wireless.ssid,802-11-wireless-security.key-mgmt,802-11-wireless-security.proto,802-11-wireless-security.pairwise,802-11-wireless-security.wep-key-type,connection.autoconnect \
            connection show "$name" 2>/dev/null)
        ssid=$(printf '%s\n' "$fields" | sed -n 's/^802-11-wireless\.ssid://p')
        km=$(printf '%s\n' "$fields" | sed -n 's/^802-11-wireless-security\.key-mgmt://p')
        proto=$(printf '%s\n' "$fields" | sed -n 's/^802-11-wireless-security\.proto://p')
        pairwise=$(printf '%s\n' "$fields" | sed -n 's/^802-11-wireless-security\.pairwise://p')
        wep=$(printf '%s\n' "$fields" | sed -n 's/^802-11-wireless-security\.wep-key-type://p')
        auto=$(printf '%s\n' "$fields" | sed -n 's/^connection\.autoconnect://p')
        rating=$(profile_rating "$km" "$proto" "$pairwise" "$wep")
        level=${rating%%|*}
        label=${rating#*|}
        total=$((total + 1))
        [ "$level" = 'Good' ] && good=$((good + 1))
        local auto_tf=false
        [ "$auto" = 'yes' ] && auto_tf=true
        msp_data_row 'SavedProfiles' Profile "$name" SSID "${ssid:-$name}" KeyManagement "${km:-none}" Rating "$level" AutoConnect# "$auto_tf" PasswordSaved 'not checked'
        if [ "$level" = 'Insecure' ] || [ "$level" = 'Weak' ]; then
            if [ "$auto_tf" = 'true' ]; then
                msp_finding --status WARN --severity Medium --category 'Profiles' --check 'Unsafe saved network (auto-connect)' --target "$name" \
                    --id "A3.Profile.$(msp_id_part "$name")" \
                    --detail "\"$name\" ($label) connects automatically. Anyone can create a network with this name and the computer will join it." \
                    --rec "Forget it, or turn off automatic connection: nmcli connection modify \"$name\" connection.autoconnect no (technician action, with client agreement)."
            else
                msp_finding --status WARN --severity Low --category 'Profiles' --check 'Unsafe saved network' --target "$name" \
                    --id "A3.Profile.$(msp_id_part "$name")" \
                    --detail "\"$name\" ($label) is saved (manual connect only)." --rec 'Forget it if no longer needed.'
            fi
        fi
    done <<EOF
$names
EOF
    msp_finding --status INFO --category 'Profiles' --check 'Saved Wi-Fi profiles' \
        --detail "$total saved Wi-Fi connection(s); $good use good security. Passwords were not read."
}
msp_check 'Profiles' 'Saved Wi-Fi profiles' check_saved

if [ "$WIFI_OK" -eq 1 ]; then
    # =====================================================================================
    msp_section 'Nearby networks'
    # =====================================================================================
    check_nearby() {
        local count open=0
        # One row per network name: number of access points, best signal, and every security seen.
        local rows
        rows=$(awk -F'|' '{ n = ($2 == "" ? "(hidden network)" : $2); key = n SUBSEP $4
                if (!(key in seen)) { seen[key] = 1; order[++c] = key; name[key] = n; sec[key] = $4 }
                aps[key]++; if ($7 + 0 > best[key]) best[key] = $7 + 0; ch[key] = ch[key] (index(" " ch[key] " ", " " $5 " ") ? "" : " " $5) }
            END { for (i = 1; i <= c; i++) { k = order[i]; print name[k] "|" sec[k] "|" aps[k] "|" best[k] "|" ch[k] } }' "$SCAN_FILE" | sort -t'|' -k4,4nr)
        if [ -z "$rows" ]; then
            msp_finding --status INFO --category 'Nearby' --check 'Nearby networks' --detail 'No networks in NetworkManager'\''s last scan (Wi-Fi off, or radio disabled).'
            return 0
        fi
        count=0
        printf '  %-32s  %-16s  %-4s  %-6s  %s\n' 'SSID' 'Security' 'APs' 'Signal' 'Rating'
        local name sec aps best chans level
        while IFS='|' read -r name sec aps best chans; do
            [ -n "$name" ] || continue
            level=$(scan_rating "$sec" | cut -d'|' -f1)
            count=$((count + 1))
            [ "$level" = 'Insecure' ] && open=$((open + 1))
            [ "$count" -le 25 ] && printf '  %-32.32s  %-16.16s  %-4s  %-6s  %s\n' "$name" "${sec:-open}" "$aps" "$best%" "$level"
            msp_data_row 'NearbyNetworks' SSID "$name" Security "$sec" Rating "$level" AccessPoints# "$aps" BestSignalPct# "$best" Channels "${chans# }"
        done <<EOF
$rows
EOF
        msp_finding --status INFO --category 'Nearby' --check 'Nearby networks' \
            --detail "$count network(s) in range; $open open/WEP (neighbours' networks are not the client's responsibility)."

        local home=$HOME_SSID
        [ -n "$home" ] || home=$CONNECTED_NAME
        [ -n "$home" ] || return 0
        local same worst='' worst_rank=9 r levels
        same=$(printf '%s\n' "$rows" | awk -F'|' -v h="$home" '$1 == h')
        if [ -z "$same" ]; then
            msp_finding --status INFO --category 'Nearby' --check 'Home network in scan' --detail "\"$home\" was not in NetworkManager's last scan."
            return 0
        fi
        levels=$(printf '%s\n' "$same" | while IFS='|' read -r name sec aps best chans; do scan_rating "$sec" | cut -d'|' -f1; done | sort -u)
        while IFS='|' read -r name sec aps best chans; do
            r=$(rank "$(scan_rating "$sec" | cut -d'|' -f1)")
            if [ "$r" -lt "$worst_rank" ]; then worst_rank=$r; worst=${sec:-open}; fi
        done <<EOF
$same
EOF
        if [ -n "$HOME_SSID" ] && [ -z "$CONNECTED_LEVEL" ]; then
            local status='PASS' sev='Info' advice=''
            case "$worst_rank" in
                0) status='FAIL'; sev='Critical'; advice='Switch the router to WPA2-AES or WPA3 with a long passphrase.' ;;
                1) status='FAIL'; sev='High'; advice='Switch the router to WPA2-AES (not TKIP) or WPA3.' ;;
            esac
            msp_finding --status "$status" --severity "$sev" --category 'Nearby' --check 'Home Wi-Fi security (from scan)' --target "$home" \
                --detail "\"$home\": $worst" --rec "$advice"
        fi
        if [ "$(printf '%s\n' "$levels" | grep -c .)" -gt 1 ]; then
            msp_finding --status WARN --severity High --category 'Nearby' --check 'Same network name, different security' --target "$home" \
                --detail "Networks named \"$home\" are broadcasting with different security ($(printf '%s\n' "$same" | cut -d'|' -f2 | sed 's/^$/open/' | paste -sd ';' - | sed 's/;/; /g')). This can be a misconfigured extra access point or an impersonating (\"evil twin\") network." \
                --rec 'Check every router/extender/mesh unit uses the same WPA2/WPA3 settings. If one cannot be explained, escalate.'
        fi
    }
    msp_check 'Nearby' 'Nearby networks' check_nearby
fi

msp_complete "$OUTPUT"
exit 0
