#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2329  # The embedded helper defines globals and functions this script does not use; checks run through msp_check.
# get-wifi-security-audit-macos.sh - read-only Wi-Fi security audit of a Mac: the network it is
# on, saved networks and nearby networks, flagging open, WEP and WPA (v1) security. Wi-Fi
# passwords are never read.
#
# Usage:  bash get-wifi-security-audit-macos.sh [--home-ssid NAME] [--output DIR] [--help]
#         sudo bash get-wifi-security-audit-macos.sh ...   (adds the security of saved networks)
#
# Options:
#   --home-ssid NAME  Name of the client's home Wi-Fi, so it is rated from the nearby scan when
#                     the Mac is wired or elsewhere, and checked for look-alike networks.
#   --output DIR      Also save results as JSON and CSV (toolkit schema 2.0).
#   --help            Show this help.
#
# Sources (all local; nothing is sent on the network and no Wi-Fi scan is started):
#   Current connection  system_profiler SPAirPortDataType: security, PHY mode, channel, signal
#   Saved networks      networksetup -listpreferredwirelessnetworks (names); with sudo, the
#                       security type and auto-join setting of each from
#                       /Library/Preferences/com.apple.wifi.known-networks.plist. Passwords are
#                       in the keychain and are never touched.
#   Nearby networks     system_profiler's list of other networks in range (macOS's last scan)
#
# Ratings: WPA3, WPA2, WPA2/WPA3, Enhanced Open (OWE) = good. WPA (v1) or WPA/WPA2 mixed = weak.
# WEP or no security = insecure.
#
# macOS hides Wi-Fi NAMES from apps without Location Services permission (shown as <redacted>).
# Security types are still shown, so ratings work; matching by name (home network, look-alike
# networks) is SKIPPED with instructions. This script never changes the setting.
#
# Examples:
#   bash get-wifi-security-audit-macos.sh
#   sudo bash get-wifi-security-audit-macos.sh --home-ssid "Smith-Home" --output ~/Desktop/Audit
#
# Purpose       : Confirm the home Wi-Fi is encrypted properly and the Mac won't auto-join unsafe networks.
# Use Case      : Home network security audits; travelling users; "slow/unsafe Wi-Fi" tickets.
# Scope         : This Mac's Wi-Fi interface and saved networks; nearby networks from macOS's last scan.
# Risk Level    : Read-Only -- reads Wi-Fi status only. Never reads Wi-Fi passwords; changes nothing.
# Prerequisites : macOS 12+ | bash 3.2+ | root: No (sudo adds saved-network security)
# Version       : 1.0.0
# Limitations   : macOS does not show the cipher (TKIP vs AES), so WPA2-TKIP cannot be told
#                 apart from WPA2-AES. Router-side settings (WPS, guest isolation) are checked by
#                 the A7 router script. Same check names and IDs as Get-WiFiSecurityAudit.ps1.
#                 MSP_TEST_ROOT (development tests only) prefixes the files read.

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
if [ "$(uname -s)" != 'Darwin' ]; then
    printf 'This script is for macOS. On Linux use get-wifi-security-audit-linux.sh.\n' >&2
    exit 2
fi

[ -n "$OUTPUT" ] && msp_param Output "$OUTPUT"
[ -n "$HOME_SSID" ] && msp_param HomeSsid "$HOME_SSID"
msp_init 'get-wifi-security-audit-macos' "$SCRIPT_VERSION" 'A3' 'Read-Only' \
    'Wi-Fi security audit (read-only; passwords are never read)' 'security of saved networks'

ROOT=${MSP_TEST_ROOT:-}
KNOWN_PLIST="$ROOT/Library/Preferences/com.apple.wifi.known-networks.plist"
LOCATION_ADVICE='macOS hides Wi-Fi names unless the app has Location Services permission. With the client'\''s agreement: System Settings > Privacy & Security > Location Services > turn on for Terminal, re-run, then turn it off again.'

wifi_rating() {
    # wifi_rating SECURITY_TEXT -> "Level|Label" (Level: Good, Weak, Insecure, Unknown).
    case "$1" in
        '') printf 'Unknown|Unknown security' ;;
        *OWE* | *'Enhanced Open'*) printf 'Good|Enhanced Open (encrypted, no password)' ;;
        None | Open | none | open) printf 'Insecure|Open (no encryption)' ;;
        *WEP*) printf 'Insecure|WEP (crackable in minutes)' ;;
        *WPA3* | *WPA2*)
            case "$1" in
                *'WPA/WPA2'* | *'WPA1'*) printf 'Weak|%s (allows original WPA, outdated)' "$1" ;;
                *) printf 'Good|%s' "$1" ;;
            esac
            ;;
        *WPA*) printf 'Weak|%s (original WPA, outdated)' "$1" ;;
        *) printf 'Unknown|%s' "$1" ;;
    esac
}

rank() {
    case "$1" in Insecure) printf 0 ;; Weak) printf 1 ;; Unknown) printf 2 ;; *) printf 3 ;; esac
}

# =========================================================================================
msp_section 'Wi-Fi adapter'
# =========================================================================================
WIFI_DEV=''
WIFI_OK=0
SP_FILE="${MSP_WORK_DIR:-${TMPDIR:-/tmp}}/airport.txt"
check_adapter() {
    WIFI_DEV=$(networksetup -listallhardwareports 2>/dev/null | awk '/^Hardware Port: (Wi-Fi|AirPort)$/ { getline; print $2; exit }')
    if [ -z "$WIFI_DEV" ]; then
        msp_finding --status INFO --category 'Adapter' --check 'Wi-Fi adapter' --detail 'This Mac has no Wi-Fi interface. Wi-Fi checks do not apply.'
        return 0
    fi
    local power
    power=$(networksetup -getairportpower "$WIFI_DEV" 2>/dev/null)
    # One system_profiler call (a few seconds) feeds the connection and nearby-network checks.
    system_profiler SPAirPortDataType >"$SP_FILE" 2>/dev/null
    WIFI_OK=1
    case "$power" in
        *': On'*) msp_finding --status INFO --category 'Adapter' --check 'Wi-Fi adapter' --detail "$WIFI_DEV (Wi-Fi on)" ;;
        *) msp_finding --status INFO --category 'Adapter' --check 'Wi-Fi adapter' --detail "$WIFI_DEV (Wi-Fi off). Only saved networks can be checked." ;;
    esac
}
msp_check 'Adapter' 'Wi-Fi adapter' check_adapter

sp_networks() {
    # sp_networks SECTION -> "name|security|channel|phy|signal" for each network under
    # "Current Network Information:" or "Other Local Wi-Fi Networks:" of the Wi-Fi interface.
    awk -v want="$1" -v dev="$WIFI_DEV:" '
        function flush() { if (name != "") print name "|" sec "|" chan "|" phy "|" sig; name = ""; sec = ""; chan = ""; phy = ""; sig = "" }
        { line = $0; sub(/^ +/, "", line); ind = length($0) - length(line) }
        line == dev { indev = 1; next }
        indev && ind <= 8 && line ~ /:$/ && line != dev { flush(); indev = 0; insec = 0; next }
        !indev { next }
        line == want ":" { flush(); insec = 1; secind = ind; next }
        insec && ind <= secind { flush(); insec = 0 }
        !insec { next }
        line ~ /:$/ && ind == secind + 2 { flush(); name = substr(line, 1, length(line) - 1); next }
        name != "" && line ~ /^Security: / { sec = substr(line, 11) }
        name != "" && line ~ /^Channel: / { chan = substr(line, 10) }
        name != "" && line ~ /^PHY Mode: / { phy = substr(line, 11) }
        name != "" && line ~ /^Signal \/ Noise: / { sig = substr(line, 17) }
        END { flush() }
    ' "$SP_FILE"
}

CONNECTED_NAME=''
CONNECTED_LEVEL=''
if [ "$WIFI_OK" -eq 1 ]; then
    # =====================================================================================
    msp_section 'Current connection'
    # =====================================================================================
    check_current() {
        local row name sec chan phy sig rating level label
        row=$(sp_networks 'Current Network Information' | head -n 1)
        if [ -z "$row" ] || ! grep -q 'Status: Connected' "$SP_FILE"; then
            local detail='This Mac is not connected to Wi-Fi.'
            if [ -n "$HOME_SSID" ]; then detail="$detail The home network \"$HOME_SSID\" is rated from the nearby scan below."
            else detail="$detail Use --home-ssid \"<name>\" to rate the home network from the nearby scan."; fi
            msp_finding --status INFO --category 'Connection' --check 'Current Wi-Fi connection' --detail "$detail"
            return 0
        fi
        IFS='|' read -r name sec chan phy sig <<EOF
$row
EOF
        rating=$(wifi_rating "$sec")
        level=${rating%%|*}
        label=${rating#*|}
        CONNECTED_LEVEL=$level
        local shown="\"$name\""
        if [ "$name" = '<redacted>' ]; then
            shown='(name hidden by macOS)'
        else
            CONNECTED_NAME=$name
        fi
        local where="$shown ($phy, channel $chan, signal $sig)"
        local ev
        ev=$(msp_json_obj SSID "$name" Security "$sec" Channel "$chan" PhyMode "$phy" Signal "$sig")
        case "$level" in
            Good)
                msp_finding --status PASS --category 'Connection' --check 'Current Wi-Fi security' --evidence "$ev" --detail "$where: $label"
                case "$sec" in *WPA3*) ;; *)
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
        if [ "$name" = '<redacted>' ]; then
            msp_finding --status INFO --category 'Connection' --check 'Network name' --detail "macOS hid the network name; the rating above is still valid." --rec "$LOCATION_ADVICE"
        fi
    }
    msp_check 'Connection' 'Current Wi-Fi connection' check_current
fi

# =========================================================================================
msp_section 'Saved Wi-Fi networks'
# =========================================================================================
check_saved() {
    local names count=0
    if [ -n "$WIFI_DEV" ]; then
        names=$(networksetup -listpreferredwirelessnetworks "$WIFI_DEV" 2>/dev/null | sed -n 's/^[[:space:]]\{1,\}//p')
        [ -n "$names" ] && count=$(printf '%s\n' "$names" | grep -c .)
    fi
    if [ "$count" -eq 0 ]; then
        msp_finding --status INFO --category 'Profiles' --check 'Saved Wi-Fi profiles' --detail 'No saved Wi-Fi networks.'
        return 0
    fi
    if ! msp_is_root; then
        msp_finding --status INFO --category 'Profiles' --check 'Saved Wi-Fi profiles' \
            --detail "$count saved network(s). Their security types are only readable with sudo. Passwords were not read."
        msp_skip 'Profiles' 'Saved network security' 'Skipped: requires root (sudo). macOS keeps the security type of saved networks in a root-only file.' "$(msp_root_hint)"
        return 0
    fi
    [ -r "$KNOWN_PLIST" ] || { printf 'No such file or directory: %s\n' "$KNOWN_PLIST" >&2; return 1; }
    # "wifi.network.ssid.<name>" entries; each holds SupportedSecurityTypes and AutoJoinDisabled.
    # Only those two values are read: passwords are not in this file.
    local rows
    rows=$(plutil -convert xml1 -o - "$KNOWN_PLIST" 2>/dev/null | awk '
        /<dict>/ { depth++ }
        /<\/dict>/ { if (depth == 2 && name != "") { print name "|" sec "|" auto; name = "" } depth-- }
        depth == 1 && /<key>wifi\.network\.ssid\./ { line = $0; sub(/.*<key>wifi\.network\.ssid\./, "", line); sub(/<\/key>.*/, "", line); name = line; sec = ""; auto = "true"; next }
        depth == 2 && /<key>SupportedSecurityTypes<\/key>/ { want = "sec"; next }
        depth == 2 && /<key>AutoJoinDisabled<\/key>/ { want = "auto"; next }
        want == "sec" { line = $0; if (line ~ /<string>/) { sub(/.*<string>/, "", line); sub(/<\/string>.*/, "", line); sec = line } want = ""; next }
        want == "auto" { if ($0 ~ /<true\/>/) auto = "false"; want = ""; next }
    ')
    [ -n "$rows" ] || { printf 'Could not read saved networks from %s\n' "$KNOWN_PLIST" >&2; return 1; }
    local name sec auto rating level label good=0 total=0 shown
    while IFS='|' read -r name sec auto; do
        [ -n "$name" ] || continue
        # Names are XML-escaped in the plist.
        shown=$(printf '%s' "$name" | sed 's/&amp;/\&/g; s/&lt;/</g; s/&gt;/>/g; s/&apos;/'\''/g; s/&quot;/"/g')
        rating=$(wifi_rating "$sec")
        level=${rating%%|*}
        label=${rating#*|}
        total=$((total + 1))
        [ "$level" = 'Good' ] && good=$((good + 1))
        msp_data_row 'SavedProfiles' Profile "$shown" Security "$sec" Rating "$level" AutoConnect# "$auto" PasswordSaved 'not checked'
        if [ "$level" = 'Insecure' ] || [ "$level" = 'Weak' ]; then
            if [ "$auto" = 'true' ]; then
                msp_finding --status WARN --severity Medium --category 'Profiles' --check 'Unsafe saved network (auto-connect)' --target "$shown" \
                    --id "A3.Profile.$(msp_id_part "$shown")" \
                    --detail "\"$shown\" ($label) is joined automatically. Anyone can create a network with this name and the Mac will join it." \
                    --rec 'Forget this network (System Settings > Wi-Fi > ... > Forget), or turn off Auto-Join for it, with the client'\''s agreement.'
            else
                msp_finding --status WARN --severity Low --category 'Profiles' --check 'Unsafe saved network' --target "$shown" \
                    --id "A3.Profile.$(msp_id_part "$shown")" \
                    --detail "\"$shown\" ($label) is saved (auto-join off)." --rec 'Forget it if no longer needed.'
            fi
        fi
    done <<EOF
$rows
EOF
    msp_finding --status INFO --category 'Profiles' --check 'Saved Wi-Fi profiles' \
        --detail "$total saved network(s); $good use good security. Passwords were not read."
}
msp_check 'Profiles' 'Saved Wi-Fi profiles' check_saved

if [ "$WIFI_OK" -eq 1 ]; then
    # =====================================================================================
    msp_section 'Nearby networks'
    # =====================================================================================
    check_nearby() {
        local rows count=0 open=0 redacted=0 name sec chan phy sig rating level
        rows=$(sp_networks 'Other Local Wi-Fi Networks')
        if [ -z "$rows" ]; then
            msp_finding --status INFO --category 'Nearby' --check 'Nearby networks' --detail 'No other networks in macOS'\''s last scan (Wi-Fi off, or none in range).'
            return 0
        fi
        printf '  %-32s  %-24s  %-22s  %s\n' 'SSID' 'Security' 'Channel' 'Rating'
        while IFS='|' read -r name sec chan phy sig; do
            [ -n "$name" ] || continue
            rating=$(wifi_rating "$sec")
            level=${rating%%|*}
            count=$((count + 1))
            [ "$level" = 'Insecure' ] && open=$((open + 1))
            [ "$name" = '<redacted>' ] && redacted=$((redacted + 1))
            [ "$count" -le 25 ] && printf '  %-32.32s  %-24.24s  %-22.22s  %s\n' "$name" "$sec" "$chan" "$level"
            msp_data_row 'NearbyNetworks' SSID "$name" Security "$sec" Rating "$level" Channel "$chan" PhyMode "$phy"
        done <<EOF
$rows
EOF
        msp_finding --status INFO --category 'Nearby' --check 'Nearby networks' \
            --detail "$count network(s) in range; $open open/WEP (neighbours' networks are not the client's responsibility)."

        local home=$HOME_SSID
        [ -n "$home" ] || home=$CONNECTED_NAME
        if [ -z "$home" ]; then return 0; fi
        if [ "$redacted" -gt 0 ]; then
            msp_skip 'Nearby' 'Home network in scan' 'Skipped: macOS hid the names of nearby networks, so the home network and look-alikes cannot be matched by name.' "$LOCATION_ADVICE"
            return 0
        fi
        local same levels worst='' worst_rank=9 r
        same=$(printf '%s\n' "$rows" | awk -F'|' -v h="$home" '$1 == h')
        # The connected network itself is not in "other" networks; count it for the comparison.
        if [ -n "$CONNECTED_LEVEL" ] && [ "$home" = "$CONNECTED_NAME" ]; then
            same=$(printf '%s\n%s' "$(sp_networks 'Current Network Information' | head -n 1)" "$same")
        fi
        if [ -z "$(printf '%s' "$same" | tr -d '\n')" ]; then
            msp_finding --status INFO --category 'Nearby' --check 'Home network in scan' --detail "\"$home\" was not in macOS's last scan."
            return 0
        fi
        levels=$(printf '%s\n' "$same" | while IFS='|' read -r name sec chan phy sig; do [ -n "$name" ] && wifi_rating "$sec" | cut -d'|' -f1; done | sort -u)
        while IFS='|' read -r name sec chan phy sig; do
            [ -n "$name" ] || continue
            r=$(rank "$(wifi_rating "$sec" | cut -d'|' -f1)")
            if [ "$r" -lt "$worst_rank" ]; then worst_rank=$r; worst=$sec; fi
        done <<EOF
$same
EOF
        if [ -n "$HOME_SSID" ] && [ -z "$CONNECTED_LEVEL" ]; then
            local status='PASS' sev='Info' advice=''
            case "$worst_rank" in
                0) status='FAIL'; sev='Critical'; advice='Switch the router to WPA2-AES or WPA3 with a long passphrase.' ;;
                1) status='FAIL'; sev='High'; advice='Switch the router to WPA2 or WPA3 only (no WPA/TKIP).' ;;
            esac
            msp_finding --status "$status" --severity "$sev" --category 'Nearby' --check 'Home Wi-Fi security (from scan)' --target "$home" \
                --detail "\"$home\": $worst" --rec "$advice"
        fi
        if [ "$(printf '%s\n' "$levels" | grep -c .)" -gt 1 ]; then
            msp_finding --status WARN --severity High --category 'Nearby' --check 'Same network name, different security' --target "$home" \
                --detail "Networks named \"$home\" are broadcasting with different security ($(printf '%s\n' "$same" | cut -d'|' -f2 | paste -sd ';' - | sed 's/;/; /g')). This can be a misconfigured extra access point or an impersonating (\"evil twin\") network." \
                --rec 'Check every router/extender/mesh unit uses the same WPA2/WPA3 settings. If one cannot be explained, escalate.'
        fi
    }
    msp_check 'Nearby' 'Nearby networks' check_nearby
fi

msp_complete "$OUTPUT"
exit 0
