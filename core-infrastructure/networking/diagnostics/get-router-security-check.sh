#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2329  # The embedded helper defines globals and functions this script does not use; checks run through msp_check.
# get-router-security-check.sh - read-only home router check for macOS and Linux: gateway, DNS
# servers in use, whether the admin page uses HTTP or HTTPS, management ports, UPnP (and any
# port forwards it has opened), then a guided checklist for the settings only the router's
# admin page can show. Never logs in or guesses passwords. The Windows version is
# Get-RouterSecurityCheck.ps1 (same checks and finding IDs).
#
# Usage:  bash get-router-security-check.sh [--skip-checklist-prompt] [--expected-dns IP[,IP...]]
#                                           [--ssdp-wait N] [--output DIR]
#
# Options:
#   --skip-checklist-prompt  Do not ask the checklist questions; record them as "Not verified".
#   --expected-dns IP,...    DNS servers the client uses on purpose (for example a filtering
#                            service), so they are not flagged as unrecognised.
#   --ssdp-wait N            Seconds to listen for UPnP answers (1-10, default 3).
#   --output DIR             Also save results as JSON and CSV (toolkit schema 2.0), with
#                            AdminPage, UpnpDevices and UpnpPortForwards tables.
#   --help                   Show this help.
#
# Automatic checks (the scope is printed before anything is sent):
#   Gateway      The router of the adapter with the default route (never a VPN: SKIPPED then).
#   DNS          DNS servers in use; local, well-known public resolvers are fine; unrecognised
#                public servers are flagged for confirmation. DNS set by hand is noted.
#   Admin page   GET "/" on the router over HTTP (80, 8080) and HTTPS (443, 8443), WITHOUT
#                credentials, redirects not followed except once to an HTTPS address inside
#                the local subnet. Needs curl (or wget for HTTP only).
#   Management   Whether the router accepts Telnet (23), FTP (21) or SSH (22) connections.
#   UPnP         One SSDP discovery (UDP multicast 239.255.255.250:1900, TTL 1, so it never
#                leaves the local network; needs perl, which macOS and Debian/Ubuntu include).
#                If the router answers as an Internet Gateway Device, it is asked - read-only -
#                for its external IP and the port forwards UPnP has opened.
# Guided checklist (interactive): admin password changed, remote management off, WPS off,
#   firmware current, UPnP off, guest isolation. Answer Y/N/U with the client. Without a
#   terminal (RMM, pipes) or with --skip-checklist-prompt, items are "Not verified".
#
# Examples:
#   bash get-router-security-check.sh
#   bash get-router-security-check.sh --skip-checklist-prompt --output ~/Desktop/Audit
#
# Purpose       : Find the router settings that most often leave a home network exposed.
# Use Case      : Home network security audits; new router installs; "is my router safe?"
# Scope         : The default gateway only (TCP 21, 22, 23, 80, 443, 8080, 8443), plus one SSDP
#                 multicast on the local network.
# Risk Level    : Read-Only -- unauthenticated GET requests and read-only UPnP queries
#                 (GetExternalIPAddress, GetGenericPortMappingEntry). No logins, no password
#                 guessing, no settings changed.
# Prerequisites : macOS 12+ or Linux | bash 3.2+ | root: No | curl; perl for UPnP
# Version       : 1.0.0
# Limitations   : Cannot see settings behind the admin login (the checklist covers them).
#                 Routers managed only by an app may have no admin page. A router can have UPnP
#                 on but not answer SSDP. Cannot test what is reachable from the internet.

set -u
MSP_SCRIPT_FILE=$0

#region MSPToolkit (generated) Sections=Core,Net
# DO NOT EDIT — regenerate with Sync-MSPEmbeddedHelper.ps1
# Source: endpoint-systems/utilities/msp-toolkit-common.sh | Sections: Core,Net | SHA256: 5e0794b5a477128e5ac2c0279ed4ee3cb4ba5189b4d07b1b1c2f0aa4d4a630b2
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

#region MSPHelper:Net
# --- Local subnet -----------------------------------------------------------------------------
# msp_local_subnet fills these. Only the adapter that carries the default route is used, and
# never a VPN or virtual adapter, so scans stay on the client's real LAN.
MSP_NET_IFACE=''
MSP_NET_IP=''
MSP_NET_PREFIX=''
MSP_NET_CIDR=''
MSP_NET_NETWORK=''
MSP_NET_BROADCAST=''
MSP_NET_NETWORK_INT=0
MSP_NET_BROADCAST_INT=0
MSP_NET_HOSTCOUNT=0
MSP_NET_GATEWAY=''
MSP_NET_MAC=''
MSP_NET_ERROR=''
MSP_NET_SKIP=0

msp_ip_to_int() {
    # Dotted IPv4 -> integer (bash arithmetic is 64-bit). Returns 1 for anything not a valid IPv4.
    local ip=$1 a b c d rest o
    case "$ip" in *[!0-9.]* | '') return 1 ;; esac
    case "$ip" in *.*.*.*) ;; *) return 1 ;; esac
    a=${ip%%.*}
    rest=${ip#*.}
    b=${rest%%.*}
    rest=${rest#*.}
    c=${rest%%.*}
    d=${rest#*.}
    case "$d" in *.*) return 1 ;; esac
    for o in "$a" "$b" "$c" "$d"; do
        case "$o" in '' | ????*) return 1 ;; esac
        # 10# forces decimal: "08" would otherwise be read as an invalid octal number.
        [ $((10#$o)) -le 255 ] || return 1
    done
    printf '%s' $(((10#$a << 24) + (10#$b << 16) + (10#$c << 8) + 10#$d))
}

msp_int_to_ip() {
    local n=$1
    printf '%s.%s.%s.%s' $(((n >> 24) & 255)) $(((n >> 16) & 255)) $(((n >> 8) & 255)) $((n & 255))
}

msp_mask_to_prefix() {
    # 255.255.255.0 or 0xffffff00 (macOS ifconfig) -> 24
    local m=$1 n bits=0
    case "$m" in
        0x* | 0X*) n=$((m)) ;;
        *) n=$(msp_ip_to_int "$m") || return 1 ;;
    esac
    while [ "$n" -gt 0 ]; do
        bits=$((bits + (n & 1)))
        n=$((n >> 1))
    done
    printf '%s' "$bits"
}

msp_is_virtual_iface() {
    # VPN, tunnel, container, VM and Apple-internal interface names.
    case "$1" in
        utun* | tun* | tap* | ppp* | ipsec* | wg* | gif* | stf* | awdl* | llw* | anpi* | ap[0-9]* | \
            bridge* | vmnet* | vboxnet* | docker* | br-* | veth* | virbr* | tailscale* | zt* | lo* | \
            nordlynx* | proton* | cscotun* | gpd* | vti*) return 0 ;;
    esac
    return 1
}

msp__default_routes() {
    # Prints "metric interface gateway" for each IPv4 default route with a real gateway address.
    if [ "$MSP_PLATFORM" = 'macOS' ]; then
        # netstat lists every default route, unlike "route get default" (which shows only the
        # primary one - a full-tunnel VPN would hide the Wi-Fi route).
        netstat -rn -f inet 2>/dev/null | awk '$1 == "default" && $2 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ { print NR, $NF, $2 }'
    elif msp_have ip; then
        ip -4 route show default 2>/dev/null | awk '{
            gw = ""; dev = ""; metric = 0
            for (i = 1; i < NF; i++) {
                if ($i == "via") gw = $(i + 1)
                if ($i == "dev") dev = $(i + 1)
                if ($i == "metric") metric = $(i + 1)
            }
            if (gw != "" && dev != "") print metric, dev, gw
        }'
    else
        return 1
    fi
}

msp__iface_ipv4() {
    # Prints "address prefix" for the first non-link-local IPv4 address of an interface.
    local iface=$1
    if [ "$MSP_PLATFORM" = 'macOS' ]; then
        ifconfig "$iface" 2>/dev/null | awk '$1 == "inet" && $2 !~ /^169\.254\./ { print $2, $4; exit }' |
            while read -r addr mask; do printf '%s %s\n' "$addr" "$(msp_mask_to_prefix "$mask")"; done
    else
        ip -4 -o addr show dev "$iface" 2>/dev/null | awk '{
            for (i = 1; i < NF; i++) if ($i == "inet" && $(i + 1) !~ /^169\.254\./) {
                split($(i + 1), a, "/"); print a[1], a[2]; exit
            }
        }'
    fi
}

msp_local_subnet() {
    # Finds the active adapter's IPv4 subnet. Returns 0 and sets MSP_NET_*; or returns 1 with
    # MSP_NET_ERROR set. MSP_NET_SKIP=1 means "expected, report as SKIPPED" (only a VPN or
    # virtual adapter has a gateway, so nothing is scanned rather than scanning the VPN).
    MSP_NET_ERROR=''
    MSP_NET_SKIP=0
    local routes line metric iface gw pick_iface='' pick_gw='' pick_metric='' virtual_list='' addr prefix
    if ! routes=$(msp__default_routes) || [ -z "$routes" ]; then
        if [ "$MSP_PLATFORM" = 'Linux' ] && ! msp_have ip; then
            MSP_NET_ERROR="The 'ip' command is not available, so the local network could not be identified."
        else
            MSP_NET_ERROR='No IPv4 default gateway was found. The computer does not appear to be connected to a network.'
        fi
        return 1
    fi
    while read -r metric iface gw; do
        [ -n "$iface" ] || continue
        if msp_is_virtual_iface "$iface"; then
            virtual_list="$virtual_list${virtual_list:+, }$iface"
            continue
        fi
        if [ -z "$pick_iface" ] || [ "$metric" -lt "$pick_metric" ]; then
            pick_iface=$iface
            pick_gw=$gw
            pick_metric=$metric
        fi
    done <<EOF
$routes
EOF
    if [ -z "$pick_iface" ]; then
        MSP_NET_SKIP=1
        MSP_NET_ERROR="Only a VPN or virtual adapter has a default gateway ($virtual_list). Nothing was scanned, so no traffic went over the VPN."
        return 1
    fi
    read -r addr prefix <<EOF
$(msp__iface_ipv4 "$pick_iface")
EOF
    if [ -z "${addr:-}" ] || [ -z "${prefix:-}" ] || [ "$prefix" -lt 1 ] || [ "$prefix" -gt 30 ]; then
        MSP_NET_ERROR="Adapter $pick_iface has no usable IPv4 address."
        return 1
    fi
    local ipn mask
    ipn=$(msp_ip_to_int "$addr") || {
        MSP_NET_ERROR="Adapter $pick_iface reported an address that is not IPv4 ($addr)."
        return 1
    }
    mask=$(((0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF))
    MSP_NET_IFACE=$pick_iface
    MSP_NET_IP=$addr
    MSP_NET_PREFIX=$prefix
    MSP_NET_GATEWAY=$pick_gw
    MSP_NET_NETWORK_INT=$((ipn & mask))
    MSP_NET_BROADCAST_INT=$((MSP_NET_NETWORK_INT + (1 << (32 - prefix)) - 1))
    MSP_NET_NETWORK=$(msp_int_to_ip "$MSP_NET_NETWORK_INT")
    MSP_NET_BROADCAST=$(msp_int_to_ip "$MSP_NET_BROADCAST_INT")
    MSP_NET_CIDR="$MSP_NET_NETWORK/$prefix"
    MSP_NET_HOSTCOUNT=$(((1 << (32 - prefix)) - 2))
    [ "$MSP_NET_HOSTCOUNT" -ge 0 ] || MSP_NET_HOSTCOUNT=0
    MSP_NET_MAC=''
    if [ "$MSP_PLATFORM" = 'macOS' ]; then
        MSP_NET_MAC=$(ifconfig "$pick_iface" 2>/dev/null | awk '$1 == "ether" { print toupper($2); exit }')
    elif [ -r "/sys/class/net/$pick_iface/address" ]; then
        MSP_NET_MAC=$(tr 'abcdef' 'ABCDEF' <"/sys/class/net/$pick_iface/address")
    fi
    return 0
}

msp_ip_in_subnet() {
    # True when an IPv4 address is a usable host address inside the detected subnet.
    local n
    n=$(msp_ip_to_int "$1") || return 1
    [ "$n" -gt "$MSP_NET_NETWORK_INT" ] && [ "$n" -lt "$MSP_NET_BROADCAST_INT" ]
}

msp_subnet_hosts() {
    # Every usable host address in the detected subnet, one per line.
    local n=$((MSP_NET_NETWORK_INT + 1))
    while [ "$n" -lt "$MSP_NET_BROADCAST_INT" ]; do
        msp_int_to_ip "$n"
        printf '\n'
        n=$((n + 1))
    done
}

msp_dns_servers() {
    # DNS servers this computer is using, one per line.
    if [ "$MSP_PLATFORM" = 'macOS' ]; then
        scutil --dns 2>/dev/null | awk '/nameserver\[[0-9]+\]/ { print $3 }' | awk '!seen[$0]++'
        return 0
    fi
    local servers=''
    if msp_have resolvectl; then
        # systemd-resolved: /etc/resolv.conf only shows the local stub (127.0.0.53).
        servers=$(resolvectl dns 2>/dev/null | sed 's/^[^:]*://' | tr ' ' '\n' | grep -E '^[0-9a-fA-F:.]+$' | awk '!seen[$0]++')
    fi
    if [ -z "$servers" ]; then
        servers=$(awk '$1 == "nameserver" { print $2 }' /etc/resolv.conf 2>/dev/null)
    fi
    [ -n "$servers" ] && printf '%s\n' "$servers"
    return 0
}

msp_normalize_mac() {
    # "0:1a:2b:3:4:5" (macOS arp) or "00-1a-..." -> "00:1A:2B:03:04:05"
    printf '%s' "$1" | tr '-' ':' | awk -F: 'NF == 6 {
        out = ""
        for (i = 1; i <= 6; i++) { o = $i; if (length(o) == 1) o = "0" o; out = out (i > 1 ? ":" : "") toupper(o) }
        print out
    }'
}

msp_mac_is_randomized() {
    # Locally administered MAC (second hex digit 2, 6, A or E): phones and laptops use these
    # for privacy, so they are labeled "Private/randomized MAC", not "unknown".
    case "$1" in
        ?[26AEae]:*) return 0 ;;
    esac
    return 1
}

msp_neighbors() {
    # Neighbor (ARP) table for the detected subnet: "IP MAC" per line, MACs normalized.
    local ip mac
    {
        if [ "$MSP_PLATFORM" = 'Linux' ] && msp_have ip; then
            ip -4 neigh show dev "$MSP_NET_IFACE" 2>/dev/null | awk '$0 ~ /lladdr/ && $NF != "FAILED" && $NF != "INCOMPLETE" {
                for (i = 1; i < NF; i++) if ($i == "lladdr") print $1, $(i + 1)
            }'
        elif msp_have arp; then
            arp -an 2>/dev/null | awk '{ ip = $2; gsub(/[()]/, "", ip); if ($4 ~ /:/) print ip, $4 }'
        fi
    } | while read -r ip mac; do
        msp_ip_in_subnet "$ip" || continue
        mac=$(msp_normalize_mac "$mac")
        [ -n "$mac" ] && [ "$mac" != 'FF:FF:FF:FF:FF:FF' ] && printf '%s %s\n' "$ip" "$mac"
    done
}

# --- Probes ---------------------------------------------------------------------------------
msp_ping() {
    # Prints the address when it answers one ping within about 1 second.
    if [ "$MSP_PLATFORM" = 'macOS' ]; then
        ping -c 1 -t 1 "$1" >/dev/null 2>&1 && printf '%s\n' "$1"
    else
        ping -c 1 -W 1 "$1" >/dev/null 2>&1 && printf '%s\n' "$1"
    fi
    return 0
}

msp_tcp_open() {
    # msp_tcp_open IP PORT - true when a TCP connection succeeds within about 1 second. The
    # connection is closed immediately; nothing is sent.
    if msp_have nc; then
        if [ "$MSP_PLATFORM" = 'macOS' ]; then
            nc -z -G 1 -w 1 "$1" "$2" >/dev/null 2>&1
        else
            msp_run_timeout 2 nc -z -w 1 "$1" "$2" >/dev/null 2>&1
        fi
        return $?
    fi
    # Fallback: bash's built-in /dev/tcp, stopped after 1 second.
    # shellcheck disable=SC2016  # $1/$2 must expand in the child bash (passed as arguments), not here.
    msp_run_timeout 1 bash -c 'exec 3<>"/dev/tcp/$1/$2"' _ "$1" "$2" >/dev/null 2>&1
}

msp_parallel() {
    # msp_parallel MAX OUT_DIR FUNCTION - runs FUNCTION once per line of stdin, at most MAX at a
    # time (never more than 32), each writing its output to OUT_DIR/<n>.out. Waits for all.
    # bash 3.2 has no "wait -n", so it waits for the oldest job when the limit is reached;
    # that can briefly run fewer than MAX jobs, never more.
    local max=$1 outdir=$2 func=$3 item n=0 first=0 running=0
    local pids=()
    [ "$max" -gt 32 ] && max=32
    [ "$max" -lt 1 ] && max=1
    while IFS= read -r item; do
        [ -n "$item" ] || continue
        "$func" "$item" >"$outdir/$n.out" 2>/dev/null </dev/null &
        pids[n]=$!
        n=$((n + 1))
        running=$((running + 1))
        if [ "$running" -ge "$max" ]; then
            wait "${pids[$first]}" 2>/dev/null
            first=$((first + 1))
            running=$((running - 1))
        fi
    done
    while [ "$first" -lt "$n" ]; do
        wait "${pids[$first]}" 2>/dev/null
        first=$((first + 1))
    done
}
# --- Listening sockets ----------------------------------------------------------------------
msp_listening_tcp() {
    # Listening TCP sockets of this computer, one "port|address|pid|process" per line (IPv4 and
    # IPv6 rows are listed separately). Reads the local socket table only; sends nothing.
    # macOS: netstat -anv shows the owning process of every socket without root.
    # Linux: ss shows the process only for the current user's sockets unless run as root.
    local procs
    procs=$(ps -axo pid=,comm= 2>/dev/null)
    {
        if [ "$MSP_PLATFORM" = 'macOS' ]; then
            netstat -anv -p tcp 2>/dev/null | awk '$1 ~ /^tcp/ && $6 == "LISTEN" {
                n = split($4, parts, "."); port = parts[n]; addr = substr($4, 1, length($4) - length(port) - 1)
                pid = ""
                # macOS 13+: "process:pid" after the buffer sizes (the name may contain spaces).
                for (i = 11; i <= NF; i++) if ($i ~ /:[0-9]+$/) { pid = $i; sub(/.*:/, "", pid); break }
                # Older macOS: a numeric pid column.
                if (pid == "" && $9 ~ /^[0-9]+$/) pid = $9
                print port "|" addr "|" pid
            }'
        elif msp_have ss; then
            ss -ltnp 2>/dev/null | awk '$1 == "LISTEN" {
                local_ = $4; n = split(local_, parts, ":"); port = parts[n]
                addr = substr(local_, 1, length(local_) - length(port) - 1)
                gsub(/[][]/, "", addr); sub(/%.*/, "", addr)
                pid = ""
                if (match($0, /pid=[0-9]+/)) pid = substr($0, RSTART + 4, RLENGTH - 4)
                print port "|" addr "|" pid
            }'
        elif msp_have netstat; then
            netstat -ltn 2>/dev/null | awk '$1 ~ /^tcp/ && $NF == "LISTEN" {
                n = split($4, parts, ":"); port = parts[n]; addr = substr($4, 1, length($4) - length(port) - 1)
                print port "|" addr "|"
            }'
        else
            return 1
        fi
    } | while IFS='|' read -r port addr pid; do
        [ -n "$port" ] || continue
        name=''
        if [ -n "$pid" ]; then
            name=$(printf '%s\n' "$procs" | awk -v p="$pid" '$1 == p { $1 = ""; sub(/^ /, ""); print; exit }')
            name=${name##*/}
        fi
        printf '%s|%s|%s|%s\n' "$port" "$addr" "$pid" "$name"
    done
}

msp_is_loopback() {
    # True for 127.x.x.x, ::1 and localhost-only bindings.
    case "$1" in 127.* | ::1 | localhost) return 0 ;; esac
    return 1
}

# --- MAC vendor hint ------------------------------------------------------------------------
# Same table as $script:MSPOuiData in MSPToolkit.Common.psm1 (OUI = first 3 bytes; curated
# common home/SMB vendors only). tests/Invoke-ToolkitTests.ps1 checks that both give the same
# answer for every entry. Vendor is a HINT, never proof: unknown here does not mean suspicious.
# No internet lookups are made. Format: OUI|Vendor|Device hint
msp__oui_data() {
    cat <<'MSP_OUI'
00:50:56|VMware|Virtual machine
00:0C:29|VMware|Virtual machine
00:05:69|VMware|Virtual machine
08:00:27|Oracle VirtualBox|Virtual machine
00:15:5D|Microsoft Hyper-V|Virtual machine
52:54:00|QEMU/KVM|Virtual machine
B8:27:EB|Raspberry Pi|Single-board computer
DC:A6:32|Raspberry Pi|Single-board computer
E4:5F:01|Raspberry Pi|Single-board computer
D8:3A:DD|Raspberry Pi|Single-board computer
2C:CF:67|Raspberry Pi|Single-board computer
00:03:93|Apple|Apple device
00:0A:95|Apple|Apple device
00:17:F2|Apple|Apple device
00:1B:63|Apple|Apple device
00:1E:C2|Apple|Apple device
00:25:00|Apple|Apple device
28:CF:E9|Apple|Apple device
3C:07:54|Apple|Apple device
40:6C:8F|Apple|Apple device
7C:D1:C3|Apple|Apple device
A4:5E:60|Apple|Apple device
AC:BC:32|Apple|Apple device
D0:23:DB|Apple|Apple device
F0:18:98|Apple|Apple device
F4:5C:89|Apple|Apple device
BC:52:B7|Apple|Apple device
8C:85:90|Apple|Apple device
60:FB:42|Apple|Apple device
88:66:A5|Apple|Apple device
F0:99:BF|Apple|Apple device
44:65:0D|Amazon|Smart speaker / streaming / IoT
74:C2:46|Amazon|Smart speaker / streaming / IoT
F0:D2:F1|Amazon|Smart speaker / streaming / IoT
FC:65:DE|Amazon|Smart speaker / streaming / IoT
68:54:FD|Amazon|Smart speaker / streaming / IoT
84:D6:D0|Amazon|Smart speaker / streaming / IoT
F4:F5:D8|Google|Smart speaker / Chromecast / phone
F4:F5:E8|Google|Smart speaker / Chromecast / phone
54:60:09|Google|Smart speaker / Chromecast / phone
3C:5A:B4|Google|Smart speaker / Chromecast / phone
1C:F2:9A|Google|Smart speaker / Chromecast / phone
20:DF:B9|Google|Smart speaker / Chromecast / phone
48:D6:D5|Google|Smart speaker / Chromecast / phone
18:B4:30|Google Nest|Thermostat / camera / IoT
64:16:66|Google Nest|Thermostat / camera / IoT
00:0E:58|Sonos|Speaker
5C:AA:FD|Sonos|Speaker
94:9F:3E|Sonos|Speaker
48:A6:B8|Sonos|Speaker
B8:E9:37|Sonos|Speaker
54:2A:1B|Sonos|Speaker
B0:A7:37|Roku|TV / streaming
DC:3A:5E|Roku|TV / streaming
CC:6D:A0|Roku|TV / streaming
08:05:81|Roku|TV / streaming
AC:3A:7A|Roku|TV / streaming
D8:31:34|Roku|TV / streaming
00:17:88|Philips Hue (Signify)|Smart lighting
EC:B5:FA|Philips Hue (Signify)|Smart lighting
24:0A:C4|Espressif|IoT device (smart plug, bulb, sensor)
30:AE:A4|Espressif|IoT device (smart plug, bulb, sensor)
84:CC:A8|Espressif|IoT device (smart plug, bulb, sensor)
A4:CF:12|Espressif|IoT device (smart plug, bulb, sensor)
BC:DD:C2|Espressif|IoT device (smart plug, bulb, sensor)
CC:50:E3|Espressif|IoT device (smart plug, bulb, sensor)
24:62:AB|Espressif|IoT device (smart plug, bulb, sensor)
3C:71:BF|Espressif|IoT device (smart plug, bulb, sensor)
5C:CF:7F|Espressif|IoT device (smart plug, bulb, sensor)
60:01:94|Espressif|IoT device (smart plug, bulb, sensor)
80:7D:3A|Espressif|IoT device (smart plug, bulb, sensor)
84:F3:EB|Espressif|IoT device (smart plug, bulb, sensor)
A0:20:A6|Espressif|IoT device (smart plug, bulb, sensor)
AC:67:B2|Espressif|IoT device (smart plug, bulb, sensor)
C4:4F:33|Espressif|IoT device (smart plug, bulb, sensor)
DC:4F:22|Espressif|IoT device (smart plug, bulb, sensor)
EC:FA:BC|Espressif|IoT device (smart plug, bulb, sensor)
18:FE:34|Espressif|IoT device (smart plug, bulb, sensor)
2C:3A:E8|Espressif|IoT device (smart plug, bulb, sensor)
68:C6:3A|Espressif|IoT device (smart plug, bulb, sensor)
98:F4:AB|Espressif|IoT device (smart plug, bulb, sensor)
B4:E6:2D|Espressif|IoT device (smart plug, bulb, sensor)
D8:BF:C0|Espressif|IoT device (smart plug, bulb, sensor)
E8:DB:84|Espressif|IoT device (smart plug, bulb, sensor)
7C:9E:BD|Espressif|IoT device (smart plug, bulb, sensor)
08:3A:F2|Espressif|IoT device (smart plug, bulb, sensor)
C8:2B:96|Espressif|IoT device (smart plug, bulb, sensor)
50:C7:BF|TP-Link|Router / Wi-Fi / smart plug
14:CC:20|TP-Link|Router / Wi-Fi / smart plug
98:DA:C4|TP-Link|Router / Wi-Fi / smart plug
B0:BE:76|TP-Link|Router / Wi-Fi / smart plug
C0:4A:00|TP-Link|Router / Wi-Fi / smart plug
EC:08:6B|TP-Link|Router / Wi-Fi / smart plug
F4:F2:6D|TP-Link|Router / Wi-Fi / smart plug
60:32:B1|TP-Link|Router / Wi-Fi / smart plug
AC:84:C6|TP-Link|Router / Wi-Fi / smart plug
54:AF:97|TP-Link|Router / Wi-Fi / smart plug
1C:3B:F3|TP-Link|Router / Wi-Fi / smart plug
30:DE:4B|TP-Link|Router / Wi-Fi / smart plug
84:16:F9|TP-Link|Router / Wi-Fi / smart plug
00:09:5B|Netgear|Router / Wi-Fi
00:14:6C|Netgear|Router / Wi-Fi
00:1B:2F|Netgear|Router / Wi-Fi
00:1E:2A|Netgear|Router / Wi-Fi
00:22:3F|Netgear|Router / Wi-Fi
00:24:B2|Netgear|Router / Wi-Fi
00:26:F2|Netgear|Router / Wi-Fi
20:4E:7F|Netgear|Router / Wi-Fi
28:C6:8E|Netgear|Router / Wi-Fi
2C:B0:5D|Netgear|Router / Wi-Fi
30:46:9A|Netgear|Router / Wi-Fi
44:94:FC|Netgear|Router / Wi-Fi
6C:B0:CE|Netgear|Router / Wi-Fi
84:1B:5E|Netgear|Router / Wi-Fi
A0:40:A0|Netgear|Router / Wi-Fi
A0:63:91|Netgear|Router / Wi-Fi
C0:3F:0E|Netgear|Router / Wi-Fi
E0:46:9A|Netgear|Router / Wi-Fi
9C:D3:6D|Netgear|Router / Wi-Fi
00:06:25|Linksys|Router / Wi-Fi
00:0C:41|Linksys|Router / Wi-Fi
00:12:17|Linksys|Router / Wi-Fi
00:13:10|Linksys|Router / Wi-Fi
00:14:BF|Linksys|Router / Wi-Fi
00:16:B6|Linksys|Router / Wi-Fi
00:18:39|Linksys|Router / Wi-Fi
00:1A:70|Linksys|Router / Wi-Fi
00:1C:10|Linksys|Router / Wi-Fi
00:1D:7E|Linksys|Router / Wi-Fi
00:1E:E5|Linksys|Router / Wi-Fi
00:21:29|Linksys|Router / Wi-Fi
00:22:6B|Linksys|Router / Wi-Fi
00:23:69|Linksys|Router / Wi-Fi
00:25:9C|Linksys|Router / Wi-Fi
20:AA:4B|Linksys|Router / Wi-Fi
58:6D:8F|Linksys|Router / Wi-Fi
C0:C1:C0|Linksys|Router / Wi-Fi
48:F8:B3|Linksys|Router / Wi-Fi
00:15:6D|Ubiquiti|Router / Wi-Fi access point
00:27:22|Ubiquiti|Router / Wi-Fi access point
04:18:D6|Ubiquiti|Router / Wi-Fi access point
24:A4:3C|Ubiquiti|Router / Wi-Fi access point
44:D9:E7|Ubiquiti|Router / Wi-Fi access point
68:72:51|Ubiquiti|Router / Wi-Fi access point
78:8A:20|Ubiquiti|Router / Wi-Fi access point
80:2A:A8|Ubiquiti|Router / Wi-Fi access point
B4:FB:E4|Ubiquiti|Router / Wi-Fi access point
DC:9F:DB|Ubiquiti|Router / Wi-Fi access point
F0:9F:C2|Ubiquiti|Router / Wi-Fi access point
FC:EC:DA|Ubiquiti|Router / Wi-Fi access point
74:83:C2|Ubiquiti|Router / Wi-Fi access point
E0:63:DA|Ubiquiti|Router / Wi-Fi access point
18:E8:29|Ubiquiti|Router / Wi-Fi access point
24:5A:4C|Ubiquiti|Router / Wi-Fi access point
68:D7:9A|Ubiquiti|Router / Wi-Fi access point
78:45:58|Ubiquiti|Router / Wi-Fi access point
AC:8B:A9|Ubiquiti|Router / Wi-Fi access point
D0:21:F9|Ubiquiti|Router / Wi-Fi access point
00:1A:92|ASUS|Router / computer
00:1D:60|ASUS|Router / computer
00:22:15|ASUS|Router / computer
00:23:54|ASUS|Router / computer
00:24:8C|ASUS|Router / computer
00:26:18|ASUS|Router / computer
08:60:6E|ASUS|Router / computer
10:BF:48|ASUS|Router / computer
14:DA:E9|ASUS|Router / computer
1C:87:2C|ASUS|Router / computer
2C:56:DC|ASUS|Router / computer
30:5A:3A|ASUS|Router / computer
38:D5:47|ASUS|Router / computer
40:16:7E|ASUS|Router / computer
50:46:5D|ASUS|Router / computer
54:04:A6|ASUS|Router / computer
60:45:CB|ASUS|Router / computer
70:4D:7B|ASUS|Router / computer
74:D0:2B|ASUS|Router / computer
AC:22:0B|ASUS|Router / computer
BC:EE:7B|ASUS|Router / computer
D8:50:E6|ASUS|Router / computer
F4:6D:04|ASUS|Router / computer
04:D9:F5|ASUS|Router / computer
00:09:0F|Fortinet|Firewall
08:5B:0E|Fortinet|Firewall
70:4C:A5|Fortinet|Firewall
90:6C:AC|Fortinet|Firewall
00:06:B1|SonicWall|Firewall
00:17:C5|SonicWall|Firewall
C0:EA:E4|SonicWall|Firewall
18:B1:69|SonicWall|Firewall
00:18:0A|Cisco Meraki|Network device
0C:8D:DB|Cisco Meraki|Network device
34:56:FE|Cisco Meraki|Network device
88:15:44|Cisco Meraki|Network device
AC:17:C8|Cisco Meraki|Network device
E0:55:3D|Cisco Meraki|Network device
E0:CB:BC|Cisco Meraki|Network device
00:1B:21|Intel|Computer (PC/laptop network card)
00:1E:67|Intel|Computer (PC/laptop network card)
00:1F:3B|Intel|Computer (PC/laptop network card)
3C:A9:F4|Intel|Computer (PC/laptop network card)
7C:7A:91|Intel|Computer (PC/laptop network card)
80:86:F2|Intel|Computer (PC/laptop network card)
A0:A8:CD|Intel|Computer (PC/laptop network card)
B4:96:91|Intel|Computer (PC/laptop network card)
F8:63:3F|Intel|Computer (PC/laptop network card)
8C:8D:28|Intel|Computer (PC/laptop network card)
34:13:E8|Intel|Computer (PC/laptop network card)
48:51:B7|Intel|Computer (PC/laptop network card)
5C:87:9C|Intel|Computer (PC/laptop network card)
64:5D:86|Intel|Computer (PC/laptop network card)
70:9C:D1|Intel|Computer (PC/laptop network card)
9C:B6:D0|Intel|Computer (PC/laptop network card)
A4:34:D9|Intel|Computer (PC/laptop network card)
AC:ED:5C|Intel|Computer (PC/laptop network card)
D0:57:7B|Intel|Computer (PC/laptop network card)
DC:21:5C|Intel|Computer (PC/laptop network card)
F8:94:C2|Intel|Computer (PC/laptop network card)
00:E0:4C|Realtek|Computer (network card)
00:14:22|Dell|Computer
18:03:73|Dell|Computer
18:DB:F2|Dell|Computer
24:B6:FD|Dell|Computer
34:17:EB|Dell|Computer
54:BF:64|Dell|Computer
74:86:7A|Dell|Computer
84:7B:EB|Dell|Computer
98:90:96|Dell|Computer
B8:2A:72|Dell|Computer
B8:CA:3A|Dell|Computer
D4:81:D7|Dell|Computer
D4:BE:D9|Dell|Computer
F8:B1:56|Dell|Computer
F8:BC:12|Dell|Computer
A4:BB:6D|Dell|Computer
6C:2B:59|Dell|Computer
E4:54:E8|Dell|Computer
00:1B:78|HP|Computer / printer
00:1E:0B|HP|Computer / printer
00:21:5A|HP|Computer / printer
00:23:7D|HP|Computer / printer
00:25:B3|HP|Computer / printer
10:60:4B|HP|Computer / printer
14:58:D0|HP|Computer / printer
1C:C1:DE|HP|Computer / printer
2C:44:FD|HP|Computer / printer
30:E1:71|HP|Computer / printer
3C:D9:2B|HP|Computer / printer
40:B0:34|HP|Computer / printer
64:51:06|HP|Computer / printer
70:5A:0F|HP|Computer / printer
80:CE:62|HP|Computer / printer
94:57:A5|HP|Computer / printer
9C:8E:99|HP|Computer / printer
A0:D3:C1|HP|Computer / printer
B0:5A:DA|HP|Computer / printer
D4:C9:EF|HP|Computer / printer
EC:B1:D7|HP|Computer / printer
F4:CE:46|HP|Computer / printer
FC:15:B4|HP|Computer / printer
00:1E:8F|Canon|Printer
18:0C:AC|Canon|Printer
2C:9E:FC|Canon|Printer
F4:81:39|Canon|Printer
88:87:17|Canon|Printer
00:BB:C1|Canon|Printer
00:26:AB|Epson|Printer
64:EB:8C|Epson|Printer
A4:EE:57|Epson|Printer
AC:18:26|Epson|Printer
B0:E8:92|Epson|Printer
38:1A:52|Epson|Printer
44:D2:44|Epson|Printer
9C:AE:D3|Epson|Printer
E0:BB:9E|Epson|Printer
DC:CD:2F|Epson|Printer
00:1B:A9|Brother|Printer
00:80:77|Brother|Printer
30:05:5C|Brother|Printer
3C:2A:F4|Brother|Printer
00:12:FB|Samsung|Phone / TV / appliance
00:15:99|Samsung|Phone / TV / appliance
00:16:32|Samsung|Phone / TV / appliance
00:1D:25|Samsung|Phone / TV / appliance
00:21:19|Samsung|Phone / TV / appliance
00:23:39|Samsung|Phone / TV / appliance
08:D4:2B|Samsung|Phone / TV / appliance
10:1D:C0|Samsung|Phone / TV / appliance
14:49:E0|Samsung|Phone / TV / appliance
18:3A:2D|Samsung|Phone / TV / appliance
1C:62:B8|Samsung|Phone / TV / appliance
24:4B:03|Samsung|Phone / TV / appliance
28:BA:B5|Samsung|Phone / TV / appliance
30:CD:A7|Samsung|Phone / TV / appliance
34:23:BA|Samsung|Phone / TV / appliance
38:01:97|Samsung|Phone / TV / appliance
40:0E:85|Samsung|Phone / TV / appliance
4C:BC:A5|Samsung|Phone / TV / appliance
50:01:BB|Samsung|Phone / TV / appliance
5C:49:7D|Samsung|Phone / TV / appliance
64:B3:10|Samsung|Phone / TV / appliance
78:BD:BC|Samsung|Phone / TV / appliance
84:25:DB|Samsung|Phone / TV / appliance
8C:71:F8|Samsung|Phone / TV / appliance
90:F1:AA|Samsung|Phone / TV / appliance
94:35:0A|Samsung|Phone / TV / appliance
A0:0B:BA|Samsung|Phone / TV / appliance
B4:79:A7|Samsung|Phone / TV / appliance
BC:14:85|Samsung|Phone / TV / appliance
C0:97:27|Samsung|Phone / TV / appliance
CC:07:AB|Samsung|Phone / TV / appliance
D0:22:BE|Samsung|Phone / TV / appliance
E4:7C:F9|Samsung|Phone / TV / appliance
F0:25:B7|Samsung|Phone / TV / appliance
F4:7B:5E|Samsung|Phone / TV / appliance
F8:04:2E|Samsung|Phone / TV / appliance
FC:A1:3E|Samsung|Phone / TV / appliance
00:1E:75|LG Electronics|TV / phone / appliance
10:68:3F|LG Electronics|TV / phone / appliance
20:3D:BD|LG Electronics|TV / phone / appliance
34:4D:F7|LG Electronics|TV / phone / appliance
38:8C:50|LG Electronics|TV / phone / appliance
58:A2:B5|LG Electronics|TV / phone / appliance
64:99:5D|LG Electronics|TV / phone / appliance
78:5D:C8|LG Electronics|TV / phone / appliance
88:C9:D0|LG Electronics|TV / phone / appliance
A8:16:B2|LG Electronics|TV / phone / appliance
C4:36:6C|LG Electronics|TV / phone / appliance
CC:2D:8C|LG Electronics|TV / phone / appliance
E8:5B:5B|LG Electronics|TV / phone / appliance
00:04:1F|Sony|Game console / TV
00:13:15|Sony|Game console / TV
00:15:C1|Sony|Game console / TV
00:19:C5|Sony|Game console / TV
00:1D:0D|Sony|Game console / TV
00:1F:A7|Sony|Game console / TV
00:24:8D|Sony|Game console / TV
28:0D:FC|Sony|Game console / TV
70:9E:29|Sony|Game console / TV
A8:E3:EE|Sony|Game console / TV
BC:60:A7|Sony|Game console / TV
F8:46:1C|Sony|Game console / TV
FC:0F:E6|Sony|Game console / TV
00:50:F2|Microsoft|Xbox / Surface
28:18:78|Microsoft|Xbox / Surface
30:59:B7|Microsoft|Xbox / Surface
60:45:BD|Microsoft|Xbox / Surface
7C:1E:52|Microsoft|Xbox / Surface
98:5F:D3|Microsoft|Xbox / Surface
C8:3F:26|Microsoft|Xbox / Surface
DC:B4:C4|Microsoft|Xbox / Surface
58:82:A8|Microsoft|Xbox / Surface
00:17:FA|Microsoft|Xbox / Surface
00:22:48|Microsoft|Xbox / Surface
00:25:AE|Microsoft|Xbox / Surface
7C:ED:8D|Microsoft|Xbox / Surface
00:09:BF|Nintendo|Game console
00:16:56|Nintendo|Game console
00:17:AB|Nintendo|Game console
00:19:1D|Nintendo|Game console
00:1A:E9|Nintendo|Game console
00:1B:EA|Nintendo|Game console
00:1C:BE|Nintendo|Game console
00:1D:BC|Nintendo|Game console
00:1E:35|Nintendo|Game console
00:1F:32|Nintendo|Game console
00:21:47|Nintendo|Game console
00:22:4C|Nintendo|Game console
00:23:31|Nintendo|Game console
00:24:1E|Nintendo|Game console
00:24:44|Nintendo|Game console
00:25:A0|Nintendo|Game console
04:03:D6|Nintendo|Game console
18:2A:7B|Nintendo|Game console
2C:10:C1|Nintendo|Game console
34:AF:2C|Nintendo|Game console
40:F4:07|Nintendo|Game console
58:BD:A3|Nintendo|Game console
7C:BB:8A|Nintendo|Game console
8C:56:C5|Nintendo|Game console
98:B6:E9|Nintendo|Game console
A4:C0:E1|Nintendo|Game console
B8:AE:6E|Nintendo|Game console
CC:FB:65|Nintendo|Game console
D8:6B:F7|Nintendo|Game console
DC:68:EB|Nintendo|Game console
E0:E7:51|Nintendo|Game console
E8:4E:CE|Nintendo|Game console
64:B5:C6|Nintendo|Game console
00:11:32|Synology|NAS / file server
90:09:D0|Synology|NAS / file server
00:08:9B|QNAP|NAS / file server
24:5E:BE|QNAP|NAS / file server
44:19:B6|Hikvision|Security camera / recorder
4C:BD:8F|Hikvision|Security camera / recorder
C0:56:E3|Hikvision|Security camera / recorder
BC:AD:28|Hikvision|Security camera / recorder
28:57:BE|Hikvision|Security camera / recorder
54:C4:15|Hikvision|Security camera / recorder
18:68:CB|Hikvision|Security camera / recorder
C4:2F:90|Hikvision|Security camera / recorder
A4:14:37|Hikvision|Security camera / recorder
8C:E7:48|Hikvision|Security camera / recorder
3C:EF:8C|Dahua|Security camera / recorder
4C:11:BF|Dahua|Security camera / recorder
90:02:A9|Dahua|Security camera / recorder
14:A7:8B|Dahua|Security camera / recorder
2C:AA:8E|Wyze|Security camera / IoT
7C:78:B2|Wyze|Security camera / IoT
D0:3F:27|Wyze|Security camera / IoT
44:61:32|ecobee|Thermostat
64:52:99|Chamberlain (myQ)|Garage door opener
08:86:3B|Belkin|Smart plug / router
94:10:3E|Belkin|Smart plug / router
B4:75:0E|Belkin|Smart plug / router
C0:56:27|Belkin|Smart plug / router
EC:1A:59|Belkin|Smart plug / router
28:6C:07|Xiaomi|Phone / IoT
34:CE:00|Xiaomi|Phone / IoT
64:09:80|Xiaomi|Phone / IoT
78:11:DC|Xiaomi|Phone / IoT
7C:49:EB|Xiaomi|Phone / IoT
28:D2:44|Lenovo|Computer
54:EE:75|Lenovo|Computer
8C:16:45|Lenovo|Computer
E8:6A:64|Lenovo|Computer
98:FA:9B|Lenovo|Computer
50:7B:9D|Lenovo|Computer
C8:5B:76|Lenovo|Computer
MSP_OUI
}

MSP_VENDOR=''
MSP_VENDOR_HINT=''
MSP_VENDOR_RANDOM=0
msp_mac_vendor() {
    # msp_mac_vendor MAC - sets MSP_VENDOR, MSP_VENDOR_HINT and MSP_VENDOR_RANDOM (1 = a private,
    # randomized MAC, which phones, tablets and laptops use for Wi-Fi privacy). Sets globals
    # instead of printing so callers avoid a subshell per device. Matches Get-MSPMacVendor.
    local hex oui line first
    MSP_VENDOR='Unknown'
    MSP_VENDOR_HINT=''
    MSP_VENDOR_RANDOM=0
    hex=$(printf '%s' "${1-}" | tr -cd '0-9A-Fa-f' | tr 'abcdef' 'ABCDEF')
    [ "${#hex}" -ge 6 ] || return 0
    oui="${hex:0:2}:${hex:2:2}:${hex:4:2}"
    line=$(msp__oui_data | awk -F'|' -v o="$oui" '$1 == o { print; exit }')
    if [ -n "$line" ]; then
        line=${line#*|}
        MSP_VENDOR=${line%%|*}
        MSP_VENDOR_HINT=${line#*|}
        return 0
    fi
    # Second-lowest bit of the first byte = "locally administered" = randomized/private MAC.
    first=$((16#${hex:0:2}))
    if [ $((first & 2)) -eq 2 ]; then
        MSP_VENDOR='Private/randomized MAC'
        MSP_VENDOR_HINT='Phone, tablet or laptop using Wi-Fi privacy'
        MSP_VENDOR_RANDOM=1
    fi
    return 0
}
#endregion MSPHelper:Net
#endregion MSPToolkit (generated)

SCRIPT_VERSION='1.0.0'
OUTPUT=''
SKIP_PROMPT=0
EXPECTED_DNS=''
SSDP_WAIT=3
while [ $# -gt 0 ]; do
    case "$1" in
        --output)
            OUTPUT=${2-}
            [ -n "$OUTPUT" ] || { printf 'Missing folder after --output\n' >&2; exit 2; }
            shift 2
            ;;
        --skip-checklist-prompt) SKIP_PROMPT=1; shift ;;
        --expected-dns) EXPECTED_DNS=$(printf '%s' "${2-}" | tr ',' ' '); shift 2 ;;
        --ssdp-wait)
            SSDP_WAIT=${2-}
            case "$SSDP_WAIT" in '' | *[!0-9]*) printf -- '--ssdp-wait needs 1-10\n' >&2; exit 2 ;; esac
            if [ "$SSDP_WAIT" -lt 1 ] || [ "$SSDP_WAIT" -gt 10 ]; then printf -- '--ssdp-wait needs 1-10\n' >&2; exit 2; fi
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
msp_param SkipChecklistPrompt "$SKIP_PROMPT"
[ -n "$EXPECTED_DNS" ] && msp_param ExpectedDnsServer "$EXPECTED_DNS"
msp_param SsdpWaitSeconds "$SSDP_WAIT"
msp_init 'get-router-security-check' "$SCRIPT_VERSION" 'A7' 'Read-Only' 'Home router security check (read-only; no logins)'

# Well-known public resolvers (ERE on the address). Filtering resolvers are legitimate choices.
KNOWN_RESOLVERS='^1\.1\.1\.[123]$|^1\.0\.0\.[123]$|^2606:4700:4700::|Cloudflare
^8\.8\.8\.8$|^8\.8\.4\.4$|^2001:4860:4860::|Google Public DNS
^9\.9\.9\.[0-9]+$|^149\.112\.112\.[0-9]+$|^2620:fe::|Quad9
^208\.67\.22[02]\.[0-9]+$|^2620:119:|Cisco OpenDNS
^94\.140\.1[45]\.[0-9]+$|^2a10:50c0::|AdGuard DNS
^185\.228\.16[89]\.[0-9]+$|^2a0d:2a00:|CleanBrowsing
^8\.26\.56\.26$|^8\.20\.247\.20$|Comodo Secure DNS
^45\.90\.(28|30)\.[0-9]+$|^2a07:a8c[01]::|NextDNS
^76\.76\.(2|10)\.[0-9]+$|^2606:1a40:|Control D
^194\.242\.2\.[0-9]+$|^2a07:e340::|Mullvad DNS
^4\.2\.2\.[1-6]$|Level3/Lumen
^156\.154\.7[01]\.[0-9]+$|UltraDNS (Vercara)'

is_private() {
    printf '%s' "$1" | grep -Eq '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.|127\.)|^(fe80|fc|fd)[0-9a-f]*:|^::1$'
}

known_resolver() {
    # Prints the resolver's name when the address matches the table.
    local line pattern
    while IFS= read -r line; do
        pattern=${line%|*}
        if printf '%s' "$1" | grep -Eq "$pattern"; then printf '%s' "${line##*|}"; return 0; fi
    done <<EOF
$KNOWN_RESOLVERS
EOF
    return 1
}

HTTP_DIR="${MSP_WORK_DIR:-${TMPDIR:-/tmp}}/http"
mkdir -p "$HTTP_DIR" 2>/dev/null
HTTP_N=0
http_get() {
    # http_get URL [METHOD BODY SOAPACTION] - one request without credentials, redirects NOT
    # followed. Sets H_CODE, H_LOCATION, H_SERVER, H_AUTH, H_TITLE and H_BODY (a file). HTTPS
    # certificate errors are ignored for this request only: home routers use self-signed
    # certificates, and only the login page is read; nothing is ever sent but these requests.
    local url=$1 method=${2:-GET} body=${3-} action=${4-} headers
    HTTP_N=$((HTTP_N + 1))
    headers="$HTTP_DIR/$HTTP_N.h"
    H_BODY="$HTTP_DIR/$HTTP_N.b"
    H_CODE=''; H_LOCATION=''; H_SERVER=''; H_AUTH=''; H_TITLE=''
    : >"$headers"
    : >"$H_BODY"
    if msp_have curl; then
        if [ "$method" = 'POST' ]; then
            curl -s -k -m 5 --noproxy '*' -A 'MSP-Toolkit-ReadOnly-Check' -D "$headers" -o "$H_BODY" \
                -H 'Content-Type: text/xml; charset="utf-8"' -H "SOAPAction: \"$action\"" --data-binary "$body" "$url" 2>/dev/null
        else
            curl -s -k -m 5 --noproxy '*' -A 'MSP-Toolkit-ReadOnly-Check' -D "$headers" -o "$H_BODY" -r 0-65535 "$url" 2>/dev/null
        fi
    elif msp_have wget && [ "$method" = 'GET' ]; then
        wget -q -S -T 5 --no-proxy --no-check-certificate --max-redirect=0 -U 'MSP-Toolkit-ReadOnly-Check' -O "$H_BODY" "$url" 2>"$headers"
        sed -i 's/^  //' "$headers" 2>/dev/null # linux-only: wget prefixes headers with two spaces
    else
        return 1
    fi
    H_CODE=$(awk 'toupper($1) ~ /^HTTP\// { c = $2 } END { print c }' "$headers")
    H_LOCATION=$(awk 'tolower($1) == "location:" { $1 = ""; sub(/^ /, ""); sub(/\r$/, ""); print; exit }' "$headers")
    H_SERVER=$(awk 'tolower($1) == "server:" { $1 = ""; sub(/^ /, ""); sub(/\r$/, ""); print; exit }' "$headers")
    H_AUTH=$(awk 'tolower($1) == "www-authenticate:" { $1 = ""; sub(/^ /, ""); sub(/\r$/, ""); print; exit }' "$headers")
    H_TITLE=$(tr '\r\n' '  ' <"$H_BODY" | sed -n 's/.*<[Tt][Ii][Tt][Ll][Ee][^>]*>[[:space:]]*\([^<]*\)<\/[Tt][Ii][Tt][Ll][Ee]>.*/\1/p' | sed 's/[[:space:]][[:space:]]*/ /g; s/ *$//' | cut -c1-100)
    [ -n "$H_CODE" ]
}

xml_value() {
    # xml_value FILE TAG -> text of the first <TAG> (any namespace prefix).
    tr '\r\n' '  ' <"$1" | sed -n "s/.*<\([A-Za-z0-9]*:\)\{0,1\}$2>[[:space:]]*\([^<]*\)<\/\([A-Za-z0-9]*:\)\{0,1\}$2>.*/\2/p" | head -n 1
}

# =========================================================================================
msp_section 'Scope'
# =========================================================================================
GATEWAY=''
find_gateway() {
    if msp_local_subnet; then
        GATEWAY=$MSP_NET_GATEWAY
        return 0
    fi
    if [ "$MSP_NET_SKIP" -eq 1 ]; then
        msp_skip 'Gateway' 'Gateway' "$MSP_NET_ERROR" 'Disconnect the VPN (or connect to the client'\''s network directly) and run again.'
        return 0
    fi
    printf '%s\n' "$MSP_NET_ERROR" >&2
    return 1
}
msp_check 'Gateway' 'Gateway' find_gateway
if [ -n "$GATEWAY" ]; then
    msp_say 1 '  Only the router below is contacted, plus one UPnP discovery message on the local network.'
    printf '    Adapter : %s\n' "$MSP_NET_IFACE"
    printf '    Router  : %s   (this computer %s, subnet %s)\n' "$GATEWAY" "$MSP_NET_IP" "$MSP_NET_CIDR"
    printf '    Contact : TCP 21, 22, 23, 80, 443, 8080, 8443 on the router (and any local HTTPS address it redirects to);\n'
    printf '              SSDP multicast 239.255.255.250:1900 (TTL 1)\n'
    printf '    Never   : logins, password guesses, or setting changes\n'
    msp_log INFO "Scope: gateway $GATEWAY on $MSP_NET_CIDR; TCP 21,22,23,80,443,8080,8443; SSDP multicast"
    msp_finding --status INFO --category 'Gateway' --check 'Gateway' --detail "Router $GATEWAY on $MSP_NET_CIDR ($MSP_NET_IFACE)." \
        --evidence "$(msp_json_obj Gateway "$GATEWAY" Cidr "$MSP_NET_CIDR" Adapter "$MSP_NET_IFACE")"
fi

# =========================================================================================
msp_section 'DNS servers'
# =========================================================================================
static_dns() {
    # DNS servers typed in by hand for the active adapter (empty when automatic).
    if [ "$MSP_PLATFORM" = 'macOS' ]; then
        local service
        service=$(networksetup -listnetworkserviceorder 2>/dev/null | awk -v d="Device: $MSP_NET_IFACE)" 'index($0, d) { print prev; exit } { prev = $0 }' | sed 's/^([0-9*]*) //')
        [ -n "$service" ] && networksetup -getdnsservers "$service" 2>/dev/null | grep -E '^[0-9a-fA-F:.]+$'
    elif msp_have nmcli; then
        local con
        con=$(nmcli -g GENERAL.CONNECTION device show "$MSP_NET_IFACE" 2>/dev/null | head -n 1)
        [ -n "$con" ] && nmcli -g ipv4.dns connection show "$con" 2>/dev/null | tr ',' '\n' | grep -E '^[0-9a-fA-F:.]+$'
    fi
    return 0
}

check_dns() {
    local servers static dns how known
    servers=$(msp_dns_servers)
    if [ -z "$servers" ]; then
        msp_finding --status WARN --severity Low --category 'DNS' --check 'DNS servers in use' --detail 'No DNS servers are configured.' \
            --rec 'Check the adapter is set to obtain DNS automatically.'
        return 0
    fi
    static=$(static_dns)
    how='from the router (automatic)'
    [ -n "$static" ] && how='typed in by hand on this computer (static)'
    msp_finding --status INFO --category 'DNS' --check 'DNS configuration' --detail "DNS servers $how: $(printf '%s\n' "$servers" | paste -sd ',' - | sed 's/,/, /g')"
    for dns in $servers; do
        local ev
        ev=$(msp_json_obj Server "$dns" Static# "$([ -n "$static" ] && echo true || echo false)")
        case " $EXPECTED_DNS " in *" $dns "*)
            msp_finding --status PASS --category 'DNS' --check "DNS $dns" --target "$dns" --evidence "$ev" --detail 'Listed as expected by the technician.'
            continue
            ;;
        esac
        if is_private "$dns" || [ "$dns" = "$GATEWAY" ] || msp_ip_in_subnet "$dns"; then
            local where='a device on the home network (for example Pi-hole or a second router)'
            [ "$dns" = "$GATEWAY" ] && where='the router, which forwards to its upstream DNS'
            msp_finding --status PASS --category 'DNS' --check "DNS $dns" --target "$dns" --evidence "$ev" --detail "Local DNS: $where."
            continue
        fi
        if known=$(known_resolver "$dns"); then
            msp_finding --status PASS --category 'DNS' --check "DNS $dns" --target "$dns" --evidence "$ev" --detail "Well-known public resolver: $known."
            continue
        fi
        local sev='Low' why='Usually this is the internet provider'\''s own DNS.'
        if [ -n "$static" ]; then sev='Medium'; why='It was typed in by hand on this computer, which DNS-changing malware also does.'; fi
        msp_finding --status WARN --severity "$sev" --category 'DNS' --check "DNS $dns" --target "$dns" --evidence "$ev" \
            --detail "Unrecognised public DNS server $dns. $why" \
            --rec 'Confirm it belongs to the client'\''s internet provider (an IP lookup shows the owner). If it does not and the client did not set it, set DNS back to automatic and scan for malware.'
    done
    msp_finding --status INFO --category 'DNS' --check 'Router upstream DNS' \
        --detail 'The DNS servers the ROUTER uses are only visible in its admin page (Internet/WAN settings). Check them during the checklist; they should be automatic (ISP) or a resolver the client chose.'
}
if [ -n "$GATEWAY" ]; then msp_check 'DNS' 'DNS servers in use' check_dns; fi

# =========================================================================================
msp_section 'Router admin page and management ports'
# =========================================================================================
ADMIN_ROWS=''   # Url|Scheme|Port|Answered|Code|RedirectTo|ToHttps|BasicAuth|Title|Server
check_admin_page() {
    if ! msp_have curl && ! msp_have wget; then
        msp_skip 'AdminPage' 'Admin page' 'Skipped: neither curl nor wget is installed, so the admin page cannot be requested.' 'Install curl, or check the admin page in a browser.'
        return 0
    fi
    local probe scheme port url redirect answered tohttps basic
    for probe in http:80 http:8080 https:443 https:8443; do
        scheme=${probe%:*}
        port=${probe#*:}
        msp_tcp_open "$GATEWAY" "$port" || continue
        url="$scheme://$GATEWAY:$port/"
        answered=false
        http_get "$url" && answered=true
        redirect=''
        case "$H_CODE" in 3??) redirect=$H_LOCATION ;; esac
        # Routers also redirect with a page that refreshes or scripts to https.
        [ -n "$redirect" ] || redirect=$(tr '\r\n' '  ' <"$H_BODY" | grep -oiE '(http-equiv=["'\'']?refresh[^>]*url=|location(\.href)?[[:space:]]*=[[:space:]]*["'\''])https://[^"'\''> ;]+' | grep -oiE 'https://[^"'\''> ;]+' | head -n 1)
        tohttps=false
        case "$redirect" in https:*) tohttps=true ;; esac
        basic=false
        case "$H_AUTH" in Basic*) basic=true ;; esac
        ADMIN_ROWS="$ADMIN_ROWS$url|$scheme|$port|$answered|$H_CODE|$redirect|$tohttps|$basic|$H_TITLE|$H_SERVER
"
    done
    # Follow each HTTPS redirect once (only to addresses inside the local subnet).
    local row target host tport
    while IFS='|' read -r url scheme port answered _ redirect tohttps _ _ _; do
        [ "$tohttps" = 'true' ] || continue
        host=$(printf '%s' "$redirect" | sed -n 's|^https://\([^/:]*\).*|\1|p')
        tport=$(printf '%s' "$redirect" | sed -n 's|^https://[^/:]*:\([0-9]*\).*|\1|p')
        [ -n "$tport" ] || tport=443
        msp_ip_in_subnet "$host" || continue
        printf '%s' "$ADMIN_ROWS" | awk -F'|' -v p="$tport" '$2 == "https" && $3 == p { f = 1 } END { exit !f }' && continue
        msp_log INFO "Following HTTPS redirect to $redirect"
        answered=false
        http_get "$redirect" && answered=true
        basic=false
        case "$H_AUTH" in Basic*) basic=true ;; esac
        ADMIN_ROWS="$ADMIN_ROWS$redirect|https|$tport|$answered|$H_CODE|$H_LOCATION|false|$basic|$H_TITLE|$H_SERVER
"
    done <<EOF
$ADMIN_ROWS
EOF
    local u s p a c r t b ti sv identity=''
    while IFS='|' read -r u s p a c r t b ti sv; do
        [ -n "$u" ] || continue
        printf '  %-36s %-4s %-6s %s\n' "$u" "${c:--}" "$t" "${ti:-$sv}"
        msp_data_row 'AdminPage' Url "$u" Scheme "$s" Port# "$p" Answered# "$a" StatusCode "$c" RedirectTo "$r" ToHttps# "$t" BasicAuth# "$b" Title "$ti" Server "$sv"
        [ -n "$ti" ] && identity="$identity${identity:+ | }$ti"
        [ -n "$sv" ] && identity="$identity${identity:+ | }$sv"
    done <<EOF
$ADMIN_ROWS
EOF
    identity=$(printf '%s' "$identity" | tr '|' '\n' | sed 's/^ *//; s/ *$//' | awk 'NF && !s[$0]++' | paste -sd '|' - | sed 's/|/ | /g')
    [ -n "$identity" ] && msp_finding --status INFO --category 'AdminPage' --check 'Router identification' --detail "Admin page reports: $identity"
    local http https plain basic_plain
    http=$(printf '%s' "$ADMIN_ROWS" | awk -F'|' '$2 == "http" && $4 == "true" { print $1 }')
    https=$(printf '%s' "$ADMIN_ROWS" | awk -F'|' '$2 == "https" && $4 == "true" { print $1 }' | paste -sd ',' - | sed 's/,/, /g')
    plain=$(printf '%s' "$ADMIN_ROWS" | awk -F'|' '$2 == "http" && $4 == "true" && $7 != "true" { print $1 }' | paste -sd ',' - | sed 's/,/, /g')
    basic_plain=$(printf '%s' "$ADMIN_ROWS" | awk -F'|' '$2 == "http" && $4 == "true" && $7 != "true" && $8 == "true"')
    if [ -z "$http" ] && [ -z "$https" ]; then
        msp_finding --status INFO --category 'AdminPage' --check 'Admin page encryption' \
            --detail 'No web admin page answered on ports 80/443/8080/8443. The router may be managed only through a phone app (common for mesh systems).'
        return 0
    fi
    if [ -n "$plain" ] && [ -z "$https" ]; then
        local detail="The admin page is only available over unencrypted HTTP ($plain). The admin password crosses the network in clear text."
        [ -n "$basic_plain" ] && detail="$detail It uses HTTP Basic authentication, which is trivially readable."
        msp_finding --status WARN --severity Medium --category 'AdminPage' --check 'Admin page encryption' --detail "$detail" \
            --rec 'If the router offers it, enable HTTPS for the admin page. Only log in from a wired or trusted device, and make sure the Wi-Fi is WPA2/WPA3.'
    elif [ -n "$plain" ]; then
        msp_finding --status WARN --severity Low --category 'AdminPage' --check 'Admin page encryption' \
            --detail "HTTPS is available ($https), but the admin page also loads over plain HTTP without redirecting ($plain)." \
            --rec 'Use the https:// address to log in. If the router has a "redirect HTTP to HTTPS" or "HTTPS only" option, turn it on.'
    else
        msp_finding --status PASS --category 'AdminPage' --check 'Admin page encryption' \
            --detail "Admin page uses HTTPS (${https:-redirect target did not answer}); plain HTTP only redirects to it."
    fi
}

check_mgmt_ports() {
    local found=0
    if msp_tcp_open "$GATEWAY" 23; then
        found=1
        msp_finding --status FAIL --severity High --category 'AdminPage' --check 'Router Telnet' --target "$GATEWAY" \
            --detail 'The router accepts Telnet (port 23): unencrypted remote login, heavily targeted by router malware.' \
            --rec 'Turn Telnet off in the router'\''s administration settings, and update the firmware. If it cannot be turned off, consider replacing the router.'
    fi
    if msp_tcp_open "$GATEWAY" 21; then
        found=1
        msp_finding --status WARN --severity Medium --category 'AdminPage' --check 'Router FTP' --target "$GATEWAY" \
            --detail 'The router runs an FTP server (port 21), usually for a USB drive. FTP passwords are not encrypted.' \
            --rec 'Turn off FTP/USB sharing unless the client uses it; if used, set a strong password and make sure it is not reachable from the internet.'
    fi
    if msp_tcp_open "$GATEWAY" 22; then
        found=1
        msp_finding --status INFO --category 'AdminPage' --check 'Router SSH' --target "$GATEWAY" \
            --detail 'The router accepts SSH (port 22). Encrypted; normal on some routers (UniFi, OpenWrt). Confirm it is not enabled on the internet side.'
    fi
    [ "$found" -eq 1 ] || msp_finding --status PASS --category 'AdminPage' --check 'Router management ports' --target "$GATEWAY" --detail 'No Telnet, FTP or SSH on the router.'
}
if [ -n "$GATEWAY" ]; then
    msp_check 'AdminPage' 'Admin page' check_admin_page
    msp_check 'AdminPage' 'Router management ports' check_mgmt_ports
fi

# =========================================================================================
msp_section 'UPnP'
# =========================================================================================
UPNP_ON=0
ssdp_discover() {
    # Prints one line per answer: "<ip><TAB>ST=...;LOCATION=...;SERVER=...". perl is used for the
    # UDP socket (bash cannot receive UDP). TTL 1 keeps the message on the local network.
    perl -e '
        use strict; use Socket; use IO::Socket::INET;
        my ($local, $wait) = @ARGV;
        my $s = IO::Socket::INET->new(Proto => "udp", LocalAddr => $local) or exit 3;
        my $ttl = eval { Socket::IP_MULTICAST_TTL() } || ($^O eq "darwin" ? 10 : 33);
        setsockopt($s, IPPROTO_IP, $ttl, pack("i", 1)) or setsockopt($s, IPPROTO_IP, $ttl, pack("C", 1));
        my $dest = sockaddr_in(1900, inet_aton("239.255.255.250"));
        for my $st ("urn:schemas-upnp-org:device:InternetGatewayDevice:1", "urn:schemas-upnp-org:device:InternetGatewayDevice:2", "ssdp:all") {
            send($s, "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: $st\r\n\r\n", 0, $dest);
        }
        my $end = time + $wait;
        while (time < $end) {
            my $rin = ""; vec($rin, fileno($s), 1) = 1;
            next unless select(my $rout = $rin, undef, undef, 0.3);
            my $from = recv($s, my $data, 4096, 0) or next;
            my (undef, $addr) = sockaddr_in($from);
            my %h; for (split /\r?\n/, $data) { $h{uc $1} = $2 if /^([A-Za-z0-9-]+):\s*(.*?)\s*$/ }
            print inet_ntoa($addr), "\tST=", ($h{ST} // ""), ";LOCATION=", ($h{LOCATION} // ""), ";SERVER=", ($h{SERVER} // ""), "\n";
        }' "$MSP_NET_IP" "$SSDP_WAIT"
}

check_upnp() {
    if ! msp_have perl; then
        msp_skip 'UPnP' 'UPnP discovery' 'Skipped: perl is not installed, and bash alone cannot receive the UPnP answers.' 'Check "UPnP" in the router'\''s admin page during the checklist.'
        return 0
    fi
    local answers
    answers=$(ssdp_discover 2>/dev/null)
    local ips ip types igd server location igd_location='' others='' igd_list=''
    ips=$(printf '%s\n' "$answers" | cut -f1 | awk 'NF && !s[$0]++')
    for ip in $ips; do
        msp_ip_in_subnet "$ip" || continue
        types=$(printf '%s\n' "$answers" | awk -F'\t' -v i="$ip" '$1 == i { split($2, a, ";"); sub(/^ST=/, "", a[1]); if (a[1] != "" && !s[a[1]]++) print a[1] }')
        server=$(printf '%s\n' "$answers" | awk -F'\t' -v i="$ip" '$1 == i { n = split($2, a, ";SERVER="); if (a[2] != "") { print a[2]; exit } }')
        location=$(printf '%s\n' "$answers" | awk -F'\t' -v i="$ip" '$1 == i && $2 ~ /InternetGatewayDevice/ { split($2, a, ";LOCATION="); split(a[2], b, ";SERVER="); print b[1]; exit }')
        [ -n "$location" ] || location=$(printf '%s\n' "$answers" | awk -F'\t' -v i="$ip" '$1 == i { split($2, a, ";LOCATION="); split(a[2], b, ";SERVER="); if (b[1] != "") { print b[1]; exit } }')
        igd=false
        printf '%s\n' "$types" | grep -Eq 'InternetGatewayDevice|WANIPConnection|WANPPPConnection' && igd=true
        local isgw=false
        [ "$ip" = "$GATEWAY" ] && isgw=true
        msp_data_row 'UpnpDevices' IPAddress "$ip" IsGateway# "$isgw" InternetGateway# "$igd" Server "$server" Location "$location" DeviceTypes "$(printf '%s\n' "$types" | head -n 6 | paste -sd ';' - | sed 's/;/; /g')"
        if [ "$igd" = 'true' ]; then
            igd_list="$igd_list${igd_list:+, }$ip"
            if [ -z "$igd_location" ] || [ "$ip" = "$GATEWAY" ]; then igd_location=$location; fi
        else
            others="$others${others:+, }$ip"
        fi
    done
    if [ -n "$others" ]; then
        msp_finding --status INFO --category 'UPnP' --check 'UPnP devices' \
            --detail "$(printf '%s' "$others" | tr ',' '\n' | grep -c .) other device(s) announce themselves over UPnP (TVs, speakers, printers, NAS): $others"
    fi
    if [ -z "$igd_list" ]; then
        msp_finding --status PASS --category 'UPnP' --check 'Router UPnP' \
            --detail "No device answered as a UPnP Internet Gateway within ${SSDP_WAIT}s, so UPnP port opening appears to be off. (Some routers stay silent even with UPnP on; confirm in the checklist.)"
        return 0
    fi
    UPNP_ON=1
    msp_finding --status WARN --severity Medium --category 'UPnP' --check 'Router UPnP' --target "$GATEWAY" \
        --detail "UPnP is ON ($igd_list answered as an Internet Gateway Device). Any program or device on the network - including malware - can open ports to the internet without a password." \
        --rec 'Turn UPnP off in the router unless the client needs it (some game consoles do). If it stays on, keep every device updated.'

    # Device description (read-only), only from an address inside the local subnet.
    local host
    host=$(printf '%s' "$igd_location" | sed -n 's|^https\{0,1\}://\([^/:]*\).*|\1|p')
    [ -n "$host" ] && msp_ip_in_subnet "$host" || return 0
    msp_have curl || return 0
    http_get "$igd_location" || return 0
    local desc=$H_BODY parts='' v
    for v in friendlyName manufacturer modelName modelNumber; do
        local val
        val=$(xml_value "$desc" "$v")
        [ -n "$val" ] && case " / $parts / " in *" / $val / "*) ;; *) parts="$parts${parts:+ / }$val" ;; esac
    done
    [ -n "$parts" ] && msp_finding --status INFO --category 'UPnP' --check 'Router model (UPnP)' --target "$GATEWAY" --detail "$parts"
    # The WAN connection service: its type and control URL.
    local service control base control_url
    service=$(tr '\r\n' '  ' <"$desc" | grep -oE '<serviceType>[^<]*WAN(IP|PPP)Connection[^<]*</serviceType>[[:space:]]*<serviceId>[^<]*</serviceId>[[:space:]]*<controlURL>[^<]*</controlURL>' | head -n 1)
    [ -n "$service" ] || service=$(tr '\r\n' '  ' <"$desc" | grep -oE '<serviceType>[^<]*WAN(IP|PPP)Connection[^<]*</serviceType>.{0,400}<controlURL>[^<]*</controlURL>' | head -n 1)
    [ -n "$service" ] || return 0
    local stype
    stype=$(printf '%s' "$service" | sed -n 's|.*<serviceType>\([^<]*\)</serviceType>.*|\1|p')
    control=$(printf '%s' "$service" | sed -n 's|.*<controlURL>\([^<]*\)</controlURL>.*|\1|p' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
    base=$(xml_value "$desc" 'URLBase')
    [ -n "$base" ] || base=$(printf '%s' "$igd_location" | sed -n 's|^\(https\{0,1\}://[^/]*\).*|\1|p')
    base=${base%/}
    case "$control" in http*) control_url=$control ;; /*) control_url="$base$control" ;; *) control_url="$base/$control" ;; esac
    host=$(printf '%s' "$control_url" | sed -n 's|^https\{0,1\}://\([^/:]*\).*|\1|p')
    msp_ip_in_subnet "$host" || return 0

    soap() {
        # soap ACTION ARGUMENTS - one read-only UPnP query; the reply body is in $H_BODY.
        local body
        body="<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:$1 xmlns:u=\"$stype\">$2</u:$1></s:Body></s:Envelope>"
        http_get "$control_url" POST "$body" "$stype#$1" && [ "$H_CODE" = '200' ]
    }
    if soap GetExternalIPAddress ''; then
        local external
        external=$(xml_value "$H_BODY" 'NewExternalIPAddress')
        if printf '%s' "$external" | grep -Eq '^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.'; then
            msp_finding --status INFO --category 'UPnP' --check 'Internet address' --evidence "$(msp_json_obj ExternalIP "$external")" \
                --detail "The router's internet address $external is shared provider address space (carrier-grade NAT). Unsolicited connections from the internet generally cannot reach this network."
        elif [ -n "$external" ] && is_private "$external"; then
            msp_finding --status WARN --severity Low --category 'UPnP' --check 'Internet address' --evidence "$(msp_json_obj ExternalIP "$external")" \
                --detail "The router's \"internet\" address is private ($external): it sits behind another router or ISP modem (double NAT)." \
                --rec 'Check the security settings of BOTH devices, or put the ISP modem in bridge mode.'
        elif [ -n "$external" ]; then
            msp_finding --status INFO --category 'UPnP' --check 'Internet address' --evidence "$(msp_json_obj ExternalIP "$external")" \
                --detail "The router's public internet address is $external."
        fi
    fi
    local index=0 count=0 ext proto int iport enabled descr lease sev
    while [ "$index" -lt 64 ]; do
        soap GetGenericPortMappingEntry "<NewPortMappingIndex>$index</NewPortMappingIndex>" || break
        ext=$(xml_value "$H_BODY" NewExternalPort)
        proto=$(xml_value "$H_BODY" NewProtocol)
        int=$(xml_value "$H_BODY" NewInternalClient)
        iport=$(xml_value "$H_BODY" NewInternalPort)
        enabled=$(xml_value "$H_BODY" NewEnabled)
        descr=$(xml_value "$H_BODY" NewPortMappingDescription)
        lease=$(xml_value "$H_BODY" NewLeaseDuration)
        msp_data_row 'UpnpPortForwards' ExternalPort "$ext" Protocol "$proto" InternalIP "$int" InternalPort "$iport" Enabled "$enabled" Description "$descr" LeaseSeconds "$lease"
        printf '  %s/%s -> %s:%s  "%s"\n' "$ext" "$proto" "$int" "$iport" "$descr"
        sev='Medium'
        case "$iport" in 21 | 22 | 23 | 80 | 445 | 3389 | 5900 | 8080) sev='High' ;; esac
        case "$ext" in 21 | 22 | 23 | 80 | 445 | 3389 | 5900 | 8080) sev='High' ;; esac
        msp_finding --status WARN --severity "$sev" --category 'UPnP' --check "UPnP port forward $ext/$proto" --target "$int" \
            --detail "Internet port $ext/$proto is forwarded to $int:$iport (\"$descr\")." \
            --rec 'Identify the device and program. Remove the forward (turn UPnP off, or delete it in the router) unless the client needs it.' \
            --evidence "$(msp_json_obj ExternalPort "$ext" Protocol "$proto" InternalIP "$int" InternalPort "$iport")"
        count=$((count + 1))
        index=$((index + 1))
    done
    if [ "$count" -eq 0 ]; then
        msp_finding --status PASS --category 'UPnP' --check 'UPnP port forwards' --target "$GATEWAY" --detail 'The router reports no ports opened through UPnP right now.'
    fi
}
if [ -n "$GATEWAY" ]; then msp_check 'UPnP' 'UPnP discovery' check_upnp; fi

# =========================================================================================
msp_section 'Router checklist (check in the admin page with the client)'
# =========================================================================================
ADMIN_URL=$(printf '%s' "$ADMIN_ROWS" | awk -F'|' '$4 == "true" { print ($2 == "https" ? 0 : 1) "|" $1 }' | sort | head -n 1 | cut -d'|' -f2)
UPNP_HINT='automatic check: UPnP appears OFF'
[ "$UPNP_ON" -eq 1 ] && UPNP_HINT='automatic check: UPnP is ON'
# Id|Question|Severity|Status for "No"|Fix|Where|Extra question
CHECKLIST="AdminPassword|Has the router admin password been changed from the default on the router's label?|Critical|FAIL|Change the router admin password to a unique passphrase and store it in the client's password manager.|Administration / System / Management|
RemoteManagement|Is remote management (admin access from the internet / WAN) turned OFF?|High|FAIL|Turn off remote/WAN management. If the client relies on the vendor's app, make sure that account has a strong password and 2FA.|Administration / Remote Management|
WPS|Is WPS (push-button or PIN pairing) turned OFF?|Medium|WARN|Turn WPS off; the PIN method can be brute-forced.|Wireless / WPS|
Firmware|Is the firmware current (updated in the last 12 months, or automatic updates on)?|High|FAIL|Update the firmware and turn on automatic updates. If the vendor no longer releases updates for this model, plan to replace the router.|Administration / Firmware Update|Firmware version or date (optional, Enter to skip)
UPnP|Is UPnP turned OFF (or knowingly left on for a game console)? [$UPNP_HINT]|Medium|WARN|Turn UPnP off unless a device the client uses needs it.|Advanced / NAT / UPnP|
GuestIsolation|Do visitors and smart-home devices use a guest network that cannot reach the computers?|Low|WARN|Create a guest network with \"allow access to local network\" OFF, and move visitors and IoT devices to it.|Wireless / Guest Network|"

# Ask only when a person is at a terminal; otherwise record items as not verified.
CAN_PROMPT=0
if [ "$SKIP_PROMPT" -eq 0 ] && [ -t 0 ] && [ -t 1 ]; then CAN_PROMPT=1; fi
if [ -n "$ADMIN_URL" ]; then msp_say 1 "  Router admin page: $ADMIN_URL"; else msp_say 1 '  Router admin page: not found on common ports - try the address on the router'\''s label, or the vendor'\''s app.'; fi
if [ "$CAN_PROMPT" -eq 1 ]; then
    msp_say 1 '  Log in WITH THE CLIENT (they type the password; this script never asks for it).'
    msp_say 1 '  Answer each question: Y = yes, N = no, U = unknown / could not check (Enter = U).'
else
    msp_say 90 '  Checklist questions are not being asked (--skip-checklist-prompt or no interactive terminal).'
    msp_say 90 '  Each item is recorded as "Not verified"; run this script on its own to answer them.'
fi

while IFS='|' read -r c_id c_question c_sev c_no c_fix c_where c_extra; do
    [ -n "$c_id" ] || continue
    answer='U'
    note=''
    if [ "$CAN_PROMPT" -eq 1 ]; then
        printf '\n'
        msp_say 36 "  $c_question"
        msp_say 90 "     (usually under: $c_where)"
        while true; do
            printf '     Y/N/U: '
            read -r raw </dev/tty || raw=''
            raw=$(printf '%s' "$raw" | cut -c1 | tr '[:lower:]' '[:upper:]')
            [ -n "$raw" ] || raw='U'
            case "$raw" in Y | N | U) answer=$raw; break ;; esac
            msp_say 33 '     Please type Y, N or U.'
        done
        if [ -n "$c_extra" ]; then printf '     %s: ' "$c_extra"; read -r note </dev/tty || note=''; fi
    fi
    prompted=false
    [ "$CAN_PROMPT" -eq 1 ] && prompted=true
    ev=$(msp_json_obj Answer "$answer" Prompted# "$prompted" Note "$note")
    case "$answer" in
        Y) msp_finding --status PASS --category 'Checklist' --check "Checklist: $c_id" --target "$GATEWAY" --evidence "$ev" --detail "Confirmed by technician${note:+ ($note)}." ;;
        N) msp_finding --status "$c_no" --severity "$c_sev" --category 'Checklist' --check "Checklist: $c_id" --target "$GATEWAY" --evidence "$ev" \
            --detail "Technician answered No: $c_question${note:+ ($note)}" --rec "$c_fix" ;;
        *)
            how='Not verified.'
            [ "$CAN_PROMPT" -eq 1 ] && how='Could not be checked.'
            msp_finding --status INFO --category 'Checklist' --check "Checklist: $c_id" --target "$GATEWAY" --evidence "$ev" \
                --detail "$how $c_question Look under $c_where. If not: $c_fix"
            ;;
    esac
done <<EOF
$CHECKLIST
EOF

msp_complete "$OUTPUT"
exit 0
