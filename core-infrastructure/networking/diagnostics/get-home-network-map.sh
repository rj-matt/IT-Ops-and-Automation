#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2329  # The embedded helper defines globals and functions this script does not use; checks run through msp_check.
# get-home-network-map.sh - lists the devices on the local network (IP, MAC, vendor, hostname,
# likely device type) and flags devices that cannot be identified, so the client can confirm
# what each one is. macOS and Linux; the Windows version is Get-HomeNetworkMap.ps1.
#
# Usage:  bash get-home-network-map.sh [--passive | --skip-ping] [--skip-name-lookup]
#                                      [--max-parallel N] [--allow-large-subnet] [--output DIR]
#
# Options:
#   --passive             Send nothing on the network: read this computer's neighbor (ARP)
#                         table only, no pings, no hostname lookups. Finds fewer devices.
#   --skip-ping           No ping sweep; hostname lookups still go to the DNS server.
#   --skip-name-lookup    No hostname lookups (reverse DNS / mDNS through the system resolver).
#   --max-parallel N      Simultaneous pings, 1-32 (default 32).
#   --allow-large-subnet  Allow subnets from /22 up to /20.
#   --output DIR          Also save results as JSON and CSV (toolkit schema 2.0), with a Devices table.
#   --help                Show this help.
#
# What it does:
#   1. Works out the local subnet from the adapter that carries the default route. VPN and
#      virtual adapters are never used: if only a VPN has a gateway, nothing is scanned (SKIPPED).
#      The scope is PRINTED FIRST, before anything is sent.
#   2. Pings every address in that subnet, at most 32 at a time, about 1 second each.
#   3. Reads the neighbor (ARP) table: devices that ignore ping still answer ARP.
#   4. Looks up hostnames through the system resolver and gives a vendor hint from a small
#      built-in MAC prefix table. No internet lookups are made.
#   5. Guesses the device type and flags devices it cannot identify.
#   Safety limits: only the directly attached subnet; more than /22 (1,022 addresses) is refused
#   unless --allow-large-subnet, and nothing larger than /20 (4,094) is ever scanned. No ports
#   are scanned (see get-open-port-scan.sh --scan-lan).
#
# Examples:
#   bash get-home-network-map.sh --passive
#   bash get-home-network-map.sh --output ~/Desktop/Audit
#
# Purpose       : Inventory what is connected to the client's home network.
# Use Case      : Home network security audits; "is there something on my Wi-Fi I don't know?"
# Scope         : The local IPv4 subnet of the active adapter only. Prints scope before sending anything.
# Risk Level    : Read-Only -- sends ICMP echo (ping) and ARP to local addresses (nothing with
#                 --passive); changes nothing.
# Prerequisites : macOS 12+ or Linux with iproute2 | bash 3.2+ | root: No
# Version       : 1.0.0
# Limitations   : Devices that are asleep, on a guest/IoT network or another subnet are not
#                 seen. Vendor is a hint from a small table; "Unknown" does not mean malicious.
#                 Phones/tablets often use private (randomized) MACs. IPv6-only devices are not
#                 listed. Same checks and finding IDs as Get-HomeNetworkMap.ps1.

set -u
MSP_SCRIPT_FILE=$0

#region MSPToolkit (generated) Sections=Core,Net
# DO NOT EDIT — regenerate with Sync-MSPEmbeddedHelper.ps1
# Source: endpoint-systems/utilities/msp-toolkit-common.sh | Sections: Core,Net | SHA256: 8b0a39b6f1d44dfe10d316541a8ca96d75bce82def24957f4df55f0db051051d
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
SKIP_PING=0
SKIP_NAMES=0
MAX_PARALLEL=32
ALLOW_LARGE=0
while [ $# -gt 0 ]; do
    case "$1" in
        --output)
            OUTPUT=${2-}
            [ -n "$OUTPUT" ] || { printf 'Missing folder after --output\n' >&2; exit 2; }
            shift 2
            ;;
        --passive) SKIP_PING=1; SKIP_NAMES=1; shift ;;
        --skip-ping) SKIP_PING=1; shift ;;
        --skip-name-lookup) SKIP_NAMES=1; shift ;;
        --allow-large-subnet) ALLOW_LARGE=1; shift ;;
        --max-parallel)
            MAX_PARALLEL=${2-}
            case "$MAX_PARALLEL" in '' | *[!0-9]*) printf -- '--max-parallel needs a number from 1 to 32\n' >&2; exit 2 ;; esac
            if [ "$MAX_PARALLEL" -lt 1 ] || [ "$MAX_PARALLEL" -gt 32 ]; then printf -- '--max-parallel must be 1-32\n' >&2; exit 2; fi
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
msp_param SkipPing "$SKIP_PING"
msp_param SkipNameLookup "$SKIP_NAMES"
msp_param MaxParallel "$MAX_PARALLEL"
[ "$ALLOW_LARGE" -eq 1 ] && msp_param AllowLargeSubnet 1
msp_init 'get-home-network-map' "$SCRIPT_VERSION" 'A2' 'Read-Only' 'Local network device map (read-only)'

name_matches() {
    # name_matches NAME REGEX
    printf '%s' "$1" | grep -Eq "$2"
}

device_type_guess() {
    # device_type_guess IS_SELF IS_GATEWAY HOSTNAME VENDOR_HINT RANDOMIZED - same order of rules
    # as Get-DeviceTypeGuess in the Windows version.
    local name
    if [ "$1" = '1' ]; then printf 'This computer'; return; fi
    if [ "$2" = '1' ]; then printf 'Router / gateway'; return; fi
    name=$(printf '%s' "$3" | tr '[:upper:]' '[:lower:]')
    if [ -n "$name" ]; then
        if name_matches "$name" 'iphone|ipad|android|galaxy|pixel|oneplus|moto|phone'; then printf 'Phone / tablet'; return; fi
        if name_matches "$name" 'printer|officejet|laserjet|deskjet|envy|^hp[0-9a-f]{6}|^brn|^brw|epson|canon|^npi'; then printf 'Printer'; return; fi
        if name_matches "$name" 'roku|chromecast|appletv|apple-tv|firetv|fire-tv|shield|bravia|webos|tizen|-tv|tv-'; then printf 'TV / streaming'; return; fi
        if name_matches "$name" 'echo|alexa|google-home|googlehome|nest-|homepod|sonos'; then printf 'Smart speaker'; return; fi
        if name_matches "$name" 'camera|cam-|-cam|ring-|arlo|wyze|blink|dvr|nvr|ipc'; then printf 'Camera / recorder'; return; fi
        if name_matches "$name" 'xbox|playstation|ps4|ps5|nintendo|switch'; then printf 'Game console'; return; fi
        if name_matches "$name" 'nas|synology|diskstation|qnap|mycloud'; then printf 'NAS / file server'; return; fi
        if name_matches "$name" 'raspberrypi|raspberry'; then printf 'Single-board computer'; return; fi
        if name_matches "$name" 'desktop-|laptop-|macbook|imac|mac-mini|macmini|-pc$|^pc-|surface'; then printf 'Computer'; return; fi
    fi
    if [ "$5" = '1' ]; then printf 'Phone / tablet / laptop (private MAC)'; return; fi
    if [ -n "$4" ]; then printf '%s' "$4"; return; fi
    printf 'Unknown'
}

lookup_name() {
    # Reverse lookup through the system resolver (DNS, and mDNS on macOS). Prints "IP NAME".
    local ip=$1 name=''
    if [ "$MSP_PLATFORM" = 'macOS' ]; then
        name=$(msp_run_timeout 3 dscacheutil -q host -a ip_address "$ip" 2>/dev/null | awk '$1 == "name:" { print $2; exit }')
    else
        name=$(msp_run_timeout 3 getent hosts "$ip" 2>/dev/null | awk '{ print $2; exit }')
    fi
    name=${name%.}
    [ -n "$name" ] && [ "$name" != "$ip" ] && printf '%s %s\n' "$ip" "$name"
    return 0
}

# =========================================================================================
msp_section 'Scope'
# =========================================================================================
SUBNET_OK=0
find_subnet() {
    if msp_local_subnet; then
        SUBNET_OK=1
        return 0
    fi
    if [ "$MSP_NET_SKIP" -eq 1 ]; then
        msp_skip 'Scope' 'Local subnet' "$MSP_NET_ERROR" 'Disconnect the VPN (or connect to the client'\''s network directly) and run again.'
        return 0
    fi
    printf '%s\n' "$MSP_NET_ERROR" >&2
    return 1
}
msp_check 'Scope' 'Local subnet' find_subnet
if [ "$SUBNET_OK" -ne 1 ]; then
    msp_complete "$OUTPUT"
    exit 0
fi

FIRST_HOST=$(msp_int_to_ip $((MSP_NET_NETWORK_INT + 1)))
LAST_HOST=$(msp_int_to_ip $((MSP_NET_BROADCAST_INT - 1)))
METHOD="ICMP ping (about 1 s each, up to $MAX_PARALLEL at a time) + neighbor (ARP) table"
[ "$SKIP_PING" -eq 1 ] && METHOD='Existing neighbor (ARP) table only (no pings sent)'
if [ "$SKIP_NAMES" -eq 1 ]; then METHOD="$METHOD; no hostname lookups"; else METHOD="$METHOD + hostname lookups"; fi
if [ "$SKIP_PING" -eq 1 ] && [ "$SKIP_NAMES" -eq 1 ]; then METHOD='Passive: existing neighbor (ARP) table only; nothing is sent on the network'; fi

if [ "$SKIP_PING" -eq 1 ] && [ "$SKIP_NAMES" -eq 1 ]; then
    msp_say 1 '  Passive: nothing is sent; only this computer'\''s neighbor (ARP) table is read.'
else
    msp_say 1 '  Only the range below is contacted. No ports are scanned.'
fi
printf '    Adapter : %s\n' "$MSP_NET_IFACE"
printf '    This    : %s/%s\n' "$MSP_NET_IP" "$MSP_NET_PREFIX"
printf '    Range   : %s - %s  (%s addresses, subnet %s)\n' "$FIRST_HOST" "$LAST_HOST" "$MSP_NET_HOSTCOUNT" "$MSP_NET_CIDR"
printf '    Gateway : %s\n' "$MSP_NET_GATEWAY"
printf '    Method  : %s\n' "$METHOD"
if [ "$SKIP_NAMES" -eq 0 ]; then
    msp_say 90 "    Note    : hostname lookups go to this computer's DNS server(s): $(msp_dns_servers | paste -sd ',' - | sed 's/,/, /g')"
fi
msp_log INFO "Scope: $MSP_NET_CIDR ($MSP_NET_IFACE) range $FIRST_HOST-$LAST_HOST gateway $MSP_NET_GATEWAY; $METHOD"
msp_finding --status INFO --category 'Scope' --check 'Scan scope' \
    --detail "$MSP_NET_CIDR via $MSP_NET_IFACE ($MSP_NET_HOSTCOUNT addresses); gateway $MSP_NET_GATEWAY." \
    --evidence "$(msp_json_obj Cidr "$MSP_NET_CIDR" Adapter "$MSP_NET_IFACE" Gateway "$MSP_NET_GATEWAY" Method "$METHOD")"

# Hard safety limits: home networks are almost always /24 (254 addresses).
MAX_HOSTS=1022
[ "$ALLOW_LARGE" -eq 1 ] && MAX_HOSTS=4094
if [ "$MSP_NET_HOSTCOUNT" -gt "$MAX_HOSTS" ]; then
    advice='Re-run with --allow-large-subnet only if the client'\''s network really is this large (limit /20).'
    [ "$ALLOW_LARGE" -eq 1 ] && advice='This tool never scans more than 4,094 addresses. Use a dedicated network tool approved for this client.'
    msp_finding --status SKIPPED --category 'Scope' --check 'Device discovery' \
        --detail "Subnet $MSP_NET_CIDR has $MSP_NET_HOSTCOUNT addresses, above the $MAX_HOSTS-address safety limit. Nothing was scanned." \
        --rec "$advice"
    msp_complete "$OUTPUT"
    exit 0
fi

# =========================================================================================
msp_section 'Discovery'
# =========================================================================================
# Devices, as parallel arrays (bash 3.2 has no associative arrays).
D_COUNT=0
D_IP=()
D_MAC=()
D_PING=()
D_SELF=()
D_GW=()
D_NAME=()
D_VENDOR=()
D_RANDOM=()
D_TYPE=()
D_IDENT=()

device_index() {
    # Sets DEV_IDX to the index of IP, or -1.
    local i=0
    DEV_IDX=-1
    while [ "$i" -lt "$D_COUNT" ]; do
        if [ "${D_IP[$i]}" = "$1" ]; then DEV_IDX=$i; return 0; fi
        i=$((i + 1))
    done
    return 1
}

add_device() {
    # add_device IP MAC PING SELF
    local n=$D_COUNT gw=0
    [ "$1" = "$MSP_NET_GATEWAY" ] && gw=1
    D_IP[n]=$1
    D_MAC[n]=$2
    D_PING[n]=$3
    D_SELF[n]=$4
    D_GW[n]=$gw
    D_NAME[n]=''
    D_COUNT=$((n + 1))
}

discover() {
    local pingdir="$MSP_WORK_DIR/ping" replies='' ip mac
    if [ "$SKIP_PING" -eq 0 ]; then
        mkdir -p "$pingdir"
        printf '  Pinging %s addresses... (about %s seconds)\n' "$MSP_NET_HOSTCOUNT" $((MSP_NET_HOSTCOUNT / MAX_PARALLEL + 2))
        msp_subnet_hosts | msp_parallel "$MAX_PARALLEL" "$pingdir" msp_ping
        replies=$(cat "$pingdir"/*.out 2>/dev/null)
        # Give late ARP replies a moment to land in the neighbor table.
        sleep 1
    fi
    while read -r ip mac; do
        [ -n "$ip" ] || continue
        [ "$ip" = "$MSP_NET_IP" ] && continue
        device_index "$ip" && continue
        if printf '%s\n' "$replies" | grep -qx "$ip"; then add_device "$ip" "$mac" 1 0; else add_device "$ip" "$mac" 0 0; fi
    done <<EOF
$(msp_neighbors)
EOF
    # Answered ping but has no ARP entry (rare).
    for ip in $replies; do
        [ "$ip" = "$MSP_NET_IP" ] && continue
        device_index "$ip" || add_device "$ip" '' 1 0
    done
    add_device "$MSP_NET_IP" "$MSP_NET_MAC" 1 1
    D_NAME[D_COUNT - 1]=$MSP_HOST

    if [ "$SKIP_NAMES" -eq 0 ]; then
        printf '  Found %s device(s). Looking up names...\n' "$D_COUNT"
        local namedir="$MSP_WORK_DIR/names" i=0 line
        mkdir -p "$namedir"
        while [ "$i" -lt "$D_COUNT" ]; do
            [ "${D_SELF[$i]}" = '1' ] || printf '%s\n' "${D_IP[$i]}"
            i=$((i + 1))
        done | msp_parallel 16 "$namedir" lookup_name
        while read -r ip line; do
            [ -n "$ip" ] && device_index "$ip" && D_NAME[DEV_IDX]=$line
        done <<EOF
$(cat "$namedir"/*.out 2>/dev/null)
EOF
    else
        printf '  Found %s device(s). Hostname lookups skipped.\n' "$D_COUNT"
    fi

    local i=0 ident
    while [ "$i" -lt "$D_COUNT" ]; do
        msp_mac_vendor "${D_MAC[$i]}"
        D_VENDOR[i]=$MSP_VENDOR
        D_RANDOM[i]=$MSP_VENDOR_RANDOM
        D_TYPE[i]=$(device_type_guess "${D_SELF[$i]}" "${D_GW[$i]}" "${D_NAME[$i]}" "$MSP_VENDOR_HINT" "$MSP_VENDOR_RANDOM")
        ident=0
        if [ "${D_SELF[$i]}" = '1' ] || [ "${D_GW[$i]}" = '1' ] || [ -n "${D_NAME[$i]}" ] || [ "$MSP_VENDOR" != 'Unknown' ]; then ident=1; fi
        D_IDENT[i]=$ident
        i=$((i + 1))
    done
}
msp_check 'Discovery' 'Device discovery' discover

tf() { if [ "$1" = '1' ]; then printf 'true'; else printf 'false'; fi; }

# Sorted by IP address.
ORDER=$(i=0; while [ "$i" -lt "$D_COUNT" ]; do printf '%s %s\n' "$(msp_ip_to_int "${D_IP[$i]}")" "$i"; i=$((i + 1)); done | sort -n | awk '{ print $2 }')

if [ "$D_COUNT" -gt 0 ]; then
    printf '\n  %-15s  %-17s  %-24s  %-26s  %-30s  %-4s  %s\n' 'IPAddress' 'MacAddress' 'Vendor' 'Hostname' 'DeviceType' 'Ping' 'Flag'
    for i in $ORDER; do
        flag=''
        if [ "${D_IDENT[$i]}" = '0' ]; then flag='UNIDENTIFIED'; elif [ "${D_RANDOM[$i]}" = '1' ] && [ -z "${D_NAME[$i]}" ]; then flag='confirm'; fi
        ping_text='no'
        [ "${D_PING[$i]}" = '1' ] && ping_text='yes'
        printf '  %-15s  %-17s  %-24.24s  %-26.26s  %-30.30s  %-4s  %s\n' "${D_IP[$i]}" "${D_MAC[$i]}" "${D_VENDOR[$i]}" "${D_NAME[$i]}" "${D_TYPE[$i]}" "$ping_text" "$flag"
        msp_data_row 'Devices' IPAddress "${D_IP[$i]}" MacAddress "${D_MAC[$i]}" Vendor "${D_VENDOR[$i]}" Hostname "${D_NAME[$i]}" \
            DeviceType "${D_TYPE[$i]}" RespondedToPing# "$(tf "${D_PING[$i]}")" RandomizedMac# "$(tf "${D_RANDOM[$i]}")" \
            Identified# "$(tf "${D_IDENT[$i]}")" IsGateway# "$(tf "${D_GW[$i]}")" IsSelf# "$(tf "${D_SELF[$i]}")"
    done

    # =====================================================================================
    msp_section 'Findings'
    # =====================================================================================
    breakdown=$(for i in $ORDER; do printf '%s\n' "${D_TYPE[$i]}"; done | sort | uniq -c | sort -rn | awk '{ c = $1; $1 = ""; sub(/^ /, ""); printf "%s%s: %s", (NR > 1 ? "; " : ""), $0, c }')
    if [ "$D_COUNT" -gt 1 ]; then
        msp_finding --status INFO --category 'Discovery' --check 'Devices found' --detail "$D_COUNT device(s). $breakdown" \
            --evidence "$(msp_json_obj Count# "$D_COUNT" Breakdown "$breakdown")"
    fi

    private=''
    private_count=0
    cameras=''
    camera_count=0
    iot_count=0
    for i in $ORDER; do
        if [ "${D_GW[$i]}" = '1' ]; then
            msp_finding --status INFO --category 'Discovery' --check 'Router / gateway' --target "${D_IP[$i]}" \
                --detail "${D_IP[$i]}, MAC ${D_MAC[$i]:-unknown}, vendor hint: ${D_VENDOR[$i]}."
        fi
        if [ "${D_IDENT[$i]}" = '0' ]; then
            msp_finding --status WARN --severity Low --category 'Discovery' --check 'Unidentified device' --target "${D_IP[$i]}" \
                --id "A2.Unidentified.$(msp_id_part "${D_MAC[$i]}")" \
                --detail "${D_IP[$i]} (MAC ${D_MAC[$i]:-unknown}): no hostname and vendor not in the built-in table." \
                --rec 'Ask the client what this is (check the router'\''s device list, or unplug devices one at a time). Unknown does not mean malicious.'
        fi
        if [ "${D_RANDOM[$i]}" = '1' ] && [ -z "${D_NAME[$i]}" ]; then
            private="$private${private:+, }${D_IP[$i]}"
            private_count=$((private_count + 1))
        fi
        case "${D_TYPE[$i]}" in Camera* | 'Security camera'*)
            cameras="$cameras${cameras:+, }${D_IP[$i]}"
            camera_count=$((camera_count + 1))
            ;;
        esac
        if printf '%s' "${D_TYPE[$i]}" | grep -Eq 'IoT|Smart|Thermostat|Garage|lighting|speaker'; then iot_count=$((iot_count + 1)); fi
    done
    if [ "$private_count" -gt 0 ]; then
        msp_finding --status INFO --category 'Discovery' --check 'Devices with private MAC addresses' \
            --detail "$private_count device(s) use private/randomized MACs (normal for phones, tablets and laptops): $private." \
            --rec 'Ask the client to confirm the number of phones/tablets/laptops in the home roughly matches.'
    fi
    # One MAC answering for several IPs is usually harmless but is also what ARP spoofing looks like.
    for mac in $(for i in $ORDER; do [ -n "${D_MAC[$i]}" ] && printf '%s\n' "${D_MAC[$i]}"; done | sort | uniq -d); do
        ips=$(for i in $ORDER; do [ "${D_MAC[$i]}" = "$mac" ] && printf '%s\n' "${D_IP[$i]}"; done | paste -sd ',' - | sed 's/,/, /g')
        msp_finding --status INFO --category 'Discovery' --check 'Same MAC on several IPs' --target "$mac" \
            --id "A2.SharedMac.$(msp_id_part "$mac")" \
            --detail "MAC $mac answers for $ips. Usually normal (router proxy-ARP or a multi-address device)." \
            --rec 'Only investigate if one of these IPs is supposed to be a different physical device.'
    done
    if [ "$camera_count" -gt 0 ]; then
        msp_finding --status WARN --severity Low --category 'IoT' --check 'Cameras / recorders on the network' \
            --detail "$camera_count camera/recorder device(s): $cameras. These are common attack targets." \
            --rec 'Confirm default passwords were changed, firmware is current, and the router does not forward ports to them.'
    fi
    if [ "$iot_count" -gt 0 ]; then
        msp_finding --status INFO --category 'IoT' --check 'Smart-home / IoT devices' \
            --detail "$iot_count smart-home device(s) on the same network as computers." \
            --rec 'If the router supports it, put smart-home devices on a separate guest/IoT network.'
    fi
fi
if [ "$D_COUNT" -le 1 ]; then
    detail='No other devices were found. Ping or ARP may be blocked, or the computer is isolated (guest network / client isolation).'
    [ "$SKIP_PING" -eq 1 ] && detail='No other devices are in the neighbor table yet (passive mode sends nothing, so only devices this computer already talked to are listed).'
    msp_finding --status WARN --severity Low --category 'Discovery' --check 'Devices found' --detail "$detail" \
        --rec 'Confirm the computer is on the client'\''s main network, not a guest network.'
fi

msp_finding --status INFO --category 'Discovery' --check 'Coverage note' --quiet \
    --detail 'Sleeping devices, devices on a guest/IoT network and IPv6-only devices are not listed. Compare with the router'\''s client list.'

msp_complete "$OUTPUT"
exit 0
