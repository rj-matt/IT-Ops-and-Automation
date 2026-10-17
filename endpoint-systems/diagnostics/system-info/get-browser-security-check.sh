#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2329  # The embedded helper defines globals and functions this script does not use; checks run through msp_check.
# get-browser-security-check.sh - read-only browser check for macOS and Linux: Chrome, Edge,
# Brave, Chromium and Firefox versions (flagging ones that look out of date), installed
# extensions by name and ID, and policies that block updates or force-install extensions. On
# macOS also Safari's version and extensions. Browser passwords, cookies and history are never
# opened. The Windows version is Get-BrowserSecurityCheck.ps1.
#
# Usage:  bash get-browser-security-check.sh [--all-users] [--chromium-latest N]
#                                            [--firefox-latest N] [--output DIR]
#
# Options:
#   --all-users          Also check every other user's browser profiles. Needs root (sudo).
#   --chromium-latest N  Current Chrome/Edge major version, if you looked it up (overrides the estimate).
#   --firefox-latest N   Current Firefox major version, if you looked it up.
#   --output DIR         Also save results as JSON and CSV (toolkit schema 2.0), with Browsers
#                        and Extensions tables.
#   --help               Show this help.
#
# Versions: read from the app (macOS Info.plist; Linux package database or application.ini).
#   Without internet access the current version is ESTIMATED from each browser's release
#   schedule (a new major version every 4 weeks) and raised to the newest stable install found;
#   browsers several releases behind are flagged. Confirm in the browser's About page.
# Extensions: each Chromium profile's Extensions/*/manifest.json and Firefox's extensions.json
#   (an add-on list; it holds no passwords or browsing data). Flags extensions not from the
#   official store and lists ones that can read every website.
# Policies: macOS /Library/Managed Preferences and Firefox policies.json; Linux
#   /etc/opt/chrome, /etc/opt/edge, /etc/brave, /etc/chromium policy folders and Firefox
#   policies.json. Force-installed extensions and disabled updates are flagged.
# NEVER opened: Login Data, Cookies, History, Web Data, logins.json, key4.db, cookies.sqlite,
#   places.sqlite, Safari's History.db, or any other credential/history store.
#
# Examples:
#   bash get-browser-security-check.sh
#   sudo bash get-browser-security-check.sh --all-users --output ~/Desktop/Audit
#
# Purpose       : Find out-of-date browsers and unwanted extensions without touching private data.
# Use Case      : Home network security audits; pop-ups, redirects or "my browser is acting strange".
# Scope         : This computer. Current user's browser profiles (all users with --all-users as root).
# Risk Level    : Read-Only -- reads program versions, extension manifests and policy files only.
# Prerequisites : macOS 12+ or Linux | bash 3.2+ | root: No (Yes for --all-users)
# Version       : 1.0.0
# Limitations   : "Out of date" is an estimate unless exact versions are supplied. Extension
#                 names come from the extension's own manifest. Linux: Flatpak Chromium-based
#                 browsers are not version-checked; snap and Flatpak Firefox are. Opera and
#                 Vivaldi are not checked. Same checks and finding IDs as the Windows version.

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
ALL_USERS=0
CHROMIUM_LATEST=''
FIREFOX_LATEST=''
while [ $# -gt 0 ]; do
    case "$1" in
        --output)
            OUTPUT=${2-}
            [ -n "$OUTPUT" ] || { printf 'Missing folder after --output\n' >&2; exit 2; }
            shift 2
            ;;
        --all-users) ALL_USERS=1; shift ;;
        --chromium-latest | --firefox-latest)
            case "${2-}" in '' | *[!0-9]*) printf '%s needs a version number\n' "$1" >&2; exit 2 ;; esac
            if [ "$2" -lt 100 ] || [ "$2" -gt 400 ]; then printf '%s must be 100-400\n' "$1" >&2; exit 2; fi
            if [ "$1" = '--chromium-latest' ]; then CHROMIUM_LATEST=$2; else FIREFOX_LATEST=$2; fi
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
[ "$ALL_USERS" -eq 1 ] && msp_param AllUsers 1
[ -n "$CHROMIUM_LATEST" ] && msp_param ChromiumLatestMajor "$CHROMIUM_LATEST"
[ -n "$FIREFOX_LATEST" ] && msp_param FirefoxLatestMajor "$FIREFOX_LATEST"
msp_init 'get-browser-security-check' "$SCRIPT_VERSION" 'A5' 'Read-Only' \
    'Browser versions, extensions and policies (read-only; no passwords, cookies or history)' 'other users'' profiles (--all-users)'

ROOT=${MSP_TEST_ROOT:-}
NOW=$(date +%s)
STORE_PATTERN='^https://(clients2\.google\.com|edge\.microsoft\.com|extensionupdater\.brave\.com|go-updater\.brave\.com)/'

file_mtime() {
    if [ "$MSP_PLATFORM" = 'macOS' ]; then stat -f %m "$1" 2>/dev/null; else stat -c %Y "$1" 2>/dev/null; fi # linux-only: stat -c
}

# --- Release-schedule estimate ---------------------------------------------------------------
# Same anchors as the Windows version: Chrome 140 stable = 2025-09-02, Firefox 144 = 2025-10-14,
# one major version every 28 days. The newest stable install found raises a low estimate.
estimated_major() {
    case "$1" in
        Chromium)
            if [ -n "$CHROMIUM_LATEST" ]; then printf '%s 0' "$CHROMIUM_LATEST"; return; fi
            printf '%s 1' $((140 + (NOW - 1756771200) / 86400 / 28))
            ;;
        *)
            if [ -n "$FIREFOX_LATEST" ]; then printf '%s 0' "$FIREFOX_LATEST"; return; fi
            printf '%s 1' $((144 + (NOW - 1760400000) / 86400 / 28))
            ;;
    esac
}

# Firefox ESR majors and the approximate month support ends (epoch), as in the Windows version.
esr_end() {
    case "$1" in
        115) printf '1772323200 2026-03' ;;
        128) printf '1756684800 2025-09' ;;
        140) printf '1788220800 2026-09' ;;
        153) printf '1819756800 2027-09' ;;
    esac
}

# --- Browsers on this platform ---------------------------------------------------------------
# One line each: Name|Family|Prerelease|version source|profile folder (relative to the user's
# home)|policy location. version source: macOS app path; Linux "pkg:<names>" or "ini:<paths>".
if [ "$MSP_PLATFORM" = 'macOS' ]; then
    BROWSERS='Google Chrome|Chromium|0|Google Chrome.app|Library/Application Support/Google/Chrome|com.google.Chrome
Microsoft Edge|Chromium|0|Microsoft Edge.app|Library/Application Support/Microsoft Edge|com.microsoft.Edge
Brave|Chromium|0|Brave Browser.app|Library/Application Support/BraveSoftware/Brave-Browser|com.brave.Browser
Chromium|Chromium|0|Chromium.app|Library/Application Support/Chromium|org.chromium.Chromium
Mozilla Firefox|Firefox|0|Firefox.app|Library/Application Support/Firefox/Profiles|org.mozilla.firefox
Firefox Developer Edition|Firefox|1|Firefox Developer Edition.app||org.mozilla.firefox'
else
    BROWSERS='Google Chrome|Chromium|0|pkg:google-chrome-stable|.config/google-chrome|/etc/opt/chrome/policies/managed
Microsoft Edge|Chromium|0|pkg:microsoft-edge-stable|.config/microsoft-edge|/etc/opt/edge/policies/managed
Brave|Chromium|0|pkg:brave-browser|.config/BraveSoftware/Brave-Browser|/etc/brave/policies/managed
Chromium|Chromium|0|pkg:chromium chromium-browser snap:chromium|.config/chromium:snap/chromium/common/chromium|/etc/chromium/policies/managed:/etc/chromium-browser/policies/managed
Mozilla Firefox|Firefox|0|ini:/usr/lib/firefox:/usr/lib64/firefox:/opt/firefox:/snap/firefox/current/usr/lib/firefox:/var/lib/flatpak/app/org.mozilla.firefox/current/active/files/lib/firefox|.mozilla/firefox:snap/firefox/common/.mozilla/firefox:.var/app/org.mozilla.firefox/.mozilla/firefox|/etc/firefox/policies'
fi

# --- Which users ---------------------------------------------------------------------------------
USER_LIST=''   # "name|home" per line
add_user() { USER_LIST="$USER_LIST$1|$2
"; }
SELF=${SUDO_USER:-$MSP_USER}
SELF_HOME=$HOME
if [ -n "${SUDO_USER:-}" ]; then
    if [ "$MSP_PLATFORM" = 'macOS' ]; then SELF_HOME=$(dscl . -read "/Users/$SUDO_USER" NFSHomeDirectory 2>/dev/null | awk '{ print $2 }')
    else SELF_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6); fi
fi
add_user "$SELF" "$ROOT$SELF_HOME"
if [ "$ALL_USERS" -eq 1 ]; then
    list_other_users() {
        local name home
        if [ "$MSP_PLATFORM" = 'macOS' ]; then
            for home in "$ROOT"/Users/*; do
                name=${home##*/}
                case "$name" in Shared | Guest | .*) continue ;; esac
                [ "$name" = "$SELF" ] || add_user "$name" "$home"
            done
        else
            while IFS=: read -r name _ uid _ _ home _; do
                [ "$uid" -ge 1000 ] 2>/dev/null && [ "$uid" -lt 60000 ] && [ "$name" != "$SELF" ] && [ -d "$ROOT$home" ] && add_user "$name" "$ROOT$home"
            done <<EOF
$(getent passwd)
EOF
        fi
        msp_finding --status INFO --category 'Scope' --check "Other users' browser profiles" --detail "Checking $(printf '%s' "$USER_LIST" | grep -c .) user profile(s)."
    }
    msp_check --root "Other users' profile folders are protected." 'Scope' "Other users' browser profiles" list_other_users
fi

# =========================================================================================
msp_section 'Browser versions'
# =========================================================================================
INSTALLS=''    # "Name|Family|Prerelease|Version|Major|Path|AgeDays|Esr" per line

browser_version() {
    # browser_version SOURCE -> "version|path|mtime" of the first install found, or nothing.
    local src=$1 app part pkg dir v
    if [ "$MSP_PLATFORM" = 'macOS' ]; then
        for app in "$ROOT/Applications/$src" "$ROOT$SELF_HOME/Applications/$src"; do
            [ -f "$app/Contents/Info.plist" ] || continue
            v=$(defaults read "$app/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null)
            [ -n "$v" ] && printf '%s|%s|%s\n' "$v" "$app" "$(file_mtime "$app/Contents/Info.plist")" && return 0
        done
        return 0
    fi
    for part in $src; do
        case "$part" in
            pkg:*)
                for pkg in $(printf '%s' "${part#pkg:}" | tr ':' ' '); do
                    v=''
                    if msp_have dpkg-query; then v=$(dpkg-query -W -f '${Status} ${Version}\n' "$pkg" 2>/dev/null | awk '$3 == "installed" { print $4 }'); fi
                    if [ -z "$v" ] && msp_have rpm; then v=$(rpm -q --qf '%{VERSION}\n' "$pkg" 2>/dev/null | grep -v 'not installed' | head -n 1); fi
                    v=${v#*:}
                    [ -n "$v" ] && printf '%s|package %s|%s\n' "$v" "$pkg" "$(file_mtime "$ROOT/var/lib/dpkg/info/$pkg.list" || true)" && return 0
                done
                ;;
            snap:*)
                if msp_have snap; then
                    v=$(snap list "${part#snap:}" 2>/dev/null | awk 'NR == 2 { print $2 }')
                    [ -n "$v" ] && printf '%s|snap %s|\n' "$v" "${part#snap:}" && return 0
                fi
                ;;
            ini:*)
                for dir in $(printf '%s' "${part#ini:}" | tr ':' ' '); do
                    [ -f "$ROOT$dir/application.ini" ] || continue
                    v=$(sed -n 's/^Version=//p' "$ROOT$dir/application.ini" | head -n 1)
                    [ -n "$v" ] && printf '%s|%s|%s\n' "$v" "$ROOT$dir" "$(file_mtime "$ROOT$dir/application.ini")" && return 0
                done
                ;;
        esac
    done
    return 0
}

find_browsers() {
    local name family pre src rest found v path mt major age esr
    while IFS='|' read -r name family pre src rest; do
        [ -n "$name" ] || continue
        found=$(browser_version "$src")
        [ -n "$found" ] || continue
        IFS='|' read -r v path mt <<EOF
$found
EOF
        major=$(printf '%s' "$v" | sed 's/[^0-9].*//')
        [ -n "$major" ] || major=0
        age=''
        [ -n "$mt" ] && age=$(((NOW - mt) / 86400))
        esr=0
        # Firefox records its release channel ("release", "esr") next to the program.
        if [ "$family" = 'Firefox' ]; then
            local prefs="$path/defaults/pref/channel-prefs.js"
            [ "$MSP_PLATFORM" = 'macOS' ] && prefs="$path/Contents/Resources/defaults/pref/channel-prefs.js"
            if grep -qs '"esr"' "$prefs"; then esr=1; fi
            case "$v" in *esr*) esr=1 ;; esac
        fi
        INSTALLS="$INSTALLS$name|$family|$pre|$v|$major|$path|$age|$esr
"
    done <<EOF
$BROWSERS
EOF
}
msp_check 'Version' 'Find installed browsers' find_browsers

newest_stable() {
    printf '%s' "$INSTALLS" | awk -F'|' -v f="$1" '$2 == f && $3 == "0" && $5 + 0 > m { m = $5 + 0 } END { print m + 0 }'
}

rate_browser() {
    local name=$1 family=$2 v=$3 major=$4 path=$5 age=$6 esr=$7
    local est latest estimated newest behind basis check ev
    est=$(estimated_major "$family")
    latest=${est% *}
    estimated=${est#* }
    newest=$(newest_stable "$family")
    if [ "$estimated" = '1' ] && [ "$newest" -gt "$latest" ]; then latest=$newest; fi
    behind=$((latest - major))
    [ "$behind" -lt 0 ] && behind=0
    basis='current'
    [ "$estimated" = '1' ] && basis='estimated current'
    local est_tf=false
    [ "$estimated" = '1' ] && est_tf=true
    msp_data_row 'Browsers' Browser "$name" Version "$v" Path "$path" FileAgeDays "$age" ExpectedMajor# "$latest" ExpectedEstimate# "$est_tf" ReleasesBehind# "$behind"
    ev=$(msp_json_obj Version "$v" ExpectedMajor# "$latest" Estimated# "$est_tf" FileAgeDays "$age" Path "$path")
    check="$name version"
    if [ "$esr" = '1' ]; then
        local end
        end=$(esr_end "$major")
        if [ -z "$end" ]; then
            msp_finding --status WARN --severity Low --category 'Version' --check "$check" --evidence "$ev" \
                --detail "$v is Extended Support Release $major, which this script has no support date for." \
                --rec 'Check the ESR support date at mozilla.org, or switch to the regular Firefox release.'
        elif [ "$NOW" -gt "${end% *}" ]; then
            msp_finding --status WARN --severity Medium --category 'Version' --check "$check" --evidence "$ev" \
                --detail "$v is Extended Support Release $major, whose support was due to end around ${end#* }." \
                --rec 'Confirm at mozilla.org whether this ESR branch still gets security fixes; if not, update to the current release.'
        else
            msp_finding --status PASS --category 'Version' --check "$check" --evidence "$ev" \
                --detail "$v (Extended Support Release $major, supported until about ${end#* })."
        fi
        return 0
    fi
    local how='Open the browser'\''s Settings > About page to update it.'
    if [ "$MSP_PLATFORM" = 'Linux' ]; then how='Install updates with the system updater (Software Updater / dnf / snap refresh), then restart the browser.'; fi
    if [ "$behind" -ge 4 ]; then
        msp_finding --status FAIL --severity High --category 'Version' --check "$check" --evidence "$ev" \
            --detail "$v is about $behind releases behind the $basis version $latest. It is missing security fixes${age:+; the program was last updated $age days ago}." \
            --rec "$how If it will not update, check the policy results below."
    elif [ "$behind" -ge 2 ]; then
        msp_finding --status WARN --severity Medium --category 'Version' --check "$check" --evidence "$ev" \
            --detail "$v may be $behind releases behind the $basis version $latest." --rec "$how"
    else
        msp_finding --status PASS --category 'Version' --check "$check" --evidence "$ev" \
            --detail "$v (up to date with the $basis version $latest)."
    fi
}

while IFS='|' read -r name family pre v major path age esr; do
    [ -n "$name" ] || continue
    msp_check 'Version' "$name version" rate_browser "$name" "$family" "$v" "$major" "$path" "$age" "$esr" </dev/null
done <<EOF
$INSTALLS
EOF

check_safari() {
    local app="$ROOT/Applications/Safari.app" v
    [ -f "$app/Contents/Info.plist" ] || return 0
    v=$(defaults read "$app/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null)
    msp_data_row 'Browsers' Browser 'Safari' Version "$v" Path "$app" FileAgeDays '' ExpectedMajor# 0 ExpectedEstimate# true ReleasesBehind# 0
    msp_finding --status INFO --category 'Version' --check 'Safari version' \
        --detail "$v. Safari is updated with macOS, so it is current when macOS updates are (see the A1 and A6 results)."
}
if [ "$MSP_PLATFORM" = 'macOS' ]; then msp_check 'Version' 'Safari version' check_safari; fi
if [ -z "$INSTALLS" ]; then
    msp_finding --status INFO --category 'Version' --check 'Browsers found' --detail 'Chrome, Edge, Brave, Chromium and Firefox were not found in their standard locations.'
fi

# =========================================================================================
msp_section 'Extensions'
# =========================================================================================
EXT_ROWS="${MSP_WORK_DIR:-${TMPDIR:-/tmp}}/ext-rows.txt"   # Browser|User|Profile|Name|Id|Version|Enabled|FromStore|Source|AllSites
: >"$EXT_ROWS"

chromium_name() {
    # Display name, resolving "__MSG_key__" from _locales/<default_locale|en|en_US>/messages.json.
    local flat=$1 dir=$2 name key loc file
    name=$(printf '%s\n' "$flat" | awk -F'\t' '$1 == ".name" { print $2; exit }')
    case "$name" in
        __MSG_*__)
            key=${name#__MSG_}
            key=${key%__}
            for loc in "$(printf '%s\n' "$flat" | awk -F'\t' '$1 == ".default_locale" { print $2; exit }')" en en_US; do
                file="$dir/_locales/$loc/messages.json"
                [ -n "$loc" ] && [ -f "$file" ] || continue
                local m
                m=$(msp_json_flatten "$file" | awk -F'\t' -v k="$key" 'tolower($1) == "." tolower(k) ".message" { print $2; exit }')
                if [ -n "$m" ]; then printf '%s' "$m"; return; fi
            done
            ;;
    esac
    printf '%s' "$name"
}

scan_chromium() {
    # scan_chromium BROWSER USER PROFILE_ROOT
    local browser=$1 user=$2 root=$3 prof ext ver manifest flat name version update all from
    for prof in "$root"/Default "$root"/Profile\ *; do
        [ -d "$prof/Extensions" ] || continue
        for ext in "$prof/Extensions"/*; do
            case "${ext##*/}" in [a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p][a-p]) ;; *) continue ;; esac
            # Newest version folder (names are extension versions such as 1.62.0_0).
            # shellcheck disable=SC2012
            ver=$(ls -t "$ext" 2>/dev/null | head -n 1)
            manifest="$ext/$ver/manifest.json"
            [ -n "$ver" ] && [ -f "$manifest" ] || continue
            flat=$(msp_json_flatten "$manifest")
            name=$(chromium_name "$flat" "$ext/$ver")
            version=$(printf '%s\n' "$flat" | awk -F'\t' '$1 == ".version" { print $2; exit }')
            update=$(printf '%s\n' "$flat" | awk -F'\t' '$1 == ".update_url" { print $2; exit }')
            all=false
            if printf '%s\n' "$flat" | awk -F'\t' '$1 ~ /^\.(permissions|host_permissions|optional_permissions)\[/ && ($2 == "<all_urls>" || $2 ~ /^(\*|https?):\/\/\*\//) { f = 1 } END { exit !f }'; then all=true; fi
            from=false
            if printf '%s' "$update" | grep -Eq "$STORE_PATTERN"; then from=true; fi
            printf '%s|%s|%s|%s|%s|%s|Unknown|%s|%s|%s\n' "$browser" "$user" "${prof##*/}" "$name" "${ext##*/}" "$version" "$from" "$update" "$all" >>"$EXT_ROWS"
        done
    done
}

scan_firefox() {
    # scan_firefox BROWSER USER PROFILES_DIR - extensions.json lists add-ons; no private data.
    local browser=$1 user=$2 root=$3 prof
    for prof in "$root"/*/; do
        prof=${prof%/}
        [ -f "$prof/extensions.json" ] || continue
        msp_json_flatten "$prof/extensions.json" | awk -F'\t' -v b="$browser" -v u="$user" -v p="${prof##*/}" '
            match($1, /^\.addons\[[0-9]+\]/) {
                i = substr($1, 9, RLENGTH - 9); k = substr($1, RLENGTH + 1)
                if (!(i in seen)) { seen[i] = 1; order[++n] = i }
                if (k == ".type") type[i] = $2
                else if (k == ".id") id[i] = $2
                else if (k == ".version") ver[i] = $2
                else if (k == ".active") act[i] = $2
                else if (k == ".location") loc[i] = $2
                else if (k == ".signedState") sig[i] = $2
                else if (k == ".defaultLocale.name") nm[i] = $2
                else if (k ~ /^\.userPermissions\.origins\[/ && ($2 == "<all_urls>" || $2 ~ /^\*:\/\/\*\//)) all[i] = 1
            }
            END {
                for (j = 1; j <= n; j++) {
                    i = order[j]
                    if (type[i] != "extension") continue
                    # Built-in Mozilla components are not user-installed extensions.
                    if (loc[i] ~ /^app-builtin/ || loc[i] ~ /^app-system/ || loc[i] == "app-profile-builtin") continue
                    name = (nm[i] != "" ? nm[i] : id[i])
                    store = (sig[i] + 0 >= 2 && loc[i] == "app-profile") ? "true" : "false"
                    printf "%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n", b, u, p, name, id[i], ver[i], act[i], store, loc[i], (all[i] ? "true" : "false")
                }
            }' >>"$EXT_ROWS"
    done
}

report_extensions() {
    # report_extensions BROWSER USER - findings for the rows just collected for this browser/user.
    local browser=$1 user=$2 label="$1 extensions ($2)" rows unique names profiles
    rows=$(awk -F'|' -v b="$browser" -v u="$user" '$1 == b && $2 == u' "$EXT_ROWS")
    if [ -z "$rows" ]; then
        msp_finding --status PASS --category 'Extensions' --check "$label" --detail 'No extensions installed.'
        return 0
    fi
    unique=$(printf '%s\n' "$rows" | cut -d'|' -f5 | sort -u | grep -c .)
    profiles=$(printf '%s\n' "$rows" | cut -d'|' -f3 | sort -u | grep -c .)
    names=$(printf '%s\n' "$rows" | cut -d'|' -f4 | awk '!s[$0]++' | paste -sd ';' - | sed 's/;/; /g')
    msp_finding --status INFO --category 'Extensions' --check "$label" --detail "$unique extension(s) across $profiles browser profile(s): $names"
    local b u p n id v en from src all
    while IFS='|' read -r b u p n id v en from src all; do
        msp_data_row 'Extensions' Browser "$b" User "$u" Profile "$p" Name "$n" Id "$id" Version "$v" Enabled "$en" FromStore# "$from" UpdateSource "$src" AllSiteAccess# "$all"
        [ "$from" = 'true' ] && continue
        msp_finding --status WARN --severity Medium --category 'Extensions' --check "Extension not from the official store: $n" \
            --detail "$b / $p: \"$n\" (ID $id) was not installed from the browser's store (update source: ${src:-none}). Adware commonly installs extensions this way." \
            --rec 'Ask the client whether they installed it. If not, remove it from the browser'\''s Extensions page (and look for the program that added it).' \
            --evidence "$(msp_json_obj Id "$id" Version "$v" UpdateSource "$src")"
    done <<EOF
$rows
EOF
    local broad
    broad=$(printf '%s\n' "$rows" | awk -F'|' '$10 == "true" && $8 == "true" { print $4 }' | awk '!s[$0]++' | paste -sd ';' - | sed 's/;/; /g')
    if [ -n "$broad" ]; then
        msp_finding --status INFO --category 'Extensions' --check "$label: extensions that can read every website" \
            --detail "$broad. Normal for ad blockers and password managers; anything else the client does not recognise should be removed."
    fi
    if [ "$unique" -gt 15 ]; then
        msp_finding --status WARN --severity Low --category 'Extensions' --check "$label: number of extensions" \
            --detail "$unique different extensions installed. Each one is code with access to browsing." \
            --rec 'Review the list with the client and remove extensions they no longer use.'
    fi
}

scan_user() {
    # scan_user BROWSER FAMILY PROFILE_PATHS USER HOME
    local browser=$1 family=$2 paths=$3 user=$4 home=$5 rel any=0 old_ifs=$IFS
    # Profile folders are ":"-separated and may contain spaces ("Application Support").
    IFS=':'
    # shellcheck disable=SC2086  # split on ":" only, on purpose
    set -- $paths
    IFS=$old_ifs
    for rel in "$@"; do
        [ -d "$home/$rel" ] || continue
        # Other apps create Chromium folders (native messaging hosts) without a browser; only a
        # real profile counts.
        if [ "$family" = 'Chromium' ] && [ ! -d "$home/$rel/Default" ] && ! ls -d "$home/$rel"/Profile\ * >/dev/null 2>&1; then continue; fi
        any=1
        if [ "$family" = 'Chromium' ]; then scan_chromium "$browser" "$user" "$home/$rel"; else scan_firefox "$browser" "$user" "$home/$rel"; fi
    done
    [ "$any" -eq 1 ] || return 0
    report_extensions "$browser" "$user"
}

while IFS='|' read -r b_name b_family b_pre b_src b_paths b_policy; do
    [ -n "$b_name" ] && [ "$b_pre" = '0' ] && [ -n "$b_paths" ] || continue
    while IFS='|' read -r u_name u_home; do
        [ -n "$u_name" ] || continue
        msp_check 'Extensions' "$b_name extensions ($u_name)" scan_user "$b_name" "$b_family" "$b_paths" "$u_name" "$u_home" </dev/null
    done <<EOF
$USER_LIST
EOF
done <<EOF
$BROWSERS
EOF

check_safari_ext() {
    # Safari extensions are app extensions registered with macOS; pluginkit lists them.
    local list
    list=$( { pluginkit -mAv -p com.apple.Safari.web-extension; pluginkit -mAv -p com.apple.Safari.extension; pluginkit -mAv -p com.apple.Safari.content-blocker; } 2>/dev/null |
        awk -F'\t' '/\.appex/ { id = $1; sub(/^[ +!=-]+/, "", id); sub(/\(.*/, "", id); app = $NF; sub(/\.app\/.*/, "", app); sub(/.*\//, "", app); print app " (" id ")" }' | awk '!s[$0]++')
    if [ -z "$list" ]; then
        msp_finding --status PASS --category 'Extensions' --check "Safari extensions ($SELF)" --detail 'No Safari extensions installed.'
        return 0
    fi
    msp_finding --status INFO --category 'Extensions' --check "Safari extensions ($SELF)" \
        --detail "$(printf '%s\n' "$list" | grep -c .) Safari extension(s), each installed with an app (Safari extensions come from the App Store or signed apps): $(printf '%s\n' "$list" | paste -sd ';' - | sed 's/;/; /g')" \
        --rec 'Ask the client about any they do not recognise; remove them by deleting the app that installed them.'
}
if [ "$MSP_PLATFORM" = 'macOS' ]; then msp_check 'Extensions' "Safari extensions ($SELF)" check_safari_ext; fi

# =========================================================================================
msp_section 'Update and extension policies'
# =========================================================================================
policy_flat() {
    # policy_flat LOCATION -> flattened policy settings (".Key<TAB>value") for one browser.
    # macOS: managed preference plists (MDM / configuration profiles); Linux: JSON files.
    local loc=$1 f
    if [ "$MSP_PLATFORM" = 'macOS' ]; then
        for f in "$ROOT/Library/Managed Preferences/$loc.plist" "$ROOT/Library/Managed Preferences/$SELF/$loc.plist"; do
            [ -f "$f" ] && plutil -convert json -o - "$f" 2>/dev/null | msp_json_flatten -
        done
    else
        local dir
        for dir in $(printf '%s' "$loc" | tr ':' ' '); do
            for f in "$ROOT$dir"/*.json; do [ -f "$f" ] && msp_json_flatten "$f"; done
        done
    fi
}

firefox_policies() {
    # Firefox reads policies.json from its install folder (distribution/) or /etc/firefox/policies.
    local f
    for f in "$ROOT/Applications/Firefox.app/Contents/Resources/distribution/policies.json" \
        "$ROOT/etc/firefox/policies/policies.json" "$ROOT/usr/lib/firefox/distribution/policies.json" \
        "$ROOT/usr/lib64/firefox/distribution/policies.json"; do
        [ -f "$f" ] && { printf 'FILE\t%s\n' "$f"; msp_json_flatten "$f"; }
    done
    if [ "$MSP_PLATFORM" = 'macOS' ]; then policy_flat 'org.mozilla.firefox' | sed 's/^/.policies/'; fi
}

check_policies() {
    local any=0 name family pre src paths loc flat forced keys
    while IFS='|' read -r name family pre src paths loc; do
        [ -n "$name" ] && [ "$pre" = '0' ] && [ "$family" = 'Chromium' ] || continue
        flat=$(policy_flat "$loc")
        [ -n "$flat" ] || continue
        any=1
        forced=$(printf '%s\n' "$flat" | awk -F'\t' '$1 ~ /^\.ExtensionInstallForcelist(\[|\.)/ { print $2 }')
        if [ -n "$forced" ]; then
            msp_finding --status WARN --severity High --category 'Policy' --check "$name: force-installed extensions" \
                --detail "A policy ($loc) forces $(printf '%s\n' "$forced" | grep -c .) extension(s) into the browser and stops the user removing them: $(printf '%s\n' "$forced" | paste -sd ';' - | sed 's/;/; /g')" \
                --rec 'On a home computer this is a common adware/hijacker technique. Identify the program or configuration profile that set it, remove it (System Settings > Privacy & Security > Profiles on macOS), then re-check (escalate if unsure).'
        fi
        keys=$(printf '%s\n' "$flat" | awk -F'\t' '{ k = $1; sub(/^\./, "", k); sub(/[.[].*/, "", k); if (k != "" && !s[k]++) print k }' | head -n 12 | paste -sd ',' - | sed 's/,/, /g')
        msp_finding --status INFO --category 'Policy' --check "$name: browser policies set" \
            --detail "$loc has policy settings: $keys. The browser will show \"Managed by your organization\"."
    done <<EOF
$BROWSERS
EOF
    flat=$(firefox_policies)
    if [ -n "$flat" ]; then
        any=1
        local file
        file=$(printf '%s\n' "$flat" | awk -F'\t' '$1 == "FILE" { print $2; exit }')
        forced=$(printf '%s\n' "$flat" | awk -F'\t' '$1 ~ /^\.policies\.Extensions\.Install\[/ || ($1 ~ /^\.policies\.ExtensionSettings\./ && $1 ~ /\.installation_mode$/ && $2 == "force_installed") { print $1 "=" $2 }')
        if [ -n "$forced" ]; then
            msp_finding --status WARN --severity High --category 'Policy' --check 'Mozilla Firefox: force-installed extensions' \
                --detail "A Firefox policy (${file:-managed preferences}) forces extensions into the browser: $(printf '%s\n' "$forced" | head -n 5 | paste -sd ';' - | sed 's/;/; /g')" \
                --rec 'On a home computer this is a common adware technique. Find what wrote the policy, remove it, then re-check (escalate if unsure).'
        fi
        if printf '%s\n' "$flat" | awk -F'\t' '$1 == ".policies.DisableAppUpdate" && $2 == "true" { f = 1 } END { exit !f }'; then
            msp_finding --status FAIL --severity High --category 'Policy' --check 'Firefox: updates disabled by policy' \
                --detail "DisableAppUpdate is set (${file:-managed preferences}). Firefox cannot update itself." \
                --rec 'Remove the DisableAppUpdate policy unless an IT department deliberately set it. (Linux packages from the distribution update through the system updater, so this is less serious there.)'
        fi
        msp_finding --status INFO --category 'Policy' --check 'Mozilla Firefox: browser policies set' \
            --detail "Firefox policies found (${file:-managed preferences}): $(printf '%s\n' "$flat" | awk -F'\t' '$1 ~ /^\.policies\./ { k = $1; sub(/^\.policies\./, "", k); sub(/[.[].*/, "", k); if (!s[k]++) print k }' | head -n 12 | paste -sd ',' - | sed 's/,/, /g')."
    fi
    # Chrome on macOS updates through Google's updater; a check interval of 0 turns it off.
    if [ "$MSP_PLATFORM" = 'macOS' ]; then
        local interval
        interval=$(defaults read com.google.Keystone.Agent checkInterval 2>/dev/null)
        [ -n "$interval" ] || interval=$(policy_flat 'com.google.Keystone' | awk -F'\t' '$1 == ".checkInterval" { print $2; exit }')
        if [ "$interval" = '0' ]; then
            any=1
            msp_finding --status FAIL --severity High --category 'Policy' --check 'Google Update (Chrome): updates blocked by policy' \
                --detail 'Google'\''s updater check interval is 0, so Chrome never checks for updates.' \
                --rec 'Remove the setting (defaults delete com.google.Keystone.Agent checkInterval) unless IT manages Chrome updates another way.'
        fi
    fi
    if [ "$any" -eq 0 ]; then
        msp_finding --status PASS --category 'Policy' --check 'Browser policies' --detail 'No browser or browser-updater policies are set (normal for a home computer).'
    fi
}
msp_check 'Policy' 'Browser policies' check_policies

msp_complete "$OUTPUT"
exit 0
