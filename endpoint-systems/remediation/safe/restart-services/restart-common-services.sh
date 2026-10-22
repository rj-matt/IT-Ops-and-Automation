#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2329  # The embedded helper defines globals and functions this script does not use; checks run through msp_check.
# restart-common-services.sh - restarts a short allow-list of macOS or Linux services that
# commonly fix everyday problems (printing, name resolution, and on Linux the network manager),
# with before/after state, a printed plan, confirmation and --what-if. The Windows version is
# Restart-CommonServices.ps1.
#
# Usage:  bash restart-common-services.sh [--services LIST] [--start-if-stopped] [--what-if]
#                                         [--force] [--timeout N] [--output DIR]
#
# Allow-list (nothing else can be restarted with this script) and why each is on it:
#   macOS
#     mDNSResponder     DNS cache and name resolution. Websites "not found" after a router or
#                       DNS change. macOS restarts it at once if it stops, so its cache is
#                       CLEARED instead (dscacheutil -flushcache; killall -HUP mDNSResponder,
#                       Apple's documented method), which is what a restart would achieve.
#     cupsd             Printing (CUPS). Stuck print queue, printer shown offline. Started by
#                       macOS when needed, so it is restarted only if it is running.
#   Linux (each only when installed)
#     cups              Printing (CUPS), as on macOS.
#     systemd-resolved  DNS cache and name resolution; a restart also clears its cache.
#     NetworkManager    Wi-Fi/Ethernet connections. NOT in the default set: restarting it drops
#                       the network for a few seconds, which also drops a remote session.
#                       Name it with --services NetworkManager.
#
# For each service:
#   Running                     -> restart it (mDNSResponder: clear its cache)
#   Stopped, starts at boot     -> start it (it should be running)
#   Stopped, started on demand  -> left alone (the system starts it when needed);
#                                  --start-if-stopped starts it
#   Disabled / masked / missing -> never changed; reported
#
# Order: record the current state, print the plan, ask you to type YES (--force skips the
# question; --what-if shows the plan only), make the changes, record the state again.
#
# Options:
#   --services LIST     Comma-separated names from the allow-list above, or all (default:
#                       macOS mDNSResponder,cupsd; Linux cups,systemd-resolved).
#   --start-if-stopped  Also start allow-listed services that are stopped and started on demand.
#   --what-if           Show the current state and the plan; change nothing (no sudo needed).
#   --force             Do not ask for confirmation. Required for non-interactive runs (RMM,
#                       ssh without a terminal); without it a non-interactive run changes nothing.
#   --timeout N         Seconds to wait for each service to be running again (10-300, default 60).
#   --output DIR        Also save results as JSON and CSV (toolkit schema 2.0) with
#                       ServicesBefore and ServicesAfter tables.
#   --help              Show this help.
#
# Exit codes: 0 done (or --what-if, or nothing to change); 1 nothing changed (not root, not
# confirmed, non-interactive without --force); 2 a service did not end up running.
#
# Examples:
#   bash restart-common-services.sh --what-if
#   sudo bash restart-common-services.sh --services cupsd
#   sudo bash restart-common-services.sh --force --output /tmp/Ticket123
#
# Purpose       : The "turn it off and on again" fix for a few services, done safely and documented.
# Use Case      : Printing and name-resolution tickets; Linux network-connection tickets.
# Scope         : This computer; only the allow-listed services.
# Risk Level    : Safe -- services restart in seconds; print jobs in progress may need resending;
#                 NetworkManager (only when named) drops the network for a few seconds.
# Prerequisites : macOS 12+ (launchd) or Linux with systemd | bash 3.2+ | root: Yes for changes
#                 (No for --what-if)
# Version       : 1.0.0
# Limitations   : Does not clear stuck print jobs or repair printer drivers. A service that stops
#                 again right away has a deeper problem (check get-recent-critical-errors.sh).
#                 Linux without systemd is not supported (reported, nothing changed).

set -u
MSP_SCRIPT_FILE=$0

#region MSPToolkit (generated) Sections=Core,Change
# DO NOT EDIT — regenerate with Sync-MSPEmbeddedHelper.ps1
# Source: endpoint-systems/utilities/msp-toolkit-common.sh | Sections: Core,Change | SHA256: 173fbf4da144887a85357dd3cb7cb5ade88f9ea34ddae3ba288451e6b46fa45f
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

#region MSPHelper:Change
msp_is_interactive() {
    # True when a person can answer a prompt: input and output are a terminal. False under RMM
    # agents, cron/launchd jobs, "ssh host command" without -t, and piped or redirected input.
    [ -t 0 ] && [ -t 1 ]
}

msp_change_plan() {
    # msp_change_plan STEP... - prints and logs the numbered list of changes before anything is
    # changed.
    local n=0 step
    msp_section 'Planned changes'
    for step in "$@"; do
        n=$((n + 1))
        printf '  %s. %s\n' "$n" "$step"
        msp_log INFO "Plan $n: $step"
    done
}

msp_what_if() {
    # msp_what_if TARGET ACTION - one "What if:" line for a change a --what-if run would make.
    msp_say 90 "What if: $2 on \"$1\"."
    msp_log INFO "What if: $2 on \"$1\""
}

msp_confirm_change() {
    # msp_confirm_change QUESTION FORCE(0|1) - asks the technician to type YES before changes are
    # made. Returns 0 to go ahead.
    #   FORCE=1                     : no question (recorded as a finding).
    #   not interactive, no --force : refuses (SKIPPED finding), so an RMM job or a pasted
    #                                 command can never make changes by accident.
    # Callers skip this entirely under --what-if, which changes nothing.
    local answer=''
    if [ "${2:-0}" = '1' ]; then
        msp_finding --status INFO --category 'Safety' --check 'Confirmation' --detail 'Not asked: --force was given.'
        return 0
    fi
    if ! msp_is_interactive; then
        msp_finding --status SKIPPED --category 'Safety' --check 'Confirmation' \
            --detail 'No changes made: this session cannot answer a confirmation prompt (non-interactive) and --force was not given.' \
            --rec 'Run it in a Terminal window, or add --force once you are sure (use --what-if first to see the plan).'
        return 1
    fi
    printf '\n'
    msp_say 33 "  $1"
    printf '  Type YES to continue (anything else cancels): '
    IFS= read -r answer || answer=''
    msp_log INFO "Confirmation answer: \"$answer\""
    [ "$answer" = 'YES' ] && return 0
    msp_finding --status INFO --category 'Safety' --check 'Confirmation' --detail 'Cancelled by the technician. No changes were made.'
    return 1
}
#endregion MSPHelper:Change
#endregion MSPToolkit (generated)

SCRIPT_VERSION='1.0.0'
OUTPUT=''
SERVICES='all'
START_IF_STOPPED=0
WHAT_IF=0
FORCE=0
TIMEOUT=60
while [ $# -gt 0 ]; do
    case "$1" in
        --output)
            OUTPUT=${2-}
            [ -n "$OUTPUT" ] || { printf 'Missing folder after --output\n' >&2; exit 2; }
            shift 2
            ;;
        --services)
            SERVICES=${2-}
            [ -n "$SERVICES" ] || { printf 'Missing list after --services\n' >&2; exit 2; }
            shift 2
            ;;
        --start-if-stopped) START_IF_STOPPED=1; shift ;;
        --what-if | --whatif) WHAT_IF=1; shift ;;
        --force) FORCE=1; shift ;;
        --timeout)
            TIMEOUT=${2-}
            case "$TIMEOUT" in '' | *[!0-9]*) printf -- '--timeout needs 10-300\n' >&2; exit 2 ;; esac
            if [ "$TIMEOUT" -lt 10 ] || [ "$TIMEOUT" -gt 300 ]; then printf -- '--timeout needs 10-300\n' >&2; exit 2; fi
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

# Allow-list per platform: name|display name|in the default set (1/0). Platform from uname,
# before msp_init, so a wrong name is refused before anything is logged.
case "$(uname -s 2>/dev/null)" in
    Darwin) ALLOW='mDNSResponder|DNS cache and name resolution|1
cupsd|Printing (CUPS)|1' ;;
    *) ALLOW='cups|Printing (CUPS)|1
systemd-resolved|DNS cache and name resolution|1
NetworkManager|Network connections (drops the network for a few seconds)|0' ;;
esac
SELECTED=''
if [ "$SERVICES" = 'all' ] || [ "$SERVICES" = 'All' ]; then
    SELECTED=$(printf '%s\n' "$ALLOW" | awk -F'|' '$3 == 1 { print $1 }')
else
    for s in $(printf '%s' "$SERVICES" | tr ',' ' '); do
        if ! printf '%s\n' "$ALLOW" | cut -d'|' -f1 | grep -qx -- "$s"; then
            printf 'Not on the allow-list for this computer: %s. Allowed: %s\n' "$s" "$(printf '%s\n' "$ALLOW" | cut -d'|' -f1 | paste -sd ',' -)" >&2
            exit 2
        fi
        printf '%s\n' "$SELECTED" | grep -qx -- "$s" || SELECTED="$SELECTED${SELECTED:+
}$s"
    done
fi

[ -n "$OUTPUT" ] && msp_param Output "$OUTPUT"
msp_param Services "$(printf '%s\n' "$SELECTED" | paste -sd ',' -)"
[ "$START_IF_STOPPED" -eq 1 ] && msp_param StartIfStopped 1
[ "$WHAT_IF" -eq 1 ] && msp_param WhatIf 1
[ "$FORCE" -eq 1 ] && msp_param Force 1
msp_param TimeoutSeconds "$TIMEOUT"
msp_init 'restart-common-services' "$SCRIPT_VERSION" 'B4' 'Safe' 'Restart allow-listed services (printing, DNS cache, network) with before/after state' \
    'restarting services and clearing the DNS cache (not needed for --what-if)'

EXIT_CODE=0
display_name() { printf '%s\n' "$ALLOW" | awk -F'|' -v n="$1" '$1 == n { print $2 }'; }
launchd_label() {
    case "$1" in
        mDNSResponder) printf 'system/com.apple.mDNSResponder.reloaded' ;;
        cupsd) printf 'system/org.cups.cupsd' ;;
    esac
}

service_row() {
    # service_row NAME -> "Name|Status|StartType|Pid". Status: Running / Stopped / Failed /
    # NotFound. StartType: Boot / OnDemand / Disabled / Masked / KeepAlive / Unknown.
    local name=$1 out state pid start
    if [ "$MSP_PLATFORM" = 'macOS' ]; then
        local label
        label=$(launchd_label "$name")
        out=$(launchctl print "$label" 2>/dev/null)
        if [ -z "$out" ]; then printf '%s|NotFound||\n' "$name"; return 0; fi
        state=$(printf '%s\n' "$out" | sed -n 's/^	state = //p' | head -n 1)
        pid=$(printf '%s\n' "$out" | sed -n 's/^	pid = //p' | head -n 1)
        start='OnDemand'
        [ "$name" = 'mDNSResponder' ] && start='KeepAlive'
        launchctl print-disabled system 2>/dev/null | grep -qE "\"${label#system/}\" => (true|disabled)" && start='Disabled'
        case "$state" in running) state='Running' ;; *) state='Stopped' ;; esac
        printf '%s|%s|%s|%s\n' "$name" "$state" "$start" "$pid"
        return 0
    fi
    out=$(systemctl show -p LoadState -p ActiveState -p UnitFileState -p MainPID "$name.service" 2>/dev/null)
    case "$(printf '%s\n' "$out" | sed -n 's/^LoadState=//p')" in
        loaded) ;;
        masked) printf '%s|Stopped|Masked|\n' "$name"; return 0 ;;
        *) printf '%s|NotFound||\n' "$name"; return 0 ;;
    esac
    state=$(printf '%s\n' "$out" | sed -n 's/^ActiveState=//p')
    pid=$(printf '%s\n' "$out" | sed -n 's/^MainPID=//p')
    [ "$pid" = '0' ] && pid=''
    case "$(printf '%s\n' "$out" | sed -n 's/^UnitFileState=//p')" in
        enabled | enabled-runtime | alias) start='Boot' ;;
        disabled) start='Disabled' ;;
        masked | masked-runtime) start='Masked' ;;
        static | indirect | generated | transient) start='OnDemand' ;;
        *) start='Unknown' ;;
    esac
    case "$state" in
        active | reloading | activating) state='Running' ;;
        failed) state='Failed' ;;
        *) state='Stopped' ;;
    esac
    printf '%s|%s|%s|%s\n' "$name" "$state" "$start" "$pid"
}

wait_running() {
    # wait_running NAME - true once the service is running, false after TIMEOUT seconds.
    local waited=0
    while [ "$waited" -lt "$TIMEOUT" ]; do
        [ "$(service_row "$1" | cut -d'|' -f2)" = 'Running' ] && return 0
        sleep 1
        waited=$((waited + 1))
    done
    return 1
}

if [ "$MSP_PLATFORM" = 'Linux' ] && ! msp_have systemctl; then
    msp_finding --status SKIPPED --category 'Safety' --check 'Service manager' \
        --detail 'No changes made: this Linux computer does not use systemd, which this script needs.' --rec 'Restart the service with the distribution'\''s own tools.'
    msp_complete "$OUTPUT"
    exit 1
fi

# =========================================================================================
msp_section 'Current state (before)'
# =========================================================================================
PLAN=''      # name|action|state per line; action: Restart / Start / FlushCache / None
while IFS= read -r name; do
    [ -n "$name" ] || continue
    IFS='|' read -r _ status start pid <<EOF
$(service_row "$name")
EOF
    msp_data_row 'ServicesBefore' Name "$name" DisplayName "$(display_name "$name")" Status "$status" StartType "$start" Pid "$pid"
    action='None'
    if [ "$status" = 'NotFound' ]; then why='Service not found on this computer.'
    elif [ "$start" = 'Disabled' ] || [ "$start" = 'Masked' ]; then why="$start. This script never changes a disabled or masked service."
    elif [ "$name" = 'mDNSResponder' ]; then action='FlushCache'; why='macOS restarts it at once if stopped; its cache will be cleared instead.'
    elif [ "$status" = 'Running' ]; then action='Restart'; why='Running; will be restarted.'
    elif [ "$start" = 'Boot' ]; then action='Start'; why="$status although it should start automatically; will be started."
    elif [ "$START_IF_STOPPED" -eq 1 ]; then action='Start'; why="$status (started on demand); will be started because --start-if-stopped was given."
    else why="$status; normal for a service started on demand (the system starts it when needed). Left alone; use --start-if-stopped to start it."
    fi
    fstatus='INFO'
    rec=''
    if [ "$status" = 'NotFound' ] || [ "$start" = 'Disabled' ] || [ "$start" = 'Masked' ]; then fstatus='WARN'; fi
    if [ "$start" = 'Boot' ] && [ "$status" != 'Running' ]; then fstatus='WARN'; fi
    [ "$start" = 'Disabled' ] || [ "$start" = 'Masked' ] && rec='A disabled service is usually set on purpose (by an admin or security software); find out why before enabling it.'
    msp_finding --status "$fstatus" --category 'Before' --check "Service $name" --rec "$rec" \
        --detail "$(display_name "$name"): $status, start type $start${pid:+, pid $pid}. $why"
    PLAN="$PLAN$name|$action|$status
"
done <<EOF
$SELECTED
EOF

steps=''
CHANGES=0
while IFS='|' read -r name action status; do
    [ -n "$name" ] || continue
    case "$action" in
        Restart) step="Restart $name ($(display_name "$name"))" ;;
        Start) step="Start $name ($(display_name "$name"))" ;;
        FlushCache) step='Clear the DNS cache (dscacheutil -flushcache; killall -HUP mDNSResponder)' ;;
        *) step="No change to $name ($(display_name "$name"))" ;;
    esac
    [ "$action" != 'None' ] && CHANGES=$((CHANGES + 1))
    steps="$steps$step
"
done <<EOF
$PLAN
EOF
# The numbered plan, one step per line (bash 3.2: no mapfile).
OLDIFS=$IFS
IFS='
'
set -f
# shellcheck disable=SC2086  # Split on newlines on purpose (globbing is off).
msp_change_plan $steps
set +f
IFS=$OLDIFS

if [ "$WHAT_IF" -eq 1 ]; then
    while IFS='|' read -r name action _; do
        [ -n "$name" ] && [ "$action" != 'None' ] && msp_what_if "$name" "$action"
    done <<EOF
$PLAN
EOF
    msp_finding --status INFO --category 'Safety' --check 'Dry run' --detail '--what-if: the plan was shown; nothing was changed.'
    msp_complete "$OUTPUT"
    exit 0
fi
if [ "$CHANGES" -eq 0 ]; then
    msp_finding --status INFO --category 'Safety' --check 'Result' --detail 'Nothing to change.'
    msp_complete "$OUTPUT"
    exit 0
fi
if [ "$MSP_IS_ADMIN" != 'true' ]; then
    msp_finding --status SKIPPED --category 'Safety' --check 'Administrator' --detail 'No changes made: restarting services requires root (sudo).' \
        --rec "Run again with sudo: sudo bash $MSP_SCRIPT_FILE (or use --what-if to preview without sudo)."
    msp_complete "$OUTPUT"
    exit 1
fi
if ! msp_confirm_change "Make the $CHANGES change(s) listed above on $MSP_HOST?" "$FORCE"; then
    msp_complete "$OUTPUT"
    exit 1
fi

# =========================================================================================
msp_section 'Changes'
# =========================================================================================
run_action() {
    # run_action NAME ACTION - makes one change; prints the first error line on failure.
    local name=$1 action=$2 err
    err="${MSP_WORK_DIR:-${TMPDIR:-/tmp}}/action.err"
    msp_log INFO "Change: $action $name"
    case "$MSP_PLATFORM:$action" in
        macOS:FlushCache) dscacheutil -flushcache 2>"$err" && killall -HUP mDNSResponder 2>>"$err" ;;
        macOS:Restart) launchctl kickstart -k "$(launchd_label "$name")" 2>"$err" ;;
        macOS:Start) launchctl kickstart "$(launchd_label "$name")" 2>"$err" ;;
        Linux:Restart) systemctl --no-ask-password restart "$name.service" 2>"$err" ;;
        Linux:Start) systemctl --no-ask-password start "$name.service" 2>"$err" ;;
        *) printf 'unknown action %s\n' "$action" >"$err"; false ;;
    esac
    local rc=$?
    [ "$rc" -eq 0 ] || head -n 1 "$err" 2>/dev/null
    return "$rc"
}
while IFS='|' read -r name action _; do
    [ -n "$name" ] && [ "$action" != 'None' ] || continue
    if why=$(run_action "$name" "$action"); then
        if [ "$action" = 'FlushCache' ]; then
            msp_finding --status PASS --category 'Change' --check "$name: clear cache" --detail 'DNS cache cleared.'
        elif wait_running "$name"; then
            msp_finding --status PASS --category 'Change' --check "$name: $(printf '%s' "$action" | tr '[:upper:]' '[:lower:]')" --detail "$action done; running."
        else
            EXIT_CODE=2
            msp_finding --status FAIL --category 'Change' --check "$name: $(printf '%s' "$action" | tr '[:upper:]' '[:lower:]')" --detail "Did not reach running within $TIMEOUT seconds." \
                --rec 'Restart the computer. If the service still will not run, check get-recent-critical-errors.sh for the reason.'
        fi
    else
        EXIT_CODE=2
        msp_finding --status FAIL --category 'Change' --check "$name: $(printf '%s' "$action" | tr '[:upper:]' '[:lower:]')" --detail "Failed: ${why:-no error text}" \
            --rec 'Restart the computer. If the service still will not run, check get-recent-critical-errors.sh for the reason.'
    fi
done <<EOF
$PLAN
EOF

# =========================================================================================
msp_section 'State after'
# =========================================================================================
while IFS='|' read -r name action before; do
    [ -n "$name" ] || continue
    IFS='|' read -r _ status start pid <<EOF
$(service_row "$name")
EOF
    msp_data_row 'ServicesAfter' Name "$name" DisplayName "$(display_name "$name")" Status "$status" StartType "$start" Pid "$pid"
    case "$action" in
        Restart | Start)
            if [ "$status" = 'Running' ]; then
                msp_finding --status PASS --category 'After' --check "$name running" --detail "$before -> Running${pid:+ (pid $pid)}"
            else
                EXIT_CODE=2
                msp_finding --status FAIL --category 'After' --check "$name running" --detail "$before -> $status" \
                    --rec 'The service stopped again; check get-recent-critical-errors.sh and escalate with the log.'
            fi
            ;;
    esac
done <<EOF
$PLAN
EOF

msp_complete "$OUTPUT"
exit "$EXIT_CODE"
