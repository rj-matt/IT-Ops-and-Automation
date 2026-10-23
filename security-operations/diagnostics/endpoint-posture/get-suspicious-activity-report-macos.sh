#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2329  # The embedded helper defines globals and functions this script does not use; checks run through msp_check.
# get-suspicious-activity-report-macos.sh - first-look triage for signs of compromise on a Mac:
# launch agents and daemons, cron, login shell files, programs and network connections from
# unusual folders, SSH keys, hosts file and proxy. Read-only. NOT an antivirus or EDR.
# The Windows version is Get-SuspiciousActivityReport.ps1 and the Linux version
# get-suspicious-activity-report-linux.sh (same check names).
#
# Usage:  bash get-suspicious-activity-report-macos.sh [--days N] [--output DIR] [--help]
#         sudo bash get-suspicious-activity-report-macos.sh ...   (adds every user and Background items)
#
# Options:
#   --days N      How far back "new" reaches for startup items and SSH keys (1-90, default 14).
#   --output DIR  Also save results as JSON and CSV (toolkit schema 2.0), with StartupItems,
#                 FlaggedProcesses and FlaggedConnections tables.
#   --help        Show this help.
#
# A quick look at the places malware, adware and scam remote-access tools most often leave
# traces, so a technician can decide within minutes whether to escalate. It does not scan
# files, look inside memory or follow what programs do. A clean result does not prove the Mac
# is clean.
#
# "Unusual folders": /tmp, /var/tmp, the temporary folder ($TMPDIR under /var/folders),
# /Users/Shared and Downloads; also hidden folders (a path part starting with ".", except
# common developer tool folders such as .local or .cargo) and the rest of /var/folders when
# the program there is not validly signed (macOS itself runs signed App Store wrappers and
# translocated apps from /var/folders). Programs elsewhere in a home folder are only flagged
# when not validly signed. Ad-hoc signatures count as unsigned.
#
# Checks
#   Startup items                      /Library/LaunchDaemons, /Library/LaunchAgents,
#                                      ~/Library/LaunchAgents (every user's with sudo), the
#                                      user's crontab (StartupItems table)
#   Startup items in unusual folders   WARN High
#   Startup items that run scripts     curl/wget piped to a shell, base64 decoding, osascript
#                                      -e, python -c, reverse shells. WARN High
#   Unsigned startup programs          In a home folder, not validly signed. WARN Medium
#   New startup items                  Added or changed in the last --days days. WARN Low
#   Background items                   Login items and background tasks macOS registered
#                                      (sfltool dumpbtm; sudo); unusual folders = WARN High
#   Login shell files                  ~/.zshrc, ~/.zprofile, ~/.bash_profile ... lines that
#                                      download and run code. WARN Medium
#   Programs running from unusual folders   WARN High; unsigned ones in a home folder WARN Medium
#   Connections from flagged programs  Established TCP connections of those programs (lsof;
#                                      other users' with sudo)
#   SSH keys                           authorized_keys added or changed in the window = WARN Medium
#   Hosts file                         Entries for update, security or major sites = WARN High
#   Proxy settings                     A system proxy or automatic proxy script = WARN Medium
#
# Examples:
#   bash get-suspicious-activity-report-macos.sh
#   sudo bash get-suspicious-activity-report-macos.sh --days 30 --output ~/Desktop/Ticket123
#
# Purpose       : First-look triage: "does anything on this Mac look like it was tampered with?"
# Use Case      : Scam calls ("someone was on my computer"), pop-ups and browser redirects,
#                 unknown programs, before or after removing a remote-access tool.
# Scope         : This Mac only. No network traffic. Reads launchd property lists, crontab,
#                 shell start-up files, the process and connection lists, authorized_keys
#                 (names and dates only), /etc/hosts and the proxy settings.
# Risk Level    : Read-Only -- reads files and system information; changes nothing.
# Prerequisites : macOS 12+ | bash 3.2+ | root: No (sudo adds other users' launch agents and
#                 SSH keys, Background items, and other users' network connections)
# Version       : 1.0.0
# Limitations   : NOT an antivirus or EDR: no file scanning, no memory analysis, no history of
#                 what ran. XProtect detections and the unified log are not searched (slow).
#                 Signed malware in /Applications is not flagged by folder. Configuration
#                 profiles are covered by A1 (MDM). MSP_TEST_ROOT (development tests only)
#                 prefixes the files read.

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

SCRIPT_VERSION='1.0.0'
OUTPUT=''
DAYS=14
while [ $# -gt 0 ]; do
    case "$1" in
        --output)
            OUTPUT=${2-}
            [ -n "$OUTPUT" ] || { printf 'Missing folder after --output\n' >&2; exit 2; }
            shift 2
            ;;
        --days)
            case "${2-}" in '' | *[!0-9]*) printf -- '--days must be a number from 1 to 90\n' >&2; exit 2 ;; esac
            if [ "$2" -lt 1 ] || [ "$2" -gt 90 ]; then printf -- '--days must be a number from 1 to 90\n' >&2; exit 2; fi
            DAYS=$2
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
msp_param Days "$DAYS"
msp_init 'get-suspicious-activity-report-macos' "$SCRIPT_VERSION" 'C3' 'Read-Only' \
    'First-look triage for signs of compromise (read-only; not an antivirus or EDR)' \
    'other users'\'' launch agents and SSH keys, Background items'

ROOT=${MSP_TEST_ROOT:-}
NOW=$(date +%s)
SINCE=$((NOW - DAYS * 86400))
HOME_DIR=${HOME:-/var/empty}

file_mtime() { stat -f %m "$1" 2>/dev/null; }
ymd() { date -r "$1" '+%Y-%m-%d'; }

folder_risk() {
    # folder_risk PATH -> High (unusual folder), Hidden (hidden or system cache folder: unusual
    # unless validly signed), Profile (elsewhere in a home folder: flagged if unsigned) or nothing.
    local p=$1
    case "$p" in
        # macOS runs App Store wrappers and translocated apps from here; they are signed.
        /var/folders/*/T/AppTranslocation/* | /private/var/folders/*/T/AppTranslocation/*) printf 'Hidden'; return 0 ;;
        /tmp/* | /private/tmp/* | /var/tmp/* | /private/var/tmp/* | /var/folders/*/T/* | /private/var/folders/*/T/* | /Users/Shared/* | */Downloads/*)
            printf 'High'
            return 0
            ;;
        /var/folders/* | /private/var/folders/*) printf 'Hidden'; return 0 ;;
    esac
    if printf '%s' "$p" | grep -Eq '/\.[^/]+/' &&
        ! printf '%s' "$p" | grep -Eq '/\.(local|cargo|rustup|nvm|npm|yarn|rbenv|pyenv|volta|bun|deno|vscode|vscode-server|cursor|sdkman|docker|orbstack|colima|lima|gem|dotnet|jenv|asdf|linuxbrew|Trash)/'; then
        printf 'Hidden'
        return 0
    fi
    case "$p" in
        /Users/*/Applications/* | "$HOME_DIR"/Applications/*) ;;
        /Users/*/* | "$HOME_DIR"/*) printf 'Profile' ;;
    esac
}

effective_risk() {
    # effective_risk PATH -> High, Profile-unsigned or nothing, after the signature check that
    # Hidden and Profile paths need. Sets SIGNED (yes/no/missing/'').
    local r
    r=$(folder_risk "$1")
    SIGNED=''
    case "$r" in
        High) printf 'High' ;;
        Hidden)
            SIGNED=$(signed_state "$1")
            [ "$SIGNED" = 'no' ] && printf 'High'
            ;;
        Profile)
            SIGNED=$(signed_state "$1")
            [ "$SIGNED" = 'no' ] && printf 'Unsigned'
            ;;
    esac
}

SCRIPT_RE='(curl|wget)[^|]*\|[[:space:]]*(sudo[[:space:]]+)?(ba|z)?sh|base64[[:space:]]+(-d|--decode|-D)|eval[[:space:]]*"?\$\((curl|wget)|osascript[[:space:]]+-e|python[0-9.]*[[:space:]]+-c|perl[[:space:]]+-e|[[:space:]]nc[[:space:]].*-e[[:space:]]|/dev/tcp/|bash[[:space:]]+-i[[:space:]]'
runs_script() { printf '%s' "$1" | grep -Eiq "$SCRIPT_RE"; }

signed_state() {
    # signed_state PATH -> yes / no / missing. Ad-hoc signatures count as no. "Resource envelope
    # is obsolete" is an older (still Apple-issued) signature format used by iPhone/iPad apps
    # running on Apple silicon; it counts as signed. Any other verification failure is no.
    local p=$1 err
    [ -e "$ROOT$p" ] || { printf 'missing'; return 0; }
    if codesign -dv "$ROOT$p" 2>&1 | grep -Eq 'Signature=adhoc|not signed at all'; then printf 'no'; return 0; fi
    if err=$(codesign -v "$ROOT$p" 2>&1); then printf 'yes'; return 0; fi
    case "$err" in *'resource envelope is obsolete'*) printf 'yes' ;; *) printf 'no' ;; esac
}

folder_label() {
    case "$1" in
        High) printf 'unusual' ;;
        Unsigned) printf 'home folder, unsigned' ;;
    esac
}

target_path() {
    # target_path < one argument per line -> the program a command really runs: for an
    # interpreter, the first later argument that is a file path; otherwise the first argument.
    local first a
    IFS= read -r first || first=''
    case "${first##*/}" in
        sh | bash | zsh | dash | python | python[0-9]* | perl | ruby | node | osascript)
            while IFS= read -r a; do
                case "$a" in /*) printf '%s' "$a"; return 0 ;; esac
            done
            ;;
    esac
    printf '%s' "$first"
}

list_items() {
    # list_items "line|line" -> "a; b; c" (first 8, then "and N more").
    local text=$1 n
    n=$(printf '%s\n' "$text" | grep -c .)
    text=$(printf '%s\n' "$text" | grep . | head -n 8 | paste -sd ';' - | sed 's/;/; /g')
    [ "$n" -gt 8 ] && text="$text; and $((n - 8)) more"
    printf '%s' "$text"
}

msp_finding --status INFO --category 'Scope' --check 'Scope' \
    --detail "First-look triage of common hiding places for the last $DAYS day(s); not an antivirus or EDR scan. A clean result does not prove the Mac is clean: if compromise is suspected, run a malware scan and escalate."

# =========================================================================================
msp_section 'Startup items'
# =========================================================================================
S_COUNT=0
S_SRC=()
S_NAME=()
S_CMD=()
S_PATH=()
S_RISK=()
S_SCRIPT=()
S_MTIME=()
S_SIGNED=()
add_item() {
    # add_item SOURCE NAME MTIME COMMAND PATH
    local n=$S_COUNT risk script=0 signed
    SIGNED=''
    risk=$(effective_risk "$5")
    signed=$(folder_risk "$5" | grep -q . && signed_state "$5")
    runs_script "$4" && script=1
    S_SRC[n]=$1
    S_NAME[n]=$2
    S_MTIME[n]=$3
    S_CMD[n]=$4
    S_PATH[n]=$5
    S_RISK[n]=$risk
    S_SCRIPT[n]=$script
    S_SIGNED[n]=$signed
    S_COUNT=$((n + 1))
    msp_data_row 'StartupItems' Source "$1" Name "$2" Command "$4" Path "$5" Folder "$(folder_label "$risk")" \
        RunsScript# "$([ "$script" -eq 1 ] && printf true || printf false)" Signed "$signed" Modified "$([ -n "$3" ] && ymd "$3")"
}

check_launchd() {
    local dirs d f label prog args cmd path mtime
    dirs="/Library/LaunchDaemons
/Library/LaunchAgents
$HOME_DIR/Library/LaunchAgents"
    if [ "$MSP_IS_ADMIN" = 'true' ]; then
        for d in "$ROOT"/Users/*/Library/LaunchAgents; do
            [ -d "$d" ] && dirs="$dirs
${d#"$ROOT"}"
        done
    fi
    while IFS= read -r d; do
        [ -n "$d" ] && [ -d "$ROOT$d" ] || continue
        for f in "$ROOT$d"/*.plist; do
            [ -f "$f" ] || continue
            label=$(plutil -extract Label raw -o - "$f" 2>/dev/null)
            [ -n "$label" ] || label=${f##*/}
            prog=$(plutil -extract Program raw -o - "$f" 2>/dev/null)
            args=$(plutil -extract ProgramArguments json -o - "$f" 2>/dev/null | msp_json_flatten - | cut -f2)
            # Program, when present, is what runs; ProgramArguments then starts with argv[0].
            if [ -n "$prog" ] && [ -n "$args" ]; then
                cmd="$prog $(printf '%s\n' "$args" | sed 1d | paste -sd ' ' -)"
                path=$({ printf '%s\n' "$prog"; printf '%s\n' "$args" | sed 1d; } | target_path)
            elif [ -n "$args" ]; then
                cmd=$(printf '%s\n' "$args" | paste -sd ' ' -)
                path=$(printf '%s\n' "$args" | target_path)
            else
                cmd=$prog
                path=$prog
            fi
            [ -n "$cmd" ] || cmd='(no program set)'
            mtime=$(file_mtime "$f")
            add_item "$d" "$label" "$mtime" "$cmd" "$path"
        done
    done <<EOF
$dirs
EOF
}
msp_check 'Startup' 'Launch agents and daemons' check_launchd

check_cron() {
    local lines line cmd
    msp_have crontab || return 0
    lines=$(crontab -l 2>/dev/null | grep -Ev '^[[:space:]]*(#|$)|^[A-Z_]+=')
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        # Command = everything after the five schedule fields (or an @reboot-style keyword).
        cmd=$(printf '%s\n' "$line" | awk '{ if ($1 ~ /^@/) { $1 = "" } else { for (i = 1; i <= 5; i++) $i = "" } sub(/^ +/, ""); print }')
        add_item 'crontab' "$(id -un)" '' "$cmd" "$(printf '%s\n' "$cmd" | tr -s '[:blank:]' '\n' | target_path)"
    done <<EOF
$lines
EOF
}
msp_check 'Startup' 'Cron jobs' check_cron

msp_finding --status INFO --category 'Startup' --check 'Startup items' \
    --detail "$S_COUNT launch agent/daemon and cron item(s) outside Apple's own (see the StartupItems table)."

item_list() {
    # item_list FILTER -> "source label: command" lines for items where FILTER (a function) is true.
    local i=0
    while [ "$i" -lt "$S_COUNT" ]; do
        if "$1" "$i"; then printf '%s "%s": %s\n' "${S_SRC[$i]}" "${S_NAME[$i]}" "$(printf '%s' "${S_CMD[$i]}" | cut -c1-160)"; fi
        i=$((i + 1))
    done
}
is_high() { [ "${S_RISK[$1]}" = 'High' ]; }
is_script() { [ "${S_SCRIPT[$1]}" -eq 1 ]; }
is_unsigned() { [ "${S_RISK[$1]}" = 'Unsigned' ]; }
is_new() { [ -n "${S_MTIME[$1]}" ] && [ "${S_MTIME[$1]}" -ge "$SINCE" ]; }

report_items() {
    # report_items CHECK FILTER SEVERITY PASS_TEXT REC
    local hits
    hits=$(item_list "$2")
    if [ -z "$hits" ]; then
        msp_finding --status PASS --category 'Startup' --check "$1" --detail "$4"
    else
        msp_finding --status WARN --severity "$3" --category 'Startup' --check "$1" --detail "$(list_items "$hits")" --rec "$5"
    fi
}
check_startup_flags() {
    report_items 'Startup items in unusual folders' is_high High 'None start from temporary, shared, Downloads or hidden folders.' \
        'Ordinary software does not start from these folders. Note the file, check it on VirusTotal from another computer, and if it is not recognized disconnect the Mac from the network and escalate.'
    report_items 'Startup items that run scripts' is_script High 'No startup item downloads or decodes code.' \
        'Startup items that download, decode or hand code to a shell are typical of adware and malware. Do not run the command; record it and escalate.'
    report_items 'Unsigned startup programs' is_unsigned Medium 'Every startup program in a home folder is validly signed.' \
        'Unsigned programs that start from a home folder are worth a look: ask the user what each is; unknown ones should be checked and removed.'
    report_items 'New startup items' is_new Low "No launch agent, daemon or cron item changed in the last $DAYS day(s)." \
        'Ask the user whether they installed something around these dates; new items around a scam call or pop-ups deserve a closer look.'
}
msp_check 'Startup' 'Startup item checks' check_startup_flags

check_btm() {
    local out paths flagged p
    out=$(msp_run_timeout 60 sfltool dumpbtm 2>&1) || { printf '%s\n' "$out" | head -n 1 >&2; return 1; }
    paths=$(printf '%s\n' "$out" | sed -n 's/^[[:space:]]*Executable Path:[[:space:]]*//p; s/^[[:space:]]*URL:[[:space:]]*file:\/\///p' | sed 's/%20/ /g' | sort -u)
    flagged=''
    while IFS= read -r p; do
        [ -n "$p" ] || continue
        [ "$(folder_risk "$p")" = 'High' ] && flagged="$flagged$p
"
    done <<EOF
$paths
EOF
    if [ -n "$flagged" ]; then
        msp_finding --status WARN --severity High --category 'Startup' --check 'Background items' --detail "$(list_items "$flagged")" \
            --rec 'Review these in System Settings > General > Login Items & Extensions; anything the user does not recognize should be removed and escalated.'
    else
        msp_finding --status PASS --category 'Startup' --check 'Background items' \
            --detail "$(printf '%s\n' "$paths" | grep -c .) registered program(s); none in unusual folders."
    fi
}
msp_check --root 'macOS only lists every login and background item to root (sfltool dumpbtm).' 'Startup' 'Background items' check_btm

check_shell_files() {
    local f hits='' line
    for f in .zshrc .zprofile .zshenv .zlogin .bash_profile .bashrc .profile; do
        [ -f "$ROOT$HOME_DIR/$f" ] || continue
        while IFS= read -r line; do
            hits="$hits~/$f: $(printf '%s' "$line" | sed 's/^[[:space:]]*//' | cut -c1-120)
"
        done <<EOF
$(grep -Ei "$SCRIPT_RE" "$ROOT$HOME_DIR/$f" 2>/dev/null | grep -Ev '^[[:space:]]*#')
EOF
    done
    hits=$(printf '%s' "$hits" | grep -v ': $')
    if [ -z "$hits" ]; then
        msp_finding --status PASS --category 'Startup' --check 'Login shell files' --detail 'No line in the shell start-up files downloads, decodes or hands code to a shell.'
    else
        msp_finding --status WARN --severity Medium --category 'Startup' --check 'Login shell files' --detail "$(list_items "$hits")" \
            --rec 'These lines run every time Terminal opens. Developer tools (Homebrew, nvm) add some legitimately; anything else should be removed after checking what it downloads.'
    fi
}
msp_check 'Startup' 'Login shell files' check_shell_files

# =========================================================================================
msp_section 'Running programs and connections'
# =========================================================================================
FLAGGED_PIDS=' '
check_processes() {
    local out pid user path risk high='' prof=''
    out=$(ps -axww -o pid= -o user= -o comm= 2>/dev/null) || { printf 'ps failed\n' >&2; return 1; }
    while read -r pid user path; do
        [ -n "$path" ] || continue
        case "$path" in /*) ;; *) continue ;; esac
        risk=$(effective_risk "$path")
        case "$risk" in
            High)
                high="$high$path (PID $pid, $user)
"
                FLAGGED_PIDS="$FLAGGED_PIDS$pid "
                msp_data_row 'FlaggedProcesses' ProcessId# "$pid" User "$user" Path "$path" Reason 'unusual folder'
                ;;
            Unsigned)
                prof="$prof$path (PID $pid, $user)
"
                FLAGGED_PIDS="$FLAGGED_PIDS$pid "
                msp_data_row 'FlaggedProcesses' ProcessId# "$pid" User "$user" Path "$path" Reason 'unsigned, in a home folder'
                ;;
        esac
    done <<EOF
$out
EOF
    if [ -n "$high" ]; then
        msp_finding --status WARN --severity High --category 'Processes' --check 'Programs running from unusual folders' --detail "$(list_items "$high")" \
            --rec 'Note the paths, then disconnect the Mac from the network and escalate. Do not quit them before a malware scan has recorded them, unless a remote session is in progress.'
    else
        msp_finding --status PASS --category 'Processes' --check 'Programs running from unusual folders' --detail 'None.'
    fi
    if [ -n "$prof" ]; then
        msp_finding --status WARN --severity Medium --category 'Processes' --check 'Unsigned programs running from the user profile' --detail "$(list_items "$prof")" \
            --rec 'Ask the user what each program is; check unknown ones on VirusTotal.'
    fi
}
msp_check 'Processes' 'Programs running from unusual folders' check_processes

check_connections() {
    local out pid name total hits=''
    msp_have lsof || { printf 'lsof: command not found\n' >&2; return 1; }
    out=$(msp_run_timeout 30 lsof -nP -iTCP -sTCP:ESTABLISHED 2>/dev/null | awk 'NR > 1 { print $2, $9 }')
    total=$(printf '%s\n' "$out" | grep -c .)
    while read -r pid name; do
        [ -n "$pid" ] || continue
        case "$FLAGGED_PIDS" in *" $pid "*) ;; *) continue ;; esac
        case "$name" in *'->'127.* | *'->[::1]'*) continue ;; esac
        hits="${hits}PID $pid -> ${name#*->}
"
        msp_data_row 'FlaggedConnections' ProcessId# "$pid" Remote "${name#*->}"
    done <<EOF
$out
EOF
    local note=''
    [ "$MSP_IS_ADMIN" = 'true' ] || note=' Only this user'\''s connections are visible without sudo.'
    if [ -n "$hits" ]; then
        msp_finding --status WARN --severity High --category 'Processes' --check 'Connections from flagged programs' --detail "$(list_items "$hits").$note" \
            --rec 'A flagged program talking to the internet may be sending data out or giving someone remote control. Disconnect the Mac from the network now and escalate.'
    else
        msp_finding --status PASS --category 'Processes' --check 'Connections from flagged programs' --detail "No flagged program has a network connection ($total connection(s) in total).$note"
    fi
}
msp_check 'Processes' 'Connections from flagged programs' check_connections

# =========================================================================================
msp_section 'Accounts and network settings'
# =========================================================================================
check_ssh_keys() {
    local files f n keys=0 new='' m list
    files="$HOME_DIR/.ssh/authorized_keys"
    if [ "$MSP_IS_ADMIN" = 'true' ]; then
        files="$files
/var/root/.ssh/authorized_keys"
        for f in "$ROOT"/Users/*/.ssh/authorized_keys; do
            [ -f "$f" ] && files="$files
${f#"$ROOT"}"
        done
    fi
    list=''
    while IFS= read -r f; do
        [ -n "$f" ] && [ -f "$ROOT$f" ] || continue
        case "$list" in *"|$f|"*) continue ;; esac
        list="$list|$f|"
        n=$(grep -Ec '^[[:space:]]*(ssh-|ecdsa-|sk-)' "$ROOT$f" 2>/dev/null)
        keys=$((keys + n))
        m=$(file_mtime "$ROOT$f")
        [ -n "$m" ] && [ "$m" -ge "$SINCE" ] && new="$new$f ($n key(s), changed $(ymd "$m"))
"
    done <<EOF
$files
EOF
    if [ -n "$new" ]; then
        msp_finding --status WARN --severity Medium --category 'Accounts' --check 'SSH keys' --detail "Changed in the last $DAYS day(s): $(list_items "$new")" \
            --rec 'A key in authorized_keys lets someone log in without a password when Remote Login is on. Confirm each key with the user; remove unknown ones and turn Remote Login off if it is not needed.'
    elif [ "$keys" -gt 0 ]; then
        msp_finding --status INFO --category 'Accounts' --check 'SSH keys' --detail "$keys key(s) allowed to log in by SSH; none changed in the last $DAYS day(s)."
    else
        msp_finding --status PASS --category 'Accounts' --check 'SSH keys' --detail 'No SSH keys allow logging in to this account.'
    fi
}
msp_check 'Accounts' 'SSH keys' check_ssh_keys

HOSTS_WATCH='microsoft|windowsupdate|apple|icloud|mzstatic|google|bing|amazon|paypal|bank|avast|avg|norton|symantec|mcafee|kaspersky|eset|malwarebytes|sophos|bitdefender|trendmicro|webroot|crowdstrike|sentinelone|virustotal|intego|objective-see'
check_hosts() {
    local entries watched n
    [ -r "$ROOT/etc/hosts" ] || { printf '/etc/hosts: Permission denied\n' >&2; return 1; }
    entries=$(sed 's/#.*$//' "$ROOT/etc/hosts" | awk 'NF >= 2' | awk '{
        keep = 0
        for (i = 2; i <= NF; i++) if ($i !~ /^(localhost|broadcasthost|ip6-.*)$/) keep = 1
        if (keep) { $1 = $1; print }
    }')
    if [ -z "$entries" ]; then
        msp_finding --status PASS --category 'Network' --check 'Hosts file' --detail 'No entries besides the macOS defaults.'
        return 0
    fi
    n=$(printf '%s\n' "$entries" | grep -c .)
    watched=$(printf '%s\n' "$entries" | grep -Ei "$HOSTS_WATCH")
    if [ -n "$watched" ]; then
        msp_finding --status WARN --severity High --category 'Network' --check 'Hosts file' --detail "$n entr(ies), including: $(list_items "$watched")" \
            --rec 'Entries for update, security or banking sites can block updates or send the user to fake sites. Unless someone added them on purpose, remove them (sudo nano /etc/hosts) and run a malware scan.'
    else
        msp_finding --status INFO --category 'Network' --check 'Hosts file' --detail "$n entr(ies): $(list_items "$entries")"
    fi
}
msp_check 'Network' 'Hosts file' check_hosts

check_proxy() {
    local out items=''
    out=$(scutil --proxy 2>/dev/null) || { printf 'scutil failed\n' >&2; return 1; }
    val() { printf '%s\n' "$out" | sed -n "s/^[[:space:]]*$1 : //p" | head -n 1; }
    [ "$(val HTTPEnable)" = '1' ] && items="${items}web proxy $(val HTTPProxy):$(val HTTPPort)
"
    [ "$(val HTTPSEnable)" = '1' ] && items="${items}secure web proxy $(val HTTPSProxy):$(val HTTPSPort)
"
    [ "$(val SOCKSEnable)" = '1' ] && items="${items}SOCKS proxy $(val SOCKSProxy):$(val SOCKSPort)
"
    [ "$(val ProxyAutoConfigEnable)" = '1' ] && items="${items}automatic proxy script $(val ProxyAutoConfigURLString)
"
    if [ -n "$items" ]; then
        msp_finding --status WARN --severity Medium --category 'Network' --check 'Proxy settings' --detail "Web traffic goes through: $(list_items "$items")." \
            --rec 'Home Macs rarely need a proxy; adware sets one to watch or change web pages. Unless the client'\''s work requires it, turn it off (System Settings > Network > the connection > Details > Proxies).'
    else
        msp_finding --status PASS --category 'Network' --check 'Proxy settings' --detail 'No proxy set.'
    fi
}
msp_check 'Network' 'Proxy settings' check_proxy

msp_complete "$OUTPUT"
exit 0
