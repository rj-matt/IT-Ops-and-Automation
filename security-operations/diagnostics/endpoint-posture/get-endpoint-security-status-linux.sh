#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2329  # The embedded helper defines globals and functions this script does not use; checks run through msp_check.
# get-endpoint-security-status-linux.sh - read-only security check of a Linux desktop or laptop:
# antivirus/EDR, firewall, disk encryption, pending updates, automatic updates, administrator
# accounts, automatic login, Secure Boot, SELinux/AppArmor, SSH and remote desktop.
#
# Usage:  bash get-endpoint-security-status-linux.sh [--output DIR] [--help]
#         sudo bash get-endpoint-security-status-linux.sh --output DIR   (adds the root-only checks)
#
# Options:
#   --output DIR   Also save results as JSON and CSV (toolkit schema 2.0) for the HTML report.
#   --help         Show this help.
#
# Every check runs on its own and reports PASS / WARN / FAIL / INFO, or SKIPPED (needs sudo, or
# not applicable to this distribution) / ERROR (the check itself could not run).
#
# Checks (same names as the Windows and macOS versions where the check is the same, so finding
# IDs line up in the combined report):
#   Antivirus      ClamAV / EDR agents present; ClamAV definition age
#   Firewall       ufw, firewalld or nftables active
#   Encryption     Root filesystem on an encrypted (LUKS / dm-crypt) device; stricter on laptops
#   Updates        Last package list refresh, pending (security) updates, last package change,
#                  automatic security updates. apt and dnf are read from the LOCAL cache only
#                  (apt-get -s / dnf -C): nothing is downloaded or searched online.
#   Accounts       sudo/wheel/admin members, daily account is admin, extra UID 0 accounts,
#                  guest login, automatic login, root password (sudo)
#   System         Secure Boot, SELinux / AppArmor
#   Remote access  SSH server (and root/password logins), VNC / RDP
#
# Examples:
#   bash get-endpoint-security-status-linux.sh
#   sudo bash get-endpoint-security-status-linux.sh --output ~/Audit
#
# Purpose       : One-screen answer to "is this Linux computer protected?" for tickets and home audits.
# Use Case      : Home network security audits, new-client onboarding, security tickets.
# Scope         : This computer only. No network traffic. No changes of any kind.
# Risk Level    : Read-Only -- reads settings only; nothing is changed, installed or enabled.
# Prerequisites : bash 3.2+ | systemd-based distribution (Debian/Ubuntu, Fedora/RHEL, and
#                 similar) | root: No (sudo adds root password status and authoritative SSH settings)
# Version       : 1.0.0
# Limitations   : Package managers other than apt and dnf are reported as SKIPPED. Pending
#                 updates are as of the last package list refresh (date shown). Without root,
#                 SSH settings are read from the config files (the running server is not asked).
#                 Desktop screen lock settings are per user and not checked.
#                 MSP_TEST_ROOT (development tests only) prefixes the configuration files read.

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
while [ $# -gt 0 ]; do
    case "$1" in
        --output)
            OUTPUT=${2-}
            [ -n "$OUTPUT" ] || { printf 'Missing folder after --output\n' >&2; exit 2; }
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
    printf 'This script is for Linux. On macOS use get-endpoint-security-status-macos.sh.\n' >&2
    exit 2
fi

[ -n "$OUTPUT" ] && msp_param Output "$OUTPUT"
msp_init 'get-endpoint-security-status-linux' "$SCRIPT_VERSION" 'A1' 'Read-Only' \
    'Endpoint security posture (read-only)' 'root password status, authoritative SSH settings'

ROOT=${MSP_TEST_ROOT:-}
IS_PORTABLE=0
if ls "$ROOT"/sys/class/power_supply/BAT* >/dev/null 2>&1; then IS_PORTABLE=1; fi
DEVICE_TEXT='desktop'
[ "$IS_PORTABLE" -eq 1 ] && DEVICE_TEXT='laptop'
DAILY_USER=${SUDO_USER:-$MSP_USER}
LISTENING=$(msp_listening_tcp 2>/dev/null)
NOW=$(date +%s)
PKG=''
if msp_have apt-get; then PKG='apt'; elif msp_have dnf; then PKG='dnf'; fi
ADMIN_GROUPS='sudo wheel admin'

days_since() {
    printf '%s' $(((NOW - $1) / 86400))
}

mtime() {
    # Modification time (epoch) of the newest of the given files; empty if none exist.
    local f t best=''
    for f in "$@"; do
        [ -e "$f" ] || continue
        t=$(stat -c %Y "$f" 2>/dev/null) || continue
        if [ -z "$best" ] || [ "$t" -gt "$best" ]; then best=$t; fi
    done
    printf '%s' "$best"
}

service_active() {
    msp_have systemctl && [ "$(systemctl is-active "$1" 2>/dev/null)" = 'active' ]
}

port_listening() {
    # True when TCP PORT is listening on a network address (not only on this computer).
    printf '%s\n' "$LISTENING" | awk -F'|' -v p="$1" '$1 == p && $2 !~ /^(127\.|::1$)/ { found = 1 } END { exit !found }'
}

conf_value() {
    # conf_value KEY FILE... -> value of the first "KEY=value" / "KEY value" line (comments ignored).
    local key=$1
    shift
    cat "$@" 2>/dev/null | sed -n "s/^[[:space:]]*${key}[[:space:]]*[=[:space:]][[:space:]]*\"\{0,1\}\([^\"]*\)\"\{0,1\}[[:space:]]*;\{0,1\}[[:space:]]*$/\1/p" | head -n 1
}

# =========================================================================================
msp_section 'Antivirus'
# =========================================================================================
check_antivirus() {
    local found='' name path
    for entry in 'ClamAV|clamscan' 'Microsoft Defender|mdatp' 'CrowdStrike Falcon|/opt/CrowdStrike' \
        'SentinelOne|/opt/sentinelone' 'Sophos|/opt/sophos-spl' 'ESET|/opt/eset' 'Huntress|/usr/share/huntress' \
        'Bitdefender|/opt/bitdefender-security-tools' 'Trend Micro|/opt/ds_agent'; do
        name=${entry%%|*}
        path=${entry#*|}
        case "$path" in
            /*) [ -e "$ROOT$path" ] && found="$found${found:+, }$name" ;;
            *) msp_have "$path" && found="$found${found:+, }$name" ;;
        esac
    done
    if [ -n "$found" ]; then
        msp_finding --status PASS --category 'Antivirus' --check 'Antivirus product' --detail "Installed: $found (the product's own status was not queried)."
    else
        msp_finding --status INFO --category 'Antivirus' --check 'Antivirus product' \
            --detail 'No antivirus or EDR agent found. Common on Linux desktops; updates, the firewall and not running untrusted software matter more.' \
            --rec 'If the client handles files from Windows users or needs it for compliance, ClamAV or the MSP'\''s EDR can be installed.'
    fi
    # ClamAV keeps its definitions in daily.cvd / daily.cld, updated by freshclam.
    local t
    t=$(mtime "$ROOT/var/lib/clamav/daily.cld" "$ROOT/var/lib/clamav/daily.cvd")
    if [ -n "$t" ]; then
        local age
        age=$(days_since "$t")
        if [ "$age" -gt 7 ]; then
            msp_finding --status WARN --severity Medium --category 'Antivirus' --check 'Antivirus definitions' \
                --detail "ClamAV definitions are $age days old." --rec 'Check that the freshclam service is running (systemctl status clamav-freshclam).'
        else
            msp_finding --status PASS --category 'Antivirus' --check 'Antivirus definitions' --detail "ClamAV definitions updated $age day(s) ago."
        fi
    fi
}
msp_check 'Antivirus' 'Antivirus product' check_antivirus

# =========================================================================================
msp_section 'Firewall'
# =========================================================================================
check_firewall() {
    local active=''
    # ufw writes ENABLED=yes when "ufw enable" was run; the service applies the rules at boot.
    if [ "$(conf_value ENABLED "$ROOT/etc/ufw/ufw.conf")" = 'yes' ] && service_active ufw; then active='ufw'; fi
    if [ -z "$active" ] && service_active firewalld; then active='firewalld'; fi
    if [ -z "$active" ] && service_active nftables; then active='nftables (rule set not inspected without root)'; fi
    if [ -n "$active" ]; then
        msp_finding --status PASS --category 'Firewall' --check 'Firewall' --detail "Active: $active."
        return 0
    fi
    local sev='Medium'
    [ "$IS_PORTABLE" -eq 1 ] && sev='High'
    msp_finding --status WARN --severity "$sev" --category 'Firewall' --check 'Firewall' \
        --detail "No active firewall found (ufw, firewalld or nftables) on this $DEVICE_TEXT." \
        --rec 'Turn one on: Ubuntu/Debian "sudo ufw enable"; Fedora "sudo systemctl enable --now firewalld". Check SSH access first if the computer is managed remotely.'
}
msp_check 'Firewall' 'Firewall' check_firewall

# =========================================================================================
msp_section 'Disk encryption'
# =========================================================================================
check_encryption() {
    if ! msp_have findmnt || ! msp_have lsblk; then printf 'command not found: findmnt/lsblk\n' >&2; return 1; fi
    local src types
    src=$(findmnt -n -o SOURCE / 2>/dev/null | head -n 1)
    src=${src%%\[*}
    # -s lists the device and everything it sits on (LVM -> crypt -> partition).
    types=$(lsblk -s -n -o TYPE "$src" 2>/dev/null | tr -d ' ' | paste -sd ',' -)
    local ev
    ev=$(msp_json_obj RootSource "$src" Stack "$types" DeviceType "$DEVICE_TEXT")
    case ",$types," in
        *,crypt,*)
            msp_finding --status PASS --category 'Encryption' --check 'System drive encryption' --evidence "$ev" \
                --detail "The root filesystem ($src) is on an encrypted (LUKS/dm-crypt) device."
            ;;
        ,,)
            msp_finding --status INFO --category 'Encryption' --check 'System drive encryption' --evidence "$ev" \
                --detail "Could not trace the root filesystem ($src) to a disk; check encryption by hand (lsblk -f)."
            ;;
        *)
            local status='WARN' sev='Medium'
            if [ "$IS_PORTABLE" -eq 1 ]; then status='FAIL'; sev='High'; fi
            msp_finding --status "$status" --severity "$sev" --category 'Encryption' --check 'System drive encryption' --evidence "$ev" \
                --detail "The root filesystem ($src) is not encrypted on this $DEVICE_TEXT. If it is lost or stolen, the data can be read." \
                --rec 'Full-disk encryption can only be added by reinstalling with "Encrypt the disk" (LUKS) selected; plan a backup and reinstall. Home-folder encryption is a partial alternative.'
            ;;
    esac
}
msp_check 'Encryption' 'System drive encryption' check_encryption

# =========================================================================================
msp_section 'Updates'
# =========================================================================================
check_updates() {
    if [ -z "$PKG" ]; then
        msp_skip 'Updates' 'Pending updates' 'Skipped: no apt or dnf package manager found; other distributions are not covered yet.' 'Check updates with the distribution'\''s own tool.'
        return 0
    fi
    local refreshed as_of='never'
    if [ "$PKG" = 'apt' ]; then
        refreshed=$(mtime "$ROOT/var/lib/apt/periodic/update-success-stamp" "$ROOT"/var/lib/apt/lists/*_InRelease "$ROOT"/var/lib/apt/lists/*_Release)
    else
        refreshed=$(mtime "$ROOT"/var/cache/dnf/*/repodata/repomd.xml "$ROOT"/var/cache/libdnf5/*/repodata/repomd.xml "$ROOT/var/cache/dnf/last_makecache")
    fi
    [ -n "$refreshed" ] && as_of=$(date -d "@$refreshed" '+%Y-%m-%d %H:%M' 2>/dev/null)
    if [ -z "$refreshed" ] || [ "$(days_since "$refreshed")" -gt 14 ]; then
        msp_finding --status WARN --severity Medium --category 'Updates' --check 'Last update scan' \
            --detail "Package lists were last refreshed: $as_of." \
            --rec 'Refresh and install updates (Ubuntu: Software Updater or "sudo apt update && sudo apt upgrade"; Fedora: "sudo dnf upgrade").'
    else
        msp_finding --status PASS --category 'Updates' --check 'Last update scan' --detail "Package lists last refreshed: $as_of."
    fi

    local total=0 security=0 out rc
    if [ "$PKG" = 'apt' ]; then
        # Simulation only (-s), from the local package lists: installs nothing, downloads nothing.
        out=$(apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null)
        total=$(printf '%s\n' "$out" | grep -c '^Inst ')
        security=$(printf '%s\n' "$out" | grep '^Inst ' | grep -c -- '-security')
    else
        # -C: cache only, never contacts the repositories. Exit 100 = updates available.
        out=$(dnf -C -q check-update 2>&1)
        rc=$?
        if [ "$rc" -ne 0 ] && [ "$rc" -ne 100 ]; then
            printf 'dnf could not read its cache: %s\n' "$(printf '%s' "$out" | head -n 1)" >&2
            return 1
        fi
        total=$(printf '%s\n' "$out" | awk 'NF == 3 && $1 ~ /\./ { n++ } END { print n + 0 }')
        security=$(dnf -C -q updateinfo list --security 2>/dev/null | awk 'NF >= 3 { n++ } END { print n + 0 }')
    fi
    local ev
    ev=$(msp_json_obj PackageManager "$PKG" Pending# "$total" SecurityPending# "$security" LastScan "$as_of")
    if [ "$security" -gt 0 ]; then
        msp_finding --status FAIL --severity High --category 'Updates' --check 'Pending updates' --evidence "$ev" \
            --detail "$security security update(s) waiting ($total in total, as of $as_of)." \
            --rec 'Install updates now and restart if asked.'
    elif [ "$total" -gt 0 ]; then
        msp_finding --status WARN --severity Medium --category 'Updates' --check 'Pending updates' --evidence "$ev" \
            --detail "$total non-security update(s) waiting (as of $as_of)." --rec 'Install pending updates at the next convenient time.'
    else
        msp_finding --status PASS --category 'Updates' --check 'Pending updates' --evidence "$ev" --detail "None waiting as of $as_of."
    fi

    # Any package install/upgrade rewrites the package database.
    local changed
    changed=$(mtime "$ROOT/var/lib/dpkg/status" "$ROOT/var/lib/rpm/rpmdb.sqlite" "$ROOT/usr/lib/sysimage/rpm/rpmdb.sqlite" "$ROOT/var/lib/rpm/Packages")
    if [ -n "$changed" ]; then
        local days text
        days=$(days_since "$changed")
        text="$(date -d "@$changed" '+%Y-%m-%d' 2>/dev/null) ($days days ago; last change to installed packages)"
        if [ "$days" -gt 60 ]; then
            msp_finding --status FAIL --severity High --category 'Updates' --check 'Last update install' --detail "$text" \
                --rec 'Nothing has been installed or updated for two months; install updates and turn on automatic security updates.'
        elif [ "$days" -gt 35 ]; then
            msp_finding --status WARN --severity Medium --category 'Updates' --check 'Last update install' --detail "$text" --rec 'Install pending updates.'
        else
            msp_finding --status PASS --category 'Updates' --check 'Last update install' --detail "$text"
        fi
    fi
}
msp_check 'Updates' 'Pending updates' check_updates

check_auto_updates() {
    local on='' how=''
    if [ "$PKG" = 'apt' ]; then
        if [ "$(conf_value 'APT::Periodic::Unattended-Upgrade' "$ROOT"/etc/apt/apt.conf.d/*)" = '1' ] && [ -e "$ROOT/usr/bin/unattended-upgrade" ]; then
            on=1
            how='unattended-upgrades'
        fi
    elif [ "$PKG" = 'dnf' ]; then
        local t
        for t in dnf-automatic-install.timer dnf-automatic.timer dnf5-automatic.timer; do
            if msp_have systemctl && [ "$(systemctl is-enabled "$t" 2>/dev/null)" = 'enabled' ]; then on=1; how=$t; break; fi
        done
    else
        return 0
    fi
    if [ -n "$on" ]; then
        msp_finding --status PASS --category 'Updates' --check 'Automatic security updates' --detail "On ($how)."
    else
        msp_finding --status WARN --severity Medium --category 'Updates' --check 'Automatic security updates' \
            --detail 'Security updates are not installed automatically.' \
            --rec 'Ubuntu/Debian: sudo apt install unattended-upgrades && sudo dpkg-reconfigure unattended-upgrades. Fedora: install dnf-automatic and enable dnf-automatic-install.timer. (Desktop update notifications also work if the client acts on them.)'
    fi
}
msp_check 'Updates' 'Automatic security updates' check_auto_updates

# =========================================================================================
msp_section 'Accounts'
# =========================================================================================
check_admins() {
    local g line members list='' m count=0 seen=' '
    for g in $ADMIN_GROUPS; do
        line=$(getent group "$g" 2>/dev/null) || continue
        members=$(printf '%s' "$line" | cut -d: -f4 | tr ',' ' ')
        for m in $members; do
            case "$seen" in *" $m "*) continue ;; esac
            seen="$seen$m "
            list="$list${list:+; }$m ($g)"
            count=$((count + 1))
            msp_data_row 'LocalAdmins' Name "$m" Group "$g"
        done
    done
    if [ "$count" -gt 3 ]; then
        msp_finding --status WARN --severity Medium --category 'Accounts' --check 'Local administrators' \
            --detail "$count accounts can use sudo: $list" --evidence "$(msp_json_obj Members "$list")" \
            --rec 'Confirm each account needs admin rights; remove the others from the sudo/wheel group.'
    else
        msp_finding --status INFO --category 'Accounts' --check 'Local administrators' --detail "${list:-none besides root}" \
            --evidence "$(msp_json_obj Members "$list")"
    fi
    # Any account other than root with user ID 0 is a full administrator in disguise.
    local extra
    extra=$(getent passwd 2>/dev/null | awk -F: '$3 == 0 && $1 != "root" { print $1 }' | paste -sd ',' -)
    if [ -n "$extra" ]; then
        msp_finding --status FAIL --severity High --category 'Accounts' --check 'Extra root accounts' \
            --detail "Accounts with root's user ID (0): $extra." \
            --rec 'Treat as suspicious: no normal setup creates these. Escalate before changing anything.'
    fi
}
msp_check 'Accounts' 'Local administrators' check_admins

check_daily_admin() {
    local groups
    groups=$(id -Gn "$DAILY_USER" 2>/dev/null)
    if printf ' %s ' "$groups" | grep -Eq ' (sudo|wheel|admin) '; then
        msp_finding --status WARN --severity Medium --category 'Accounts' --check 'Daily account has admin rights' \
            --detail "The signed-in account ($DAILY_USER) can use sudo." \
            --rec 'Normal on single-user Linux desktops (sudo still asks for the password). For shared computers, give other people standard accounts.'
    else
        msp_finding --status PASS --category 'Accounts' --check 'Daily account has admin rights' --detail "$DAILY_USER cannot use sudo."
    fi
}
msp_check 'Accounts' 'Daily account has admin rights' check_daily_admin

check_logins() {
    # Guest sessions: LightDM's allow-guest, or a "guest" account with a login shell.
    local guest=''
    if grep -Eqs '^[[:space:]]*allow-guest[[:space:]]*=[[:space:]]*true' "$ROOT"/etc/lightdm/lightdm.conf "$ROOT"/etc/lightdm/lightdm.conf.d/*.conf; then guest='LightDM guest session'; fi
    if getent passwd guest 2>/dev/null | grep -Evq ':(/usr/sbin/nologin|/sbin/nologin|/bin/false)$'; then guest="$guest${guest:+, }account \"guest\""; fi
    if [ -n "$guest" ]; then
        msp_finding --status WARN --severity Low --category 'Accounts' --check 'Guest account' \
            --detail "Guest login is possible: $guest." --rec 'Turn it off unless the client wants it.'
    else
        msp_finding --status PASS --category 'Accounts' --check 'Guest account' --detail 'Off'
    fi
    # Automatic login for GDM, LightDM and SDDM.
    local auto=''
    if [ "$(conf_value AutomaticLoginEnable "$ROOT/etc/gdm3/custom.conf" "$ROOT/etc/gdm/custom.conf" | tr '[:upper:]' '[:lower:]')" = 'true' ]; then
        auto=$(conf_value AutomaticLogin "$ROOT/etc/gdm3/custom.conf" "$ROOT/etc/gdm/custom.conf")
        auto="${auto:-a user} (GDM)"
    fi
    if [ -z "$auto" ]; then
        auto=$(conf_value autologin-user "$ROOT"/etc/lightdm/lightdm.conf "$ROOT"/etc/lightdm/lightdm.conf.d/*.conf)
        [ -n "$auto" ] && auto="$auto (LightDM)"
    fi
    if [ -z "$auto" ]; then
        auto=$(cat "$ROOT"/etc/sddm.conf "$ROOT"/etc/sddm.conf.d/*.conf 2>/dev/null | awk -F= '/^\[Autologin\]/ { s = 1; next } /^\[/ { s = 0 } s && $1 ~ /^User/ && $2 != "" { print $2; exit }')
        [ -n "$auto" ] && auto="$auto (SDDM)"
    fi
    if [ -n "$auto" ]; then
        msp_finding --status WARN --severity High --category 'Accounts' --check 'Automatic login' \
            --detail "The computer signs in automatically as $auto: anyone who turns it on gets in." \
            --rec 'Turn automatic login off (Settings > Users, or the display manager configuration).'
    else
        msp_finding --status PASS --category 'Accounts' --check 'Automatic login' --detail 'Off'
    fi
}
msp_check 'Accounts' 'Guest account' check_logins

check_root_password() {
    local s
    s=$(passwd -S root 2>/dev/null | awk '{ print $2 }')
    case "$s" in
        L | LK | NP)
            msp_finding --status PASS --category 'Accounts' --check 'Root account' --detail 'Root has no usable password (sudo is used instead).' ;;
        P | PS)
            msp_finding --status INFO --category 'Accounts' --check 'Root account' \
                --detail 'Root has a password set (normal on Debian/Fedora installs that asked for one). Make sure it is strong and not shared.' ;;
        *) printf 'Could not read root password status\n' >&2; return 1 ;;
    esac
}
msp_check --root 'Password status is only readable by root.' 'Accounts' 'Root account' check_root_password

# =========================================================================================
msp_section 'System protection'
# =========================================================================================
check_secure_boot() {
    if [ ! -d "$ROOT/sys/firmware/efi" ] && ! msp_have mokutil; then
        msp_finding --status WARN --severity Low --category 'Boot' --check 'Secure Boot' \
            --detail 'The computer starts in legacy BIOS mode, so Secure Boot is not available.' \
            --rec 'Not urgent. Switching to UEFI means reinstalling the boot loader; escalate if required.'
        return 0
    fi
    local sb=''
    msp_have mokutil && sb=$(mokutil --sb-state 2>/dev/null | head -n 1)
    case "$sb" in
        *enabled*) msp_finding --status PASS --category 'Boot' --check 'Secure Boot' --detail 'On' ;;
        *disabled*)
            msp_finding --status WARN --severity Medium --category 'Boot' --check 'Secure Boot' --detail 'Supported (UEFI) but turned off.' \
                --rec 'Turn Secure Boot on in the UEFI setup if the distribution supports it (Ubuntu, Fedora, Debian do). Third-party drivers (NVIDIA) may need enrolling a key.'
            ;;
        *) msp_finding --status INFO --category 'Boot' --check 'Secure Boot' --detail 'UEFI system; Secure Boot state not reported (install mokutil for a definite answer).' ;;
    esac
}
msp_check 'Boot' 'Secure Boot' check_secure_boot

check_mac() {
    local mode=''
    if msp_have getenforce; then mode=$(getenforce 2>/dev/null); fi
    case "$mode" in
        Enforcing) msp_finding --status PASS --category 'System' --check 'SELinux / AppArmor' --detail 'SELinux is enforcing.'; return 0 ;;
        Permissive)
            msp_finding --status WARN --severity Medium --category 'System' --check 'SELinux / AppArmor' --detail 'SELinux is in permissive mode (logs but does not block).' \
                --rec 'Set SELINUX=enforcing in /etc/selinux/config and restart, after checking the logs for denials.'
            return 0
            ;;
    esac
    if [ "$(cat "$ROOT/sys/module/apparmor/parameters/enabled" 2>/dev/null)" = 'Y' ]; then
        msp_finding --status PASS --category 'System' --check 'SELinux / AppArmor' --detail 'AppArmor is enabled.'
    else
        msp_finding --status INFO --category 'System' --check 'SELinux / AppArmor' --detail 'Neither SELinux nor AppArmor is active. Most desktop distributions ship one of them turned on.'
    fi
}
msp_check 'System' 'SELinux / AppArmor' check_mac

# =========================================================================================
msp_section 'Remote access'
# =========================================================================================
check_ssh() {
    if ! port_listening 22 && ! service_active ssh && ! service_active sshd; then
        msp_finding --status PASS --category 'Remote access' --check 'Remote login (SSH)' --detail 'No SSH server running.'
        return 0
    fi
    msp_finding --status WARN --severity Medium --category 'Remote access' --check 'Remote login (SSH)' \
        --detail 'An SSH server is running: the computer accepts command-line logins from the network.' \
        --rec 'Fine if used on purpose; otherwise "sudo systemctl disable --now ssh" (sshd on Fedora). Never forward port 22 on the router.'
    # sshd uses the FIRST value it finds, so read the drop-in files before the main file, as it does.
    local root_login password source
    if msp_is_root && msp_have sshd; then
        root_login=$(sshd -T 2>/dev/null | awk '$1 == "permitrootlogin" { print $2 }')
        password=$(sshd -T 2>/dev/null | awk '$1 == "passwordauthentication" { print $2 }')
        source='sshd -T'
    else
        root_login=$(cat "$ROOT"/etc/ssh/sshd_config.d/*.conf "$ROOT/etc/ssh/sshd_config" 2>/dev/null | awk 'tolower($1) == "permitrootlogin" { print tolower($2); exit }')
        password=$(cat "$ROOT"/etc/ssh/sshd_config.d/*.conf "$ROOT/etc/ssh/sshd_config" 2>/dev/null | awk 'tolower($1) == "passwordauthentication" { print tolower($2); exit }')
        source='read from the config files; sudo shows the running values'
    fi
    if [ "$root_login" = 'yes' ]; then
        msp_finding --status FAIL --severity High --category 'Remote access' --check 'SSH root login' \
            --detail "SSH allows root to log in with a password ($source)." \
            --rec 'Set "PermitRootLogin no" (or prohibit-password) in /etc/ssh/sshd_config and restart ssh.'
    fi
    if [ "${password:-yes}" = 'yes' ]; then
        msp_finding --status INFO --category 'Remote access' --check 'SSH password logins' \
            --detail "SSH accepts passwords (the default; $source). Fine on a home network if the port is not forwarded." \
            --rec 'If the server is reachable from the internet, use keys only (PasswordAuthentication no).'
    fi
}
msp_check 'Remote access' 'Remote login (SSH)' check_ssh

check_remote_desktop() {
    local what='' p
    for p in 5900 5901 5902; do port_listening "$p" && what="VNC (port $p)" && break; done
    port_listening 3389 && what="$what${what:+ and }RDP (port 3389: xrdp or GNOME Remote Desktop)"
    if [ -n "$what" ]; then
        msp_finding --status WARN --severity Medium --category 'Remote access' --check 'Remote Desktop' \
            --detail "$what is listening: others on the network can view or control the screen." \
            --rec 'Fine if the client uses it on purpose. Otherwise turn it off (Settings > Sharing, or stop the service), and never forward its port on the router.'
    else
        msp_finding --status PASS --category 'Remote access' --check 'Remote Desktop' --detail 'No VNC or RDP server listening.'
    fi
}
msp_check 'Remote access' 'Remote Desktop' check_remote_desktop

msp_complete "$OUTPUT"
exit 0
