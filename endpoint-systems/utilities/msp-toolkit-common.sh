# shellcheck shell=bash
# shellcheck disable=SC2034  # Globals set here are read by the scripts that embed this file.
#
# msp-toolkit-common.sh - shared helper functions for the MSP toolkit's macOS and Linux scripts:
# logging, findings, console/ticket output, JSON/CSV export (schema 2.0), privilege checks,
# local subnet detection and a capped parallel runner.
#
# This file is the single source of truth for bash helper code. Toolkit scripts do NOT source it
# at run time. Each script carries a generated copy of the sections it needs, so a script still
# works when copied alone to a USB stick.
#
# To change a helper:
#   1. Edit this file.
#   2. Run  .\endpoint-systems\utilities\Sync-MSPEmbeddedHelper.ps1
#      to regenerate the embedded copies in every .ps1 and .sh script.
#   3. Run  .\endpoint-systems\utilities\Sync-MSPEmbeddedHelper.ps1 -Check
#      before committing. It exits 1 if any embedded copy differs from this file.
#
# Sections (each wrapped in "#region MSPHelper:<Name>" / "#endregion MSPHelper:<Name>"):
#   Core   Run setup, logging, findings, console summary, ticket block, JSON/CSV export,
#          root / Full Disk Access checks, time-limited commands
#   Net    Local IPv4 subnet of the active non-VPN adapter, IPv4 math, DNS servers in use,
#          neighbor (ARP) table, ping and TCP probes, parallel runner capped at 32
#
# Every section depends on Core. The sync tool always embeds Core first.
# The PowerShell equivalent is MSPToolkit.Common.psm1; both write the same result schema.
#
# Compatibility rules for everything in this file (macOS ships bash 3.2):
#   - no associative arrays, mapfile/readarray, ${var,,}/${var^^}, declare -n/-g, wait -n,
#     |&, &>>, coproc, printf '%(...)T', $EPOCHSECONDS
#   - never expand a possibly empty array with "${arr[@]}" (bash 3.2 + set -u treats it as
#     unbound); loop over an index up to a stored count instead
#   - works under "set -u"; does not use "set -e" (a failing check must not end the script)
#   - only tools that ship with macOS and mainstream Linux: no jq, python, nmap, Homebrew
#   - never calls sudo; sections that need root are reported as SKIPPED with instructions
#
# Risk Level    : Read-Only (defining functions has no side effects)
# Prerequisites : bash 3.2+ | root: No | Dependencies: none beyond the OS
# Version       : 1.0.0

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
#endregion MSPHelper:Net
