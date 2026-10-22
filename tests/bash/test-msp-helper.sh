#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# Unit tests for endpoint-systems/utilities/msp-toolkit-common.sh (development side only).
#
#   bash tests/bash/test-msp-helper.sh            run all tests, exit 1 on any failure
#   bash tests/bash/test-msp-helper.sh --emit DIR also write files for the PowerShell
#                                                 cross-checks in tests/Invoke-ToolkitTests.ps1:
#                                                 escape-cases.json/.hex, id-cases.txt, and a
#                                                 sample result export under DIR/export
#
# Sources the helper directly (scripts embed it instead). Uses only bash 3.2 features.
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
HELPER="$HERE/../../endpoint-systems/utilities/msp-toolkit-common.sh"
EMIT_DIR=''
if [ "${1-}" = '--emit' ]; then EMIT_DIR=${2-}; fi

# shellcheck source=../../endpoint-systems/utilities/msp-toolkit-common.sh
. "$HELPER"

PASSED=0
FAILED=0

check_eq() {
    # check_eq NAME EXPECTED ACTUAL
    if [ "$2" = "$3" ]; then
        PASSED=$((PASSED + 1))
    else
        FAILED=$((FAILED + 1))
        printf 'FAIL: %s\n  expected: [%s]\n  actual:   [%s]\n' "$1" "$2" "$3"
    fi
}

check_true() {
    # check_true NAME COMMAND... (passes when COMMAND succeeds)
    local name=$1
    shift
    if "$@"; then PASSED=$((PASSED + 1)); else FAILED=$((FAILED + 1)); printf 'FAIL: %s\n' "$name"; fi
}

check_false() {
    local name=$1
    shift
    if "$@"; then FAILED=$((FAILED + 1)); printf 'FAIL: %s (expected failure)\n' "$name"; else PASSED=$((PASSED + 1)); fi
}

# --- msp_json_escape ------------------------------------------------------------------------
check_eq 'escape: empty' '' "$(msp_json_escape '')"
check_eq 'escape: plain' 'hello world' "$(msp_json_escape 'hello world')"
check_eq 'escape: double quote' 'say \"hi\"' "$(msp_json_escape 'say "hi"')"
check_eq 'escape: backslash' 'C:\\Temp\\x' "$(msp_json_escape 'C:\Temp\x')"
# shellcheck disable=SC1003  # The argument is the text "end" followed by one backslash.
check_eq 'escape: trailing backslash' 'end\\' "$(msp_json_escape 'end\')"
check_eq 'escape: newline' 'a\nb' "$(msp_json_escape "a
b")"
check_eq 'escape: tab' 'a\tb' "$(msp_json_escape "$(printf 'a\tb')")"
check_eq 'escape: carriage return' 'a\rb' "$(msp_json_escape "$(printf 'a\rb')")"
check_eq 'escape: backspace' 'a\bb' "$(msp_json_escape "$(printf 'a\bb')")"
check_eq 'escape: form feed' 'a\fb' "$(msp_json_escape "$(printf 'a\fb')")"
check_eq 'escape: control 0x01' 'a\u0001b' "$(msp_json_escape "$(printf 'a\001b')")"
check_eq 'escape: control 0x1f' 'a\u001fb' "$(msp_json_escape "$(printf 'a\037b')")"
check_eq 'escape: escape char 0x1b' '\u001b[31m' "$(msp_json_escape "$(printf '\033[31m')")"
check_eq 'escape: DEL 0x7f' 'a\u007fb' "$(msp_json_escape "$(printf 'a\177b')")"
check_eq 'escape: UTF-8 passes through' 'café ✓ 日本' "$(msp_json_escape 'café ✓ 日本')"
check_eq 'escape: UTF-8 with quote' 'naïve \"x\"' "$(msp_json_escape 'naïve "x"')"
check_eq 'escape: printf specifiers untouched' '%s %d %%' "$(msp_json_escape '%s %d %%')"
check_eq 'escape: leading dash' '-n -e' "$(msp_json_escape '-n -e')"
check_eq 'escape: slash not escaped' 'a/b' "$(msp_json_escape 'a/b')"
check_eq 'escape: mixed' '\"\\\n\t' "$(msp_json_escape "$(printf '"\\\n\t')")"
check_eq 'json_str' '"x \"y\""' "$(msp_json_str 'x "y"')"
check_eq 'json_obj strings' '{"a":"1","b":"two \"2\""}' "$(msp_json_obj a 1 b 'two "2"')"
check_eq 'json_obj raw values' '{"Port":443,"Open":true,"Name":"SSH"}' "$(msp_json_obj Port# 443 Open# true Name SSH)"
check_eq 'json_obj empty' '{}' "$(msp_json_obj)"

# --- msp_json_flatten -----------------------------------------------------------------------
TAB=$(printf '\t')
flat=$(printf '%s' '{"name":"uBlock \"Origin\"","version":"1.2","permissions":["tabs","<all_urls>"],"nested":{"a":{"b":[1,{"c":true}]}},"esc":"a\\b\/c\nd","empty":"","n":null}' | msp_json_flatten -)
check_eq 'json flatten: string' ".name${TAB}uBlock \"Origin\"" "$(printf '%s\n' "$flat" | sed -n 1p)"
check_eq 'json flatten: array items' ".permissions[1]${TAB}<all_urls>" "$(printf '%s\n' "$flat" | grep '^\.permissions\[1\]')"
check_eq 'json flatten: deep path' ".nested.a.b[1].c${TAB}true" "$(printf '%s\n' "$flat" | grep '^\.nested\.a\.b\[1\]')"
check_eq 'json flatten: number in array' ".nested.a.b[0]${TAB}1" "$(printf '%s\n' "$flat" | grep '^\.nested\.a\.b\[0\]')"
check_eq 'json flatten: escapes' ".esc${TAB}a\\b/c d" "$(printf '%s\n' "$flat" | grep '^\.esc')"
check_eq 'json flatten: empty string kept' ".empty${TAB}" "$(printf '%s\n' "$flat" | grep '^\.empty')"
check_eq 'json flatten: null' ".n${TAB}null" "$(printf '%s\n' "$flat" | grep '^\.n	')"
check_eq 'json flatten: top-level array' "[1].id${TAB}x" "$(printf '[{"id":"w"},{"id":"x"}]' | msp_json_flatten - | sed -n 2p)"
check_eq 'json flatten: pretty-printed input' ".a.b${TAB}2" "$(printf '{\n  "a": {\n    "b": 2\n  }\n}\n' | msp_json_flatten -)"
check_eq 'json flatten: malformed input does not fail' '0' "$(printf '{"a": [1, 2' | msp_json_flatten - >/dev/null; echo $?)"

# --- msp_csv_field --------------------------------------------------------------------------
check_eq 'csv: plain' '"abc"' "$(msp_csv_field 'abc')"
check_eq 'csv: quotes doubled' '"say ""hi"""' "$(msp_csv_field 'say "hi"')"
check_eq 'csv: comma kept inside quotes' '"a,b"' "$(msp_csv_field 'a,b')"
check_eq 'csv: empty' '""' "$(msp_csv_field '')"

# --- msp_id_part ----------------------------------------------------------------------------
check_eq 'id: spaces and colon' 'Remote-access-tool-Kaseya' "$(msp_id_part 'Remote-access tool: Kaseya')"
check_eq 'id: leading/trailing symbols' 'Wi-Fi' "$(msp_id_part '  (Wi-Fi)  ')"
check_eq 'id: empty becomes General' 'General' "$(msp_id_part '')"
check_eq 'id: only symbols becomes General' 'General' "$(msp_id_part '!!!')"
check_eq 'id: UTF-8 collapses to one dash' 'caf-ok' "$(msp_id_part 'café ok')"
check_eq 'id: MAC' 'AA-BB-CC-00-11-22' "$(msp_id_part 'AA:BB:CC:00:11:22')"

# --- IPv4 math ------------------------------------------------------------------------------
check_eq 'ip_to_int' '3232235777' "$(msp_ip_to_int 192.168.1.1)"
check_eq 'ip_to_int zero' '0' "$(msp_ip_to_int 0.0.0.0)"
check_eq 'ip_to_int max' '4294967295' "$(msp_ip_to_int 255.255.255.255)"
check_eq 'ip_to_int leading zero is decimal' '168298504' "$(msp_ip_to_int 010.008.008.008)"
check_false 'ip_to_int rejects 256' msp_ip_to_int 192.168.1.256
check_false 'ip_to_int rejects 3 octets' msp_ip_to_int 192.168.1
check_false 'ip_to_int rejects 5 octets' msp_ip_to_int 1.2.3.4.5
check_false 'ip_to_int rejects letters' msp_ip_to_int 192.168.a.1
check_false 'ip_to_int rejects empty octet' msp_ip_to_int 192..1.1
check_eq 'int_to_ip' '10.1.101.245' "$(msp_int_to_ip "$(msp_ip_to_int 10.1.101.245)")"
check_eq 'mask dotted /24' '24' "$(msp_mask_to_prefix 255.255.255.0)"
check_eq 'mask dotted /22' '22' "$(msp_mask_to_prefix 255.255.252.0)"
check_eq 'mask hex (macOS) /24' '24' "$(msp_mask_to_prefix 0xffffff00)"
check_eq 'mask hex /16' '16' "$(msp_mask_to_prefix 0xffff0000)"

# Subnet helpers with a hand-set subnet (no network access needed).
MSP_NET_NETWORK_INT=$(msp_ip_to_int 192.168.50.0)
MSP_NET_BROADCAST_INT=$(msp_ip_to_int 192.168.50.255)
check_true 'in subnet: host' msp_ip_in_subnet 192.168.50.10
check_false 'in subnet: network address excluded' msp_ip_in_subnet 192.168.50.0
check_false 'in subnet: broadcast excluded' msp_ip_in_subnet 192.168.50.255
check_false 'in subnet: other subnet' msp_ip_in_subnet 192.168.51.10
check_eq 'subnet_hosts count /24' '254' "$(msp_subnet_hosts | wc -l | tr -d ' ')"
check_eq 'subnet_hosts first' '192.168.50.1' "$(msp_subnet_hosts | head -n 1)"
check_eq 'subnet_hosts last' '192.168.50.254' "$(msp_subnet_hosts | tail -n 1)"

# --- MAC helpers ----------------------------------------------------------------------------
check_eq 'mac normalize macOS short octets' '00:1A:2B:03:04:05' "$(msp_normalize_mac '0:1a:2b:3:4:5')"
check_eq 'mac normalize dashes' 'AA:BB:CC:DD:EE:FF' "$(msp_normalize_mac 'aa-bb-cc-dd-ee-ff')"
check_eq 'mac normalize rejects junk' '' "$(msp_normalize_mac 'incomplete')"
check_true 'mac randomized x2' msp_mac_is_randomized 'A2:11:22:33:44:55'
check_true 'mac randomized xE' msp_mac_is_randomized '1E:11:22:33:44:55'
check_false 'mac vendor-assigned' msp_mac_is_randomized '00:1A:2B:03:04:05'

# --- Virtual interface names ----------------------------------------------------------------
for i in utun3 tun0 wg0 tailscale0 docker0 br-12ab veth9 virbr0 vboxnet0 vmnet8 ppp0 bridge100 lo0 awdl0; do
    check_true "virtual iface $i" msp_is_virtual_iface "$i"
done
for i in en0 en1 eth0 wlan0 wlp2s0 enp3s0; do
    check_false "physical iface $i" msp_is_virtual_iface "$i"
done

# --- MAC vendor hint ------------------------------------------------------------------------
msp_mac_vendor 'b8:27:eb:12:34:56'
check_eq 'vendor: table hit (lowercase input)' 'Raspberry Pi|Single-board computer|0' "$MSP_VENDOR|$MSP_VENDOR_HINT|$MSP_VENDOR_RANDOM"
msp_mac_vendor 'B8-27-EB-12-34-56'
check_eq 'vendor: dashes accepted' 'Raspberry Pi' "$MSP_VENDOR"
msp_mac_vendor 'AE:11:22:00:00:01'
check_eq 'vendor: randomized MAC' 'Private/randomized MAC|1' "$MSP_VENDOR|$MSP_VENDOR_RANDOM"
msp_mac_vendor '00:00:00:00:00:01'
check_eq 'vendor: unknown' 'Unknown||0' "$MSP_VENDOR|$MSP_VENDOR_HINT|$MSP_VENDOR_RANDOM"
msp_mac_vendor ''
check_eq 'vendor: empty' 'Unknown' "$MSP_VENDOR"
check_true 'loopback 127.0.0.1' msp_is_loopback 127.0.0.1
check_true 'loopback ::1' msp_is_loopback ::1
check_false 'not loopback *' msp_is_loopback '*'
check_false 'not loopback 0.0.0.0' msp_is_loopback 0.0.0.0

# --- Listening sockets, with stubbed netstat / ss output (no real sockets read) -------------
STUB_DIR=$(mktemp -d "${TMPDIR:-/tmp}/msp-stub.XXXXXX")
cat >"$STUB_DIR/netstat" <<'STUB'
#!/bin/sh
cat <<'OUT'
Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)      rxbytes txbytes rhiwat shiwat process:pid state options gencnt flags flags1 usecnt rtncnt fltrs
tcp4       0      0  127.0.0.1.10175        *.*                    LISTEN       0 0 131072 131072 Code Helper (Plu:5444 00100 00000106 0 1 800 1 0 0
tcp6       0      0  *.22                   *.*                    LISTEN       0 0 131072 131072 launchd:1 00100 00000006 0 1 800 1 0 0
tcp4       0      0  192.168.50.5.51000     17.1.2.3.443           ESTABLISHED  0 0 131072 131072 Safari:900 00100 00000006 0 1 800 1 0 0
OUT
STUB
cat >"$STUB_DIR/ss" <<'STUB'
#!/bin/sh
cat <<'OUT'
State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
LISTEN 0      4096   127.0.0.53%lo:53     0.0.0.0:*       users:(("systemd-resolve",pid=600,fd=14))
LISTEN 0      128    0.0.0.0:22           0.0.0.0:*
LISTEN 0      128    [::]:22              [::]:*
LISTEN 0      5      *:631                *:*             users:(("cupsd",pid=777,fd=7))
OUT
STUB
cat >"$STUB_DIR/ps" <<'STUB'
#!/bin/sh
printf '    1 /sbin/launchd\n 5444 /Applications/X.app/Code Helper (Plugin)\n  600 /lib/systemd/systemd-resolved\n  777 /usr/sbin/cupsd\n'
STUB
chmod +x "$STUB_DIR"/*
SAVED_PATH=$PATH
PATH="$STUB_DIR:$PATH"
MSP_PLATFORM='macOS'
out=$(msp_listening_tcp)
check_eq 'listen macOS: rows (ESTABLISHED ignored)' '2' "$(printf '%s\n' "$out" | grep -c .)"
check_eq 'listen macOS: process name with spaces' '10175|127.0.0.1|5444|Code Helper (Plugin)' "$(printf '%s\n' "$out" | head -n 1)"
check_eq 'listen macOS: wildcard address' '22|*|1|launchd' "$(printf '%s\n' "$out" | sed -n 2p)"
MSP_PLATFORM='Linux'
out=$(msp_listening_tcp)
check_eq 'listen Linux: rows (header ignored)' '4' "$(printf '%s\n' "$out" | grep -c .)"
check_eq 'listen Linux: scoped address and pid' '53|127.0.0.53|600|systemd-resolved' "$(printf '%s\n' "$out" | head -n 1)"
check_eq 'listen Linux: no process info without root' '22|0.0.0.0||' "$(printf '%s\n' "$out" | sed -n 2p)"
check_eq 'listen Linux: IPv6 brackets removed' '22|::||' "$(printf '%s\n' "$out" | sed -n 3p)"
PATH=$SAVED_PATH
MSP_PLATFORM=''
rm -rf "$STUB_DIR"

# --- msp_run_timeout ------------------------------------------------------------------------
start=$(date +%s)
msp_run_timeout 1 sleep 5
rc=$?
elapsed=$(($(date +%s) - start))
check_eq 'timeout: stopped command returns 124' '124' "$rc"
check_true 'timeout: stopped within 3s' [ "$elapsed" -le 3 ]
msp_run_timeout 5 true
check_eq 'timeout: fast command keeps its exit code 0' '0' "$?"
msp_run_timeout 5 sh -c 'exit 3'
check_eq 'timeout: fast command keeps its exit code 3' '3' "$?"
check_eq 'timeout: output passes through' 'hi' "$(msp_run_timeout 5 echo hi)"

# --- msp_parallel never exceeds its limit (or 32) -------------------------------------------
PAR_DIR=$(mktemp -d "${TMPDIR:-/tmp}/msp-test.XXXXXX")
mkdir -p "$PAR_DIR/live" "$PAR_DIR/out"
par_job() {
    # Records how many jobs are running at once, using one marker file per running job.
    : >"$PAR_DIR/live/$1"
    find "$PAR_DIR/live" -type f | wc -l | tr -d ' '
    sleep 0.3
    rm -f "$PAR_DIR/live/$1"
}
i=1
while [ "$i" -le 20 ]; do printf '%s\n' "$i"; i=$((i + 1)); done | msp_parallel 5 "$PAR_DIR/out" par_job
max=$(cat "$PAR_DIR/out"/*.out | sort -n | tail -n 1)
check_eq 'parallel: all 20 jobs ran' '20' "$(cat "$PAR_DIR/out"/*.out | wc -l | tr -d ' ')"
check_true "parallel: at most 5 at once (saw $max)" [ "$max" -le 5 ]
rm -f "$PAR_DIR/out"/*.out
i=1
while [ "$i" -le 80 ]; do printf '%s\n' "$i"; i=$((i + 1)); done | msp_parallel 100 "$PAR_DIR/out" par_job
max=$(cat "$PAR_DIR/out"/*.out | sort -n | tail -n 1)
check_true "parallel: capped at 32 even when 100 requested (saw $max)" [ "$max" -le 32 ]
rm -rf "$PAR_DIR"

# --- End-to-end run: findings, data, ticket block, export ----------------------------------
RUN_TMP=$(mktemp -d "${TMPDIR:-/tmp}/msp-test.XXXXXX")
OUT_DIR="$RUN_TMP/export"
[ -n "$EMIT_DIR" ] && OUT_DIR="$EMIT_DIR/export"
(
    export TMPDIR="$RUN_TMP"
    msp_param OutputPath "$OUT_DIR"
    msp_param Note 'quote " backslash \ tab	end'
    msp_init 'test-msp-helper' '1.0.0' 'T1' 'Read-Only' 'Helper self-test' 'nothing'
    msp_section 'Checks'
    msp_finding --status PASS --category 'Firewall' --check 'Firewall enabled' --detail 'On'
    msp_finding --status WARN --category 'Software' --check 'Remote tool: AnyDesk' --detail 'Installed "today"' --rec 'Confirm with the client.' --evidence "$(msp_json_obj Tool AnyDesk Running# true)"
    msp_finding --status FAIL --severity Critical --category 'Disk' --check 'Encryption' --detail "Line one
line two" --rec 'Turn it on.'
    msp_finding --status SKIPPED --category 'Disk' --check 'Recovery key' --detail 'Needs sudo'
    msp_finding --status INFO --check 'Unicode' --detail 'café ✓'
    # shellcheck disable=SC2329  # Called through msp_check.
    failing_check() { printf 'Permission denied: /secret\n' >&2; return 1; }
    msp_check 'Perms' 'Failing check' failing_check
    # shellcheck disable=SC2329  # Called through msp_check.
    silent_ok() { return 0; }
    msp_check 'Perms' 'Quiet check' silent_ok
    msp_data_row 'Devices' IP 192.168.1.10 MAC 'AA:BB:CC:DD:EE:FF' Ports# 3 Note 'has "quotes", commas'
    msp_data_row 'Devices' IP 192.168.1.11 MAC '' Ports# 0 Note ''
    msp_data_row 'Empty note' Key k
    # A table first created inside a pipeline (a subshell), then a new table in the main shell:
    # both must be exported, each with its own rows.
    printf 'r1\nr2\n' | while read -r r; do msp_data_row 'FromPipe' Row "$r"; done
    msp_data_row 'AfterPipe' Col x
    msp_complete "$OUT_DIR"
) >"$RUN_TMP/console.txt" 2>&1
json=$(find "$OUT_DIR" -name 'test-msp-helper_*.json' 2>/dev/null | head -n 1)
csv=$(find "$OUT_DIR" -name 'test-msp-helper_*_findings.csv' 2>/dev/null | head -n 1)
check_true 'export: JSON written' [ -n "$json" ]
check_true 'export: findings CSV written' [ -n "$csv" ]
check_true 'export: Devices CSV written' [ -n "$(ls "$OUT_DIR"/test-msp-helper_*_Devices.csv 2>/dev/null)" ]
check_eq 'export: table created in a pipeline kept' '"Row" "r1" "r2"' "$(cat "$OUT_DIR"/test-msp-helper_*_FromPipe.csv 2>/dev/null | paste -sd ' ' -)"
check_eq 'export: next table gets its own file' '"Col" "x"' "$(cat "$OUT_DIR"/test-msp-helper_*_AfterPipe.csv 2>/dev/null | paste -sd ' ' -)"
if [ -n "$json" ]; then
    check_true 'json: schema 2.0' grep -q '"SchemaVersion": "2.0"' "$json"
    check_true 'json: CheckId T1' grep -q '"CheckId": "T1"' "$json"
    check_true 'json: ERROR from failing check' grep -q '"Id": "T1.Perms.Failing-check".*"Status": "ERROR"' "$json"
    check_true 'json: friendly permission message' grep -q 'denied access for the current account' "$json"
    check_true 'json: newline escaped in detail' grep -q 'Line one\\nline two' "$json"
    check_true 'json: summary counts' grep -q '"Summary": {"PASS": 1, "WARN": 1, "FAIL": 1, "INFO": 1, "SKIPPED": 1, "ERROR": 1}' "$json"
    check_true 'json: evidence object raw' grep -q '"Evidence": {"Tool":"AnyDesk","Running":true}' "$json"
    check_true 'json: no CR characters' sh -c "! grep -q \"\$(printf '\r')\" '$json'"
fi
if [ -n "$csv" ]; then
    check_eq 'csv: header' '"CheckId","ScriptName","Platform","Host","Timestamp","Id","Category","Check","Status","Severity","Target","Detail","Recommendation"' "$(head -n 1 "$csv")"
fi
check_true 'console: ticket block printed' grep -q 'COPY FOR TICKET' "$RUN_TMP/console.txt"
check_true 'console: ERROR explained as not a failure' grep -q 'not the same as a failed check' "$RUN_TMP/console.txt"
check_true 'console: plain text when not a terminal' sh -c "! grep -q \"\$(printf '\033')\" '$RUN_TMP/console.txt'"
check_true 'console: FAIL listed first' sh -c "grep -A1 'Issues (most severe first)' '$RUN_TMP/console.txt' | grep -q 'FAIL/Critical'"
log=$(find "$RUN_TMP/msp-toolkit" -name 'test-msp-helper_*.log' 2>/dev/null | head -n 1)
check_true "log: written under TMPDIR/msp-toolkit" [ -n "$log" ]
if [ -n "$log" ]; then
    check_true 'log: START line' grep -q '===== START test-msp-helper v1.0.0 (T1) =====' "$log"
    check_true 'log: parameters' grep -q 'Parameters: OutputPath=' "$log"
    check_true 'log: END line' grep -q '===== END ' "$log"
fi
check_true 'cleanup: run temp folder removed' sh -c "! ls -d '$RUN_TMP'/msp-run.* >/dev/null 2>&1"

# --- Files for the PowerShell cross-checks ---------------------------------------------------
if [ -n "$EMIT_DIR" ]; then
    mkdir -p "$EMIT_DIR"
    # Escape cases: JSON array of escaped strings + one hex line per original string (the
    # PowerShell side decodes the JSON and compares the UTF-8 bytes).
    cases_file="$EMIT_DIR/escape-cases.json"
    hex_file="$EMIT_DIR/escape-cases.hex"
    : >"$hex_file"
    printf '[' >"$cases_file"
    sep=''
    # shellcheck disable=SC1003  # The Windows path case ends with one literal backslash.
    for s in '' 'plain' 'say "hi"' 'C:\Temp\' "$(printf 'a\nb\tc\rd')" "$(printf 'x\001y\037z\177')" \
        "$(printf '\033[0m')" 'café ✓ 日本' '%s %d' "$(printf 'b\bf\f')"; do
        printf '%s%s' "$sep" "$(msp_json_str "$s")" >>"$cases_file"
        printf '%s' "$s" | od -An -tx1 | tr -d ' \n' >>"$hex_file"
        printf '\n' >>"$hex_file"
        sep=','
    done
    printf ']\n' >>"$cases_file"
    # ID cases: "input<TAB>bash result" per line, compared with ConvertTo-MSPIdPart.
    : >"$EMIT_DIR/id-cases.txt"
    for s in 'Remote-access tool: Kaseya' '  (Wi-Fi)  ' '' '!!!' 'café ok' 'AA:BB:CC:00:11:22' 'Firewall / stealth mode'; do
        printf '%s\t%s\n' "$s" "$(msp_id_part "$s")" >>"$EMIT_DIR/id-cases.txt"
    done
    # Vendor cases: "MAC<TAB>Vendor|Hint|true/false" for every table entry plus edge cases,
    # compared with Get-MSPMacVendor.
    : >"$EMIT_DIR/vendor-cases.txt"
    { msp__oui_data | cut -d'|' -f1 | sed 's/$/:01:02:03/'; printf '%s\n' 'AE:11:22:33:44:55' '02:00:00:00:00:00' '00:00:00:00:00:01' 'zz' 'b8-27-eb-aa-bb-cc'; } |
        while IFS= read -r mac; do
            msp_mac_vendor "$mac"
            r=false
            [ "$MSP_VENDOR_RANDOM" -eq 1 ] && r=true
            printf '%s\t%s|%s|%s\n' "$mac" "$MSP_VENDOR" "$MSP_VENDOR_HINT" "$r" >>"$EMIT_DIR/vendor-cases.txt"
        done
fi
# --- Change section (confirmation never proceeds without a person or --force) ------------------
out=$( (msp_confirm_change 'Make 2 changes?' 0 </dev/null >/dev/null; rc=$?; printf '%s|%s|%s' "$rc" "${MSP_F_STATUS[$((MSP_F_COUNT - 1))]}" "${MSP_F_CHECK[$((MSP_F_COUNT - 1))]}") )
check_eq 'confirm: non-interactive without force refuses (SKIPPED)' '1|SKIPPED|Confirmation' "$out"
out=$( (msp_confirm_change 'Make 2 changes?' 1 </dev/null >/dev/null; rc=$?; printf '%s|%s|%s' "$rc" "${MSP_F_STATUS[$((MSP_F_COUNT - 1))]}" "${MSP_F_DETAIL[$((MSP_F_COUNT - 1))]}") )
check_eq 'confirm: --force goes ahead and says so' '0|INFO|Not asked: --force was given.' "$out"
check_false 'interactive: false with redirected input' msp_is_interactive </dev/null
check_eq 'what if line' 'What if: Restart on "cupsd".' "$(MSP_COLOR=0 msp_what_if cupsd Restart)"
check_eq 'change plan numbered' '  2. Flush the DNS cache' "$(MSP_COLOR=0 msp_change_plan 'Restart cupsd' 'Flush the DNS cache' | tail -n 1)"

rm -rf "$RUN_TMP"

printf '\n%s passed, %s failed (bash %s)\n' "$PASSED" "$FAILED" "$BASH_VERSION"
[ "$FAILED" -eq 0 ]
