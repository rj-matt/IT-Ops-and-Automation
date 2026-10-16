#!/usr/bin/env bash
# shellcheck disable=SC2016  # Stub bodies are written with single quotes on purpose: they expand when the stub runs.
# Logic tests for the bash scripts that run on ANY computer, including a Mac: the platform
# commands they call (uname, lsblk, systemctl, apt-get, nmcli, ip, ss, networksetup,
# system_profiler, plutil, ...) are replaced by stubs that print sample output, and configuration
# files are read from a fake root (MSP_TEST_ROOT). Covers the -linux.sh scripts, the Linux
# branches of the shared scripts, and macOS paths this computer cannot reach on its own (root-only
# files, VPN-only routing, visible vs hidden Wi-Fi names).
#
# No network traffic is possible: ping, nc, curl, getent hosts and the rest are stubs. In the
# passive cases they fail and leave a marker (checked at the end). The "active logic" cases use
# stubs that answer for addresses in 198.51.100.0/24 (TEST-NET-2, reserved for documentation and
# never routed), so the ping-sweep and port-check code runs without a single packet being sent.
#
# This tests the scripts' parsing and rating logic, not that the real commands behave as the
# samples assume; that needs a real machine (see the runtime cases in Invoke-ToolkitTests.ps1).
#
#   bash tests/bash/test-scripts-mocked.sh [--keep]   exit 1 on any failure; --keep leaves the work folder
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
KEEP=0
[ "${1-}" = '--keep' ] && KEEP=1
WORK=$(mktemp -d "${TMPDIR:-/tmp}/msp-mock.XXXXXX")
PASSED=0
FAILED=0
REAL_DATE=$(command -v date)
REAL_STAT=$(command -v stat)

check() {
    # check NAME FILE REGEX - passes when the regex matches a line of FILE.
    if grep -Eq -- "$3" "$2"; then PASSED=$((PASSED + 1)); else FAILED=$((FAILED + 1)); printf 'FAIL: %s\n  pattern: %s\n  output:  %s\n' "$1" "$3" "$2"; fi
}

check_not() {
    if grep -Eq -- "$3" "$2"; then FAILED=$((FAILED + 1)); printf 'FAIL: %s (unexpected match)\n  pattern: %s\n  output:  %s\n' "$1" "$3" "$2"; else PASSED=$((PASSED + 1)); fi
}

check_exists() {
    # check_exists NAME PATH... - passes when the first path (usually a glob result) exists.
    if [ -e "$2" ]; then PASSED=$((PASSED + 1)); else FAILED=$((FAILED + 1)); printf 'FAIL: %s (%s not found)\n' "$1" "$2"; fi
}

stub() {
    # stub DIR NAME BODY - an executable NAME in DIR running BODY with /bin/sh.
    printf '#!/bin/sh\n%s\n' "$3" >"$1/$2"
    chmod +x "$1/$2"
}

new_env() {
    # new_env NAME - fresh stub folder and fake root. Sets BIN and FAKE.
    BIN="$WORK/$1/bin"
    FAKE="$WORK/$1/root"
    mkdir -p "$BIN" "$FAKE"
    # Identity of the fake computer.
    stub "$BIN" uname 'case "$1" in -s) echo Linux ;; -n) echo mockhost ;; -r) echo 6.8.0-mock ;; *) echo Linux ;; esac'
    # The signed-in user is "alice" (uid 1000); her groups come from the fake /etc/group.
    stub "$BIN" id 'case "$1" in -u) echo 1000 ;; -un) echo alice ;; -Gn) awk -F: -v u="${2:-alice}" '"'"'BEGIN { printf "%s", u } { n = split($4, m, ","); for (i = 1; i <= n; i++) if (m[i] == u) printf " %s", $1 } END { print "" }'"'"' "'"$FAKE"'/etc/group" 2>/dev/null ;; *) echo "uid=1000(alice)" ;; esac'
    # GNU forms used by -linux.sh scripts, mapped onto whatever date/stat this computer has.
    stub "$BIN" date "case \"\$1\" in -d) e=\${2#@}; shift 2; if $REAL_DATE -d @0 >/dev/null 2>&1; then exec $REAL_DATE -d @\$e \"\$@\"; else exec $REAL_DATE -r \$e \"\$@\"; fi ;; *) exec $REAL_DATE \"\$@\" ;; esac"
    stub "$BIN" stat "if [ \"\$1\" = -c ]; then shift 2; if $REAL_STAT -c %Y / >/dev/null 2>&1; then exec $REAL_STAT -c %Y \"\$@\"; else exec $REAL_STAT -f %m \"\$@\"; fi; else exec $REAL_STAT \"\$@\"; fi"
    # Anything that would send traffic fails loudly and leaves a marker.
    for c in ping nc curl wget dig nslookup host avahi-resolve; do
        stub "$BIN" "$c" "echo \"NETWORK STUB CALLED: $c \$*\" >>\"$WORK/$1/network-calls\"; exit 1"
    done
    stub "$BIN" getent 'case "$1" in
        hosts) echo "NETWORK STUB CALLED: getent hosts" >>"'"$WORK/$1/network-calls"'"; exit 2 ;;
        group) [ -f "'"$FAKE"'/etc/group" ] && grep "^$2:" "'"$FAKE"'/etc/group" ;;
        passwd) if [ -n "${2-}" ]; then grep "^$2:" "'"$FAKE"'/etc/passwd"; else cat "'"$FAKE"'/etc/passwd"; fi ;;
    esac'
    : >"$WORK/$1/network-calls"
}

run_script() {
    # run_script ENV SCRIPT OUTFILE [ARGS...] - runs a script under the same bash as this test
    # (so "/bin/bash tests/..." on a Mac tests bash 3.2), with the stubs first on PATH, the
    # fake root, and stdin closed.
    local env=$1 script=$2 out=$3
    shift 3
    PATH="$WORK/$env/bin:$PATH" MSP_TEST_ROOT="$WORK/$env/root" TMPDIR="$WORK/$env" NO_COLOR=1 \
        "$BASH" "$REPO/$script" "$@" </dev/null >"$out" 2>&1
    printf '%s\n' "$?" >"$out.rc"
}

# =========================================================================================
# A1 get-endpoint-security-status-linux.sh
# =========================================================================================
A1=security-operations/diagnostics/endpoint-posture/get-endpoint-security-status-linux.sh

# --- Scenario 1: Ubuntu laptop with several problems ---------------------------------------
new_env a1-ubuntu
mkdir -p "$FAKE/etc/ufw" "$FAKE/etc/apt/apt.conf.d" "$FAKE/usr/bin" "$FAKE/var/lib/dpkg" "$FAKE/var/lib/apt/lists" \
    "$FAKE/etc/gdm3" "$FAKE/etc/ssh/sshd_config.d" "$FAKE/sys/firmware/efi" "$FAKE/sys/class/power_supply/BAT0" \
    "$FAKE/sys/module/apparmor/parameters"
printf 'ENABLED=no\n' >"$FAKE/etc/ufw/ufw.conf"
printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' >"$FAKE/etc/apt/apt.conf.d/20auto-upgrades"
: >"$FAKE/usr/bin/unattended-upgrade"
: >"$FAKE/var/lib/dpkg/status"
: >"$FAKE/var/lib/apt/lists/archive.ubuntu.com_ubuntu_dists_noble_InRelease"
printf '[daemon]\nAutomaticLoginEnable=True\nAutomaticLogin=kid\n' >"$FAKE/etc/gdm3/custom.conf"
printf 'PermitRootLogin yes\n' >"$FAKE/etc/ssh/sshd_config"
printf 'Y\n' >"$FAKE/sys/module/apparmor/parameters/enabled"
printf 'sudo:x:27:alice,bob\nadmin:x:118:\n' >"$FAKE/etc/group"
printf 'root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\ntoor:x:0:0::/root:/bin/bash\n' >"$FAKE/etc/passwd"
stub "$BIN" findmnt 'echo /dev/mapper/vgubuntu-root'
stub "$BIN" lsblk 'printf "lvm\ncrypt\npart\ndisk\n"'
stub "$BIN" systemctl 'case "$2" in ssh) echo active ;; *) echo inactive ;; esac'
stub "$BIN" apt-get 'printf "Reading package lists...\nInst openssl [3.0.13-0ubuntu3.1] (3.0.13-0ubuntu3.4 Ubuntu:24.04/noble-security [amd64])\nInst vim [2:9.1.0016-1ubuntu7] (2:9.1.0016-1ubuntu7.2 Ubuntu:24.04/noble-updates [amd64])\nConf openssl\n"'
stub "$BIN" mokutil 'echo "SecureBoot disabled"'
stub "$BIN" ss 'printf "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\nLISTEN 0 128 0.0.0.0:22 0.0.0.0:*\nLISTEN 0 5 0.0.0.0:3389 0.0.0.0:*\nLISTEN 0 5 127.0.0.1:631 0.0.0.0:*\n"'
stub "$BIN" ps 'true'
OUT="$WORK/a1-ubuntu.txt"
run_script a1-ubuntu "$A1" "$OUT" --output "$WORK/a1-ubuntu/export"
check 'A1 ubuntu: exit 0' "$OUT.rc" '^0$'
check 'A1 ubuntu: platform Linux in banner' "$OUT" 'Computer: mockhost \(Linux 6\.8\.0-mock\)'
check 'A1 ubuntu: firewall off on a laptop = WARN' "$OUT" '\[WARN\] +Firewall - No active firewall found .* laptop'
check 'A1 ubuntu: LUKS under LVM = PASS' "$OUT" '\[PASS\] +System drive encryption - .*encrypted'
check 'A1 ubuntu: security update pending = FAIL' "$OUT" '\[FAIL\] +Pending updates - 1 security update\(s\) waiting \(2 in total'
check 'A1 ubuntu: unattended-upgrades = PASS' "$OUT" '\[PASS\] +Automatic security updates - On \(unattended-upgrades\)'
check 'A1 ubuntu: sudo members listed' "$OUT" 'Local administrators - alice \(sudo\); bob \(sudo\)'
check 'A1 ubuntu: daily account in sudo = WARN' "$OUT" '\[WARN\] +Daily account has admin rights - The signed-in account \(alice\)'
check 'A1 ubuntu: extra UID 0 account = FAIL' "$OUT" '\[FAIL\] +Extra root accounts - .*toor'
check 'A1 ubuntu: GDM automatic login = WARN' "$OUT" '\[WARN\] +Automatic login - .*kid \(GDM\)'
check 'A1 ubuntu: root password needs sudo = SKIPPED' "$OUT" '\[SKIPPED\] Root account - Skipped: requires root'
check 'A1 ubuntu: Secure Boot off = WARN' "$OUT" '\[WARN\] +Secure Boot - Supported \(UEFI\) but turned off'
check 'A1 ubuntu: AppArmor = PASS' "$OUT" '\[PASS\] +SELinux / AppArmor - AppArmor is enabled'
check 'A1 ubuntu: SSH running = WARN' "$OUT" '\[WARN\] +Remote login \(SSH\)'
check 'A1 ubuntu: PermitRootLogin yes = FAIL' "$OUT" '\[FAIL\] +SSH root login'
check 'A1 ubuntu: RDP listening = WARN' "$OUT" '\[WARN\] +Remote Desktop - RDP \(port 3389'
check_not 'A1 ubuntu: no ERROR findings' "$OUT" '\[ERROR\]'
check_exists 'A1 ubuntu: JSON exported' "$WORK/a1-ubuntu/export"/*.json

# --- Scenario 2: Fedora desktop, firewalld on, not encrypted, cache-only dnf ----------------
new_env a1-fedora
mkdir -p "$FAKE/etc" "$FAKE/var/cache/dnf/fedora-1/repodata" "$FAKE/var/lib/rpm"
: >"$FAKE/var/cache/dnf/fedora-1/repodata/repomd.xml"
: >"$FAKE/var/lib/rpm/rpmdb.sqlite"
printf 'wheel:x:10:carol\n' >"$FAKE/etc/group"
printf 'root:x:0:0:root:/root:/bin/bash\ncarol:x:1000:1000::/home/carol:/bin/bash\n' >"$FAKE/etc/passwd"
stub "$BIN" findmnt 'echo "/dev/nvme0n1p3[/root]"'
stub "$BIN" lsblk 'printf "part\ndisk\n"'
stub "$BIN" systemctl 'case "$1 $2" in "is-active firewalld") echo active ;; "is-enabled dnf-automatic-install.timer") echo disabled ;; *) echo inactive ;; esac'
stub "$BIN" dnf 'case "$*" in *check-update*) printf "\nkernel.x86_64  6.9.1-200.fc40  updates\n"; exit 100 ;; *updateinfo*) exit 0 ;; esac'
stub "$BIN" getenforce 'echo Enforcing'
stub "$BIN" ss 'printf "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"'
stub "$BIN" ps 'true'
OUT="$WORK/a1-fedora.txt"
run_script a1-fedora "$A1" "$OUT"
check 'A1 fedora: exit 0' "$OUT.rc" '^0$'
check 'A1 fedora: firewalld = PASS' "$OUT" '\[PASS\] +Firewall - Active: firewalld'
check 'A1 fedora: unencrypted desktop = WARN (not FAIL)' "$OUT" '\[WARN\] +System drive encryption - The root filesystem \(/dev/nvme0n1p3\) is not encrypted on this desktop'
check 'A1 fedora: dnf cache, non-security update = WARN' "$OUT" '\[WARN\] +Pending updates - 1 non-security update'
check 'A1 fedora: dnf-automatic off = WARN' "$OUT" '\[WARN\] +Automatic security updates'
check 'A1 fedora: wheel members listed' "$OUT" 'Local administrators - carol \(wheel\)'
check 'A1 fedora: daily account not in wheel = PASS' "$OUT" '\[PASS\] +Daily account has admin rights - alice cannot use sudo'
check 'A1 fedora: legacy/UEFI unknown -> BIOS warning' "$OUT" 'Secure Boot - The computer starts in legacy BIOS mode'
check 'A1 fedora: SELinux enforcing = PASS' "$OUT" '\[PASS\] +SELinux / AppArmor - SELinux is enforcing'
check 'A1 fedora: no SSH = PASS' "$OUT" '\[PASS\] +Remote login \(SSH\) - No SSH server running'
check_not 'A1 fedora: no ERROR findings' "$OUT" '\[ERROR\]'

# --- Scenario 3: wrong platform is refused --------------------------------------------------
new_env a1-mac
stub "$BIN" uname 'echo Darwin'
OUT="$WORK/a1-mac.txt"
run_script a1-mac "$A1" "$OUT"
check 'A1 linux script refuses macOS (exit 2)' "$OUT.rc" '^2$'

# =========================================================================================
# Shared Linux network stubs (A2, A4)
# =========================================================================================
linux_net() {
    # linux_net ROUTE_LINE ADDR_LINE - ip stub for "ip -4 route/addr/neigh". The neighbor table
    # comes from $WORK/<env>/neigh.txt so each scenario can set it.
    local env_dir
    env_dir=$(dirname "$BIN")
    printf '%s\n' "$1" >"$env_dir/route.txt"
    printf '%s\n' "$2" >"$env_dir/addr.txt"
    : >"$env_dir/neigh.txt"
    stub "$BIN" ip 'case "$*" in
        *"route show default"*) cat "'"$env_dir"'/route.txt" ;;
        *"addr show"*) cat "'"$env_dir"'/addr.txt" ;;
        *"neigh show"*) cat "'"$env_dir"'/neigh.txt" ;;
    esac'
    stub "$BIN" ps 'true'
    stub "$BIN" resolvectl 'echo "Global: 198.51.100.1"'
}

# =========================================================================================
# A2 get-home-network-map.sh (Linux branch)
# =========================================================================================
A2=core-infrastructure/networking/diagnostics/get-home-network-map.sh

# --- Passive: neighbor table only, nothing sent --------------------------------------------
new_env a2-passive
linux_net 'default via 198.51.100.1 dev wlp2s0 proto dhcp metric 600' '3: wlp2s0    inet 198.51.100.23/24 brd 198.51.100.255 scope global dynamic wlp2s0'
cat >"$WORK/a2-passive/neigh.txt" <<'NEIGH'
198.51.100.1 lladdr 00:09:5b:11:22:33 REACHABLE
198.51.100.40 lladdr 00:1e:8f:44:55:66 STALE
198.51.100.41 lladdr 18:b4:30:00:00:01 STALE
198.51.100.50 lladdr 3a:11:22:33:44:55 STALE
198.51.100.60 lladdr 00:00:01:02:03:04 STALE
198.51.100.61 lladdr 00:00:01:02:03:04 STALE
198.51.100.70 FAILED
203.0.113.9 lladdr 00:00:01:99:99:99 STALE
NEIGH
OUT="$WORK/a2-passive.txt"
run_script a2-passive "$A2" "$OUT" --passive --output "$WORK/a2-passive/export"
check 'A2 passive: exit 0' "$OUT.rc" '^0$'
check 'A2 passive: says nothing is sent' "$OUT" 'Passive: nothing is sent'
check 'A2 passive: scope printed' "$OUT" 'Range   : 198\.51\.100\.1 - 198\.51\.100\.254  \(254 addresses, subnet 198\.51\.100\.0/24\)'
check 'A2 passive: 7 devices incl. this computer (FAILED and off-subnet entries dropped)' "$OUT" 'Devices found - 7 device\(s\)'
check 'A2 passive: router identified by gateway' "$OUT" 'Router / gateway - 198\.51\.100\.1, MAC 00:09:5B:11:22:33, vendor hint: Netgear'
check 'A2 passive: printer from vendor table' "$OUT" '198\.51\.100\.40 +00:1E:8F:44:55:66 +Canon'
check 'A2 passive: private MAC noted' "$OUT" 'Devices with private MAC addresses - 1 device\(s\).*198\.51\.100\.50'
check 'A2 passive: unknown vendor flagged' "$OUT" '\[WARN\] +Unidentified device - 198\.51\.100\.60'
check 'A2 passive: shared MAC noted' "$OUT" 'Same MAC on several IPs - MAC 00:00:01:02:03:04 answers for 198\.51\.100\.60, 198\.51\.100\.61'
check 'A2 passive: Nest counted as smart-home' "$OUT" 'Smart-home / IoT devices - 1'
check_not 'A2 passive: off-subnet neighbor ignored' "$OUT" '203\.0\.113\.9'
check_not 'A2 passive: no pinging' "$OUT" 'Pinging'
json=$(find "$WORK/a2-passive/export" -name "*.json" 2>/dev/null | head -n 1)
check_exists 'A2 passive: JSON exported' "$json"
[ -n "$json" ] && check 'A2 passive: unidentified ID uses the MAC (same as Windows)' "$json" '"Id": "A2\.Unidentified\.00-00-01-02-03-04"'
[ -n "$json" ] && check 'A2 passive: shared MAC ID' "$json" '"Id": "A2\.SharedMac\.00-00-01-02-03-04"'

# --- Only a VPN has a gateway: nothing is scanned ------------------------------------------
new_env a2-vpn
linux_net 'default dev wg0 scope link metric 50
default via 10.8.0.1 dev wg0 metric 50' '5: wg0    inet 10.8.0.5/24 scope global wg0'
OUT="$WORK/a2-vpn.txt"
run_script a2-vpn "$A2" "$OUT"
check 'A2 VPN only: SKIPPED, not scanned' "$OUT" '\[SKIPPED\] Local subnet - Only a VPN or virtual adapter has a default gateway \(wg0\)'
check_not 'A2 VPN only: no scope printed' "$OUT" 'Range   :'

# --- Large subnet refused -------------------------------------------------------------------
new_env a2-large
linux_net 'default via 198.18.0.1 dev eth0 metric 100' '2: eth0    inet 198.18.5.5/15 scope global eth0'
OUT="$WORK/a2-large.txt"
run_script a2-large "$A2" "$OUT"
check 'A2 /15: refused before sending anything' "$OUT" '\[SKIPPED\] Device discovery - Subnet 198\.18\.0\.0/15 has 131070 addresses'
run_script a2-large "$A2" "$OUT.allow" --allow-large-subnet
check 'A2 /15 with --allow-large-subnet: still refused above /20' "$OUT.allow" 'above the 4094-address safety limit. Nothing was scanned'

# --- Active logic with stubbed ping and name lookups (no packets) --------------------------
new_env a2-active
linux_net 'default via 198.51.100.1 dev eth0 metric 100' '2: eth0    inet 198.51.100.23/24 scope global eth0'
printf '198.51.100.1 lladdr 00:09:5b:11:22:33 REACHABLE\n' >"$WORK/a2-active/neigh.txt"
stub "$BIN" ping 'for a in "$@"; do last=$a; done; case "$last" in 198.51.100.1|198.51.100.77|198.51.100.23) exit 0 ;; *) exit 1 ;; esac'
stub "$BIN" getent 'case "$1" in hosts) case "$2" in 198.51.100.77) echo "198.51.100.77 hp1a2b3c.home" ;; *) exit 2 ;; esac ;; *) exit 2 ;; esac'
OUT="$WORK/a2-active.txt"
run_script a2-active "$A2" "$OUT" --max-parallel 8
check 'A2 active (stubbed): sweep announced with the limit' "$OUT" 'ICMP ping \(about 1 s each, up to 8 at a time\)'
check 'A2 active (stubbed): ping-only device found' "$OUT" '198\.51\.100\.77 .*hp1a2b3c\.home +Printer +yes'
check 'A2 active (stubbed): 3 devices' "$OUT" 'Devices found - 3 device\(s\)'
run_script a2-active "$A2" "$OUT.bad" --max-parallel 64
check 'A2: --max-parallel above 32 refused' "$OUT.bad.rc" '^2$'

# =========================================================================================
# A4 get-open-port-scan.sh (Linux branch)
# =========================================================================================
A4=security-operations/diagnostics/endpoint-posture/get-open-port-scan.sh
new_env a4-local
linux_net 'default via 198.51.100.1 dev eth0 metric 100' '2: eth0    inet 198.51.100.23/24 scope global eth0'
stub "$BIN" ss 'printf "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\nLISTEN 0 5 0.0.0.0:23 0.0.0.0:*\nLISTEN 0 5 127.0.0.1:5432 0.0.0.0:*\nLISTEN 0 5 [::]:3306 [::]:*\nLISTEN 0 50 0.0.0.0:445 0.0.0.0:*\nLISTEN 0 50 [::]:445 [::]:*\nLISTEN 0 5 0.0.0.0:8123 0.0.0.0:* users:((\"python3\",pid=900,fd=3))\n"'
stub "$BIN" ps 'printf "  900 /usr/bin/python3\n"'
OUT="$WORK/a4-local.txt"
run_script a4-local "$A4" "$OUT" --output "$WORK/a4-local/export"
check 'A4 local: exit 0' "$OUT.rc" '^0$'
check 'A4 local: Telnet listening = FAIL' "$OUT" '\[FAIL\] +Port 23 Telnet - Listening on the network'
check 'A4 local: MySQL on IPv6 any = WARN' "$OUT" '\[WARN\] +Port 3306 MySQL'
check 'A4 local: Samba = INFO with Linux note' "$OUT" '\[INFO\] +Port 445 SMB file sharing - .*Samba'
check 'A4 local: loopback database not flagged' "$OUT" '5432 .*This computer only'
check_not 'A4 local: no finding for loopback 5432' "$OUT" 'Port 5432 PostgreSQL -'
check 'A4 local: IPv4+IPv6 445 counted once' "$OUT" 'Listening TCP ports - 5 listening port\(s\); 4 reachable'
check 'A4 local: unknown port listed with process' "$OUT" 'Other network-reachable ports - 8123 \(python3\)'
check 'A4 local: process names need sudo note' "$OUT" 'Process names - Linux only shows'
check 'A4 local: LAN check not run by default' "$OUT" 'Local network port check - Not run'

new_env a4-lan
linux_net 'default via 198.51.100.1 dev eth0 metric 100' '2: eth0    inet 198.51.100.23/24 scope global eth0'
printf '198.51.100.1 lladdr 00:09:5b:11:22:33 REACHABLE\n198.51.100.40 lladdr 18:b4:30:00:00:01 REACHABLE\n' >"$WORK/a4-lan/neigh.txt"
stub "$BIN" ss 'true'
stub "$BIN" ping 'for a in "$@"; do last=$a; done; case "$last" in 198.51.100.1|198.51.100.40) exit 0 ;; *) exit 1 ;; esac'
# nc -z -w 1 IP PORT: open only for the router web page, the camera web page and the camera Telnet.
stub "$BIN" nc 'ip=; port=; for a in "$@"; do ip=$port; port=$a; done; case "$ip:$port" in 198.51.100.1:80|198.51.100.40:80|198.51.100.40:23) exit 0 ;; *) exit 1 ;; esac'
OUT="$WORK/a4-lan.txt"
run_script a4-lan "$A4" "$OUT" --scan-lan --max-parallel 16
check 'A4 LAN (stubbed): scope printed before probing' "$OUT" 'Ports   : 21,22,23,80,135,139,443,445,3389,5900,8080'
check 'A4 LAN (stubbed): 2 devices x 11 ports' "$OUT" 'Port check scope - 2 device\(s\) x 11 ports on 198\.51\.100\.0/24'
check 'A4 LAN (stubbed): camera Telnet = FAIL' "$OUT" '\[FAIL\] +Port 23 Telnet - 198\.51\.100\.40 \(Google Nest\) accepts Telnet'
check 'A4 LAN (stubbed): camera web page = WARN' "$OUT" '\[WARN\] +Port 80 HTTP web server - 198\.51\.100\.40 .*camera'
check_not 'A4 LAN (stubbed): router web page left to A7' "$OUT" 'Port 80 HTTP web server - 198\.51\.100\.1 '
check 'A4 LAN (stubbed): summary' "$OUT" 'LAN port check - 2 of 2 device\(s\)'
run_script a4-lan "$A4" "$OUT.target" --scan-lan --target 198.51.100.40,203.0.113.5
check 'A4 --target outside the subnet refused' "$OUT.target" 'Target refused - 203\.0\.113\.5 is not inside the local subnet'
check 'A4 --target: only the given device' "$OUT.target" 'Port check scope - 1 device\(s\)'

# =========================================================================================
# A3 get-wifi-security-audit-linux.sh
# =========================================================================================
A3L=core-infrastructure/networking/diagnostics/get-wifi-security-audit-linux.sh
new_env a3-linux
stub "$BIN" nmcli 'echo "$*" >>"'"$WORK"'/a3-linux/nmcli-args"
case "$*" in
    *"device status"*) echo "wlp2s0:wifi:connected"; echo "enp3s0:ethernet:unavailable" ;;
    *"wifi list"*) printf "%s\n" "*:HomeNet:AA\\:BB\\:CC\\:00\\:00\\:01:WPA2:6:2437 MHz:80" " :HomeNet:AA\\:BB\\:CC\\:00\\:00\\:02:WPA1 WPA2:11:2462 MHz:40" " :CafeFree:AA\\:BB\\:CC\\:00\\:00\\:03::1:2412 MHz:30" " ::AA\\:BB\\:CC\\:00\\:00\\:04:WPA2:36:5180 MHz:20" ;;
    *"NAME,TYPE connection show"*) printf "HomeNet:802-11-wireless\nCafeFree:802-11-wireless\nOld TKIP:802-11-wireless\nWired connection 1:802-3-ethernet\n" ;;
    *"connection show HomeNet") printf "802-11-wireless.ssid:HomeNet\n802-11-wireless-security.key-mgmt:wpa-psk\n802-11-wireless-security.proto:\n802-11-wireless-security.pairwise:\n802-11-wireless-security.wep-key-type:unknown\nconnection.autoconnect:yes\n" ;;
    *"connection show CafeFree") printf "802-11-wireless.ssid:CafeFree\nconnection.autoconnect:yes\n" ;;
    *"connection show Old TKIP") printf "802-11-wireless.ssid:OldNet\n802-11-wireless-security.key-mgmt:wpa-psk\n802-11-wireless-security.proto:wpa\n802-11-wireless-security.pairwise:tkip\nconnection.autoconnect:no\n" ;;
esac'
OUT="$WORK/a3-linux.txt"
run_script a3-linux "$A3L" "$OUT" --output "$WORK/a3-linux/export"
check 'A3 linux: exit 0' "$OUT.rc" '^0$'
check 'A3 linux: adapter listed' "$OUT" 'Wi-Fi adapter - wlp2s0 \(connected\)'
check 'A3 linux: current WPA2 = PASS' "$OUT" '\[PASS\] +Current Wi-Fi security - "HomeNet" \(2437 MHz, channel 6, signal 80%\): WPA2'
check 'A3 linux: WPA3 hint' "$OUT" 'WPA3 available\?'
check 'A3 linux: open saved network that auto-joins = WARN' "$OUT" '\[WARN\] +Unsafe saved network \(auto-connect\) - "CafeFree" \(Open'
check 'A3 linux: TKIP manual = WARN Low' "$OUT" '\[WARN\] +Unsafe saved network - "Old TKIP" \(wpa-psk with TKIP'
check 'A3 linux: profile count, passwords not read' "$OUT" 'Saved Wi-Fi profiles - 3 saved Wi-Fi connection\(s\); 1 use good security. Passwords were not read'
check 'A3 linux: hidden network named' "$OUT" '\(hidden network\)'
check 'A3 linux: evil-twin check' "$OUT" '\[WARN\] +Same network name, different security - Networks named "HomeNet" .*WPA2; WPA1 WPA2'
check 'A3 linux: last scan reused, no rescan' "$WORK/a3-linux/nmcli-args" 'wifi list --rescan no'
check_not 'A3 linux: secrets never requested' "$WORK/a3-linux/nmcli-args" 'secrets|-s |--show'
json=$(find "$WORK/a3-linux/export" -name "*.json" 2>/dev/null | head -n 1)
[ -n "$json" ] && check 'A3 linux: profile finding ID (same scheme as Windows)' "$json" '"Id": "A3\.Profile\.CafeFree"'

new_env a3-nonm
OUT="$WORK/a3-nonm.txt"
run_script a3-nonm "$A3L" "$OUT"
check 'A3 linux without NetworkManager: SKIPPED with a reason' "$OUT" '\[SKIPPED\] Wi-Fi adapter - Skipped: NetworkManager'

# =========================================================================================
# A3 get-wifi-security-audit-macos.sh (macOS paths not reachable on the test Mac)
# =========================================================================================
A3M=core-infrastructure/networking/diagnostics/get-wifi-security-audit-macos.sh
mac_wifi() {
    # mac_wifi NAME_CURRENT NAME_OTHERS - networksetup and system_profiler stubs; names may be <redacted>.
    stub "$BIN" uname 'case "$1" in -s) echo Darwin ;; -n) echo mockmac ;; *) echo Darwin ;; esac'
    stub "$BIN" networksetup 'case "$1" in
        -listallhardwareports) printf "Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: aa:bb:cc:dd:ee:ff\n" ;;
        -getairportpower) echo "Wi-Fi Power (en0): On" ;;
        -listpreferredwirelessnetworks) printf "Preferred networks on en0:\n\tHomeNet\n\tCafeFree\n\tOldNet\n" ;;
    esac'
    cat >"$(dirname "$BIN")/sp.txt" <<SP
Wi-Fi:

      Software Versions:
          CoreWLAN: 16.0 (1657)
      Interfaces:
        en0:
          Card Type: Wi-Fi  (0x14E4, 0x4388)
          Status: Connected
          Current Network Information:
            $1:
              PHY Mode: 802.11ax
              Channel: 36 (5GHz, 80MHz)
              Network Type: Infrastructure
              Security: WPA2 Personal
              Signal / Noise: -55 dBm / -93 dBm
          Other Local Wi-Fi Networks:
            $2:
              PHY Mode: 802.11n
              Channel: 6 (2GHz, 20MHz)
              Network Type: Infrastructure
              Security: WPA/WPA2 Personal
            CafeFree:
              PHY Mode: 802.11g
              Channel: 1 (2GHz, 20MHz)
              Network Type: Infrastructure
              Security: None
        awdl0:
          MAC Address: 02:00:00:00:00:99
          Current Network Information:
              Network Type: Infrastructure
SP
    stub "$BIN" system_profiler 'cat "'"$(dirname "$BIN")"'/sp.txt"'
}

# --- Names visible, run as root: saved-network security from the root-only plist ----------
new_env a3-mac-root
mac_wifi HomeNet HomeNet
stub "$BIN" id 'case "$1" in -u) echo 0 ;; -un) echo root ;; *) echo "uid=0(root)" ;; esac'
mkdir -p "$FAKE/Library/Preferences"
: >"$FAKE/Library/Preferences/com.apple.wifi.known-networks.plist"
stub "$BIN" plutil 'cat <<XML
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>wifi.network.ssid.CafeFree</key>
	<dict>
		<key>AddedAt</key>
		<date>2025-01-01T00:00:00Z</date>
		<key>SupportedSecurityTypes</key>
		<string>Open</string>
	</dict>
	<key>wifi.network.ssid.HomeNet</key>
	<dict>
		<key>CaptiveProfile</key>
		<dict>
			<key>CaptiveNetwork</key>
			<false/>
		</dict>
		<key>SupportedSecurityTypes</key>
		<string>WPA2 Personal</string>
	</dict>
	<key>wifi.network.ssid.Tom &amp; Jerry</key>
	<dict>
		<key>AutoJoinDisabled</key>
		<true/>
		<key>SupportedSecurityTypes</key>
		<string>WPA Personal</string>
	</dict>
</dict>
</plist>
XML'
OUT="$WORK/a3-mac-root.txt"
run_script a3-mac-root "$A3M" "$OUT" --output "$WORK/a3-mac-root/export"
check 'A3 mac: exit 0' "$OUT.rc" '^0$'
check 'A3 mac: current WPA2 = PASS with name' "$OUT" '\[PASS\] +Current Wi-Fi security - "HomeNet" \(802\.11ax, channel 36 \(5GHz, 80MHz\), signal -55 dBm / -93 dBm\): WPA2 Personal'
check 'A3 mac root: open saved network that auto-joins = WARN' "$OUT" '\[WARN\] +Unsafe saved network \(auto-connect\) - "CafeFree" \(Open'
check 'A3 mac root: WPA v1, auto-join off, XML name decoded' "$OUT" '\[WARN\] +Unsafe saved network - "Tom & Jerry" \(WPA Personal \(original WPA'
check 'A3 mac root: nested dict does not end the entry' "$OUT" 'Saved Wi-Fi profiles - 3 saved network\(s\); 1 use good security'
check 'A3 mac: nearby open network counted' "$OUT" 'Nearby networks - 2 network\(s\) in range; 1 open/WEP'
check 'A3 mac: awdl0 section ignored' "$OUT" 'Nearby networks - 2 network'
check 'A3 mac: evil twin (WPA2 vs WPA/WPA2 under the same name)' "$OUT" '\[WARN\] +Same network name, different security - Networks named "HomeNet"'

# --- Names hidden by macOS, not root -------------------------------------------------------
new_env a3-mac-redacted
mac_wifi '<redacted>' '<redacted>'
stub "$BIN" id 'case "$1" in -u) echo 501 ;; -un) echo alice ;; *) echo "uid=501(alice)" ;; esac'
OUT="$WORK/a3-mac-redacted.txt"
run_script a3-mac-redacted "$A3M" "$OUT" --home-ssid HomeNet
check 'A3 mac redacted: rating still works' "$OUT" '\[PASS\] +Current Wi-Fi security - \(name hidden by macOS\)'
check 'A3 mac redacted: Location Services advice' "$OUT" 'Network name - macOS hid the network name'
check 'A3 mac not root: saved-network security SKIPPED' "$OUT" '\[SKIPPED\] Saved network security - Skipped: requires root'
check 'A3 mac redacted: name matching SKIPPED' "$OUT" '\[SKIPPED\] Home network in scan - Skipped: macOS hid the names'

# =========================================================================================
for f in "$WORK"/*/network-calls; do
    if [ -s "$f" ]; then FAILED=$((FAILED + 1)); printf 'FAIL: network stub called (%s):\n' "$f"; cat "$f"; else PASSED=$((PASSED + 1)); fi
done

if [ "$KEEP" -eq 1 ]; then printf 'Work folder kept: %s\n' "$WORK"; else rm -rf "$WORK"; fi
printf '\n%s passed, %s failed (mocked platforms, bash %s)\n' "$PASSED" "$FAILED" "$BASH_VERSION"
[ "$FAILED" -eq 0 ]
