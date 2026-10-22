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
    stub "$BIN" date "case \"\$1\" in -d) v=\$2; shift 2; if $REAL_DATE -d @0 >/dev/null 2>&1; then exec $REAL_DATE -d \"\$v\" \"\$@\"; fi; case \"\$v\" in @*) e=\${v#@} ;; *) e=\$($REAL_DATE -j -f '%Y-%m-%d %H:%M:%S' \"\$v\" +%s 2>/dev/null || $REAL_DATE -j -f '%Y-%m-%d' \"\$v\" +%s 2>/dev/null || $REAL_DATE -j -f '%a %b %d %H:%M:%S %Y' \"\$v\" +%s 2>/dev/null) ;; esac; [ -n \"\$e\" ] || exit 1; exec $REAL_DATE -r \$e \"\$@\" ;; *) exec $REAL_DATE \"\$@\" ;; esac"
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
    PATH="$WORK/$env/bin:$PATH" MSP_TEST_ROOT="$WORK/$env/root" TMPDIR="$WORK/$env" NO_COLOR=1 HOME=/home/alice \
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
# A5 get-browser-security-check.sh (Linux branch)
# =========================================================================================
A5=endpoint-systems/diagnostics/system-info/get-browser-security-check.sh
new_env a5-linux
stub "$BIN" dpkg-query 'case "$*" in *google-chrome-stable*) echo "install ok installed 120.0.6099.71-1" ;; *) exit 1 ;; esac'
stub "$BIN" ps 'true'
mkdir -p "$FAKE/usr/lib/firefox/defaults/pref" "$FAKE/etc/opt/chrome/policies/managed" "$FAKE/etc/firefox/policies"
printf '[App]\nVersion=140.3.0esr\n' >"$FAKE/usr/lib/firefox/application.ini"
printf 'pref("app.update.channel", "esr");\n' >"$FAKE/usr/lib/firefox/defaults/pref/channel-prefs.js"
printf '{"ExtensionInstallForcelist": ["aaaabbbbccccddddeeeeffffgggghhhh;https://evil.example/update.xml"], "HomepageLocation": "https://evil.example"}\n' >"$FAKE/etc/opt/chrome/policies/managed/adware.json"
printf '{"policies": {"DisableAppUpdate": true}}\n' >"$FAKE/etc/firefox/policies/policies.json"
CHROME="$FAKE/home/alice/.config/google-chrome"
mkdir -p "$CHROME/Default/Extensions/cjpalhdlnbpafiamejdnhcphjbkeiagm/1.62.0_0" "$CHROME/Profile 1/Extensions/ppppppppppppppppppppppppppppppab/2.0_0/_locales/en"
printf '{"name":"uBlock Origin","version":"1.62.0","update_url":"https://clients2.google.com/service/update2/crx","permissions":["<all_urls>"]}\n' >"$CHROME/Default/Extensions/cjpalhdlnbpafiamejdnhcphjbkeiagm/1.62.0_0/manifest.json"
printf '{"name":"__MSG_appName__","default_locale":"en","version":"2.0","host_permissions":["*://*/*"]}\n' >"$CHROME/Profile 1/Extensions/ppppppppppppppppppppppppppppppab/2.0_0/manifest.json"
printf '{"appName":{"message":"Search Helper Pro"}}\n' >"$CHROME/Profile 1/Extensions/ppppppppppppppppppppppppppppppab/2.0_0/_locales/en/messages.json"
FF="$FAKE/home/alice/.mozilla/firefox/abcd1234.default-release"
mkdir -p "$FF"
printf '{"schemaVersion":36,"addons":[{"id":"formautofill@mozilla.org","type":"extension","location":"app-builtin","defaultLocale":{"name":"Form Autofill"}},{"id":"coupons@shady.example","version":"3.1","type":"extension","location":"app-profile","active":true,"signedState":0,"defaultLocale":{"name":"Coupon \\"Saver\\""},"userPermissions":{"origins":["<all_urls>"]}},{"id":"en-US@dictionaries","type":"dictionary","location":"app-profile"}]}\n' >"$FF/extensions.json"
OUT="$WORK/a5-linux.txt"
run_script a5-linux "$A5" "$OUT" --output "$WORK/a5-linux/export"
check 'A5 linux: exit 0' "$OUT.rc" '^0$'
check 'A5 linux: old Chrome = FAIL' "$OUT" '\[FAIL\] +Google Chrome version - 120\.0\.6099\.71-1 is about [0-9]+ releases behind'
check 'A5 linux: Firefox ESR rated on its branch' "$OUT" 'Mozilla Firefox version - 140\.3\.0esr .*Extended Support Release 140'
check 'A5 linux: Chrome store extension listed' "$OUT" 'Google Chrome extensions \(alice\) - 2 extension\(s\) across 2 browser profile\(s\): uBlock Origin; Search Helper Pro'
check 'A5 linux: __MSG_ name resolved, sideloaded = WARN' "$OUT" '\[WARN\] +Extension not from the official store: Search Helper Pro'
check 'A5 linux: all-sites store extension noted' "$OUT" 'extensions that can read every website - uBlock Origin'
check 'A5 linux: Firefox built-ins and dictionaries skipped' "$OUT" 'Mozilla Firefox extensions \(alice\) - 1 extension\(s\)'
check 'A5 linux: unsigned Firefox add-on = WARN (escaped name)' "$OUT" '\[WARN\] +Extension not from the official store: Coupon "Saver"'
check 'A5 linux: forced Chrome extension = WARN High' "$OUT" '\[WARN\] +Google Chrome: force-installed extensions - .*aaaabbbbccccddddeeeeffffgggghhhh'
check 'A5 linux: Chrome policies listed' "$OUT" 'Google Chrome: browser policies set - .*ExtensionInstallForcelist, HomepageLocation'
check 'A5 linux: Firefox updates disabled = FAIL' "$OUT" '\[FAIL\] +Firefox: updates disabled by policy'
check_not 'A5 linux: no Brave/Edge results without profiles' "$OUT" 'Brave extensions|Microsoft Edge extensions'
check_not 'A5 linux: no ERROR findings' "$OUT" '\[ERROR\]'
check_not 'A5 linux: credential stores never touched' "$OUT" 'Login Data|logins\.json|Cookies'

# =========================================================================================
# A6 get-update-compliance-linux.sh / -macos.sh
# =========================================================================================
A6L=endpoint-systems/diagnostics/system-info/get-update-compliance-linux.sh
new_env a6-old
mkdir -p "$FAKE/etc/apt/apt.conf.d" "$FAKE/var/log" "$FAKE/var/lib/apt/lists" "$FAKE/var/run" "$FAKE/boot" "$FAKE/proc"
printf 'PRETTY_NAME="Ubuntu 20.04.6 LTS"\nID=ubuntu\nVERSION_ID="20.04"\n' >"$FAKE/etc/os-release"
printf '2025-01-10 10:00:00 status installed openssl:amd64 1.1.1f\n2025-02-11 09:00:00 status installed bash:amd64 5.0\n' >"$FAKE/var/log/dpkg.log"
printf 'APT::Periodic::Update-Package-Lists "0";\n' >"$FAKE/etc/apt/apt.conf.d/10periodic"
: >"$FAKE/var/run/reboot-required"
printf 'linux-image-6.8.0-50-generic\n' >"$FAKE/var/run/reboot-required.pkgs"
: >"$FAKE/boot/vmlinuz-6.8.0-mock"
: >"$FAKE/boot/vmlinuz-6.9.0-mock"
printf '3456000.12 100.0\n' >"$FAKE/proc/uptime"
stub "$BIN" apt-get 'printf "Inst openssl [1.1.1f-1ubuntu2] (1.1.1f-1ubuntu2.23 Ubuntu:20.04/focal-security [amd64])\nInst vim [2:8.1] (2:8.1.2 Ubuntu:20.04/focal-updates [amd64])\n"'
stub "$BIN" apt-mark 'echo nvidia-driver-535'
stub "$BIN" snap 'case "$*" in *"refresh --time"*) printf "timer: 00:00~24:00/4\nhold: 2026-12-01\n" ;; *) exit 0 ;; esac'
OUT="$WORK/a6-old.txt"
run_script a6-old "$A6L" "$OUT" --output "$WORK/a6-old/export"
check 'A6 linux: exit 0' "$OUT.rc" '^0$'
check 'A6 linux: Ubuntu 20.04 past standard support = FAIL Critical' "$OUT" '\[FAIL\] +OS version support - Ubuntu 20\.04 LTS reached end of security support on 2025-05-31.*Ubuntu Pro'
check 'A6 linux: last install from dpkg.log, >75 days = FAIL' "$OUT" '\[FAIL\] +Last update installed - No package has been installed or updated since 2025-02-11'
check 'A6 linux: lists never refreshed = WARN' "$OUT" '\[WARN\] +Last update scan - The package lists were last refreshed: never'
check 'A6 linux: security update = WARN High' "$OUT" '\[WARN\] +Pending security updates - 1 security update\(s\) waiting: openssl'
check 'A6 linux: other update = INFO' "$OUT" 'Other pending updates - 1 other update'
check 'A6 linux: reboot-required + newer kernel' "$OUT" '\[WARN\] +Restart pending - .*linux-image-6\.8\.0-50-generic.*kernel 6\.9\.0-mock is installed but 6\.8\.0-mock is running'
check 'A6 linux: 40 days up = Uptime WARN' "$OUT" '\[WARN\] +Uptime - The computer has not restarted for 40 days'
check 'A6 linux: automatic list refresh off = WARN' "$OUT" '\[WARN\] +Automatic updates - Automatic refresh of the package lists is turned off'
check 'A6 linux: held package' "$OUT" '\[WARN\] +Held packages - .*nvidia-driver-535'
check 'A6 linux: snap hold' "$OUT" '\[WARN\] +Updates paused - Snap updates are held until 2026-12-01'
check_not 'A6 linux: no ERROR findings' "$OUT" '\[ERROR\]'

new_env a6-new
mkdir -p "$FAKE/etc/apt/apt.conf.d" "$FAKE/var/lib/apt/lists" "$FAKE/proc" "$FAKE/var/lib/dpkg" "$FAKE/usr/bin"
printf 'PRETTY_NAME="Debian GNU/Linux 13 (trixie)"\nID=debian\nVERSION_ID="13"\n' >"$FAKE/etc/os-release"
: >"$FAKE/var/lib/apt/lists/deb.debian.org_debian_dists_trixie_InRelease"
: >"$FAKE/var/lib/dpkg/status"
: >"$FAKE/usr/bin/unattended-upgrade"
printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' >"$FAKE/etc/apt/apt.conf.d/20auto-upgrades"
printf '86400.00 1.0\n' >"$FAKE/proc/uptime"
stub "$BIN" apt-get 'true'
stub "$BIN" apt-mark 'true'
OUT="$WORK/a6-new.txt"
run_script a6-new "$A6L" "$OUT"
check 'A6 linux: Debian 13 supported = PASS' "$OUT" '\[PASS\] +OS version support - Debian 13 \(trixie\) is supported until 2030-06-30'
check 'A6 linux: nothing pending = PASS' "$OUT" '\[PASS\] +Pending updates - None'
check 'A6 linux: automatic updates on = PASS' "$OUT" '\[PASS\] +Update policies'
new_env a6-unknown
mkdir -p "$FAKE/etc"
printf 'PRETTY_NAME="Gentoo Linux"\nID=gentoo\n' >"$FAKE/etc/os-release"
OUT="$WORK/a6-unknown.txt"
run_script a6-unknown "$A6L" "$OUT"
check 'A6 linux: distribution not in table = WARN Low' "$OUT" '\[WARN\] +OS version support - Gentoo Linux is not in this script'"'"'s support table'
check 'A6 linux: no apt/dnf = SKIPPED' "$OUT" '\[SKIPPED\] Pending updates'
printf 'PRETTY_NAME="Fedora Linux 44 (Workstation Edition)"\nID=fedora\nVERSION_ID=44\n' >"$FAKE/etc/os-release"
run_script a6-unknown "$A6L" "$OUT.f44"
check 'A6 linux: date not confirmed by an official source is said so' "$OUT.f44" '\[PASS\] +OS version support - Fedora 44 is supported until 2027-05-19\. This date is not confirmed by an official source'
check_not 'A6 linux: verified date has no "not confirmed" note' "$WORK/a6-new.txt" 'not confirmed by an official source'
check 'A6 linux: source and verified-on date in the JSON evidence' "$(find "$WORK/a6-old/export" -name '*.json' | head -n 1)" 'DateVerified.{1,6}2026-10-21'

A6M=endpoint-systems/diagnostics/system-info/get-update-compliance-macos.sh
new_env a6-mac-old
stub "$BIN" uname 'case "$1" in -s) echo Darwin ;; -n) echo mockmac ;; *) echo Darwin ;; esac'
stub "$BIN" sw_vers 'case "$1" in -productVersion) echo 13.6.7 ;; -buildVersion) echo 22G720 ;; esac'
OUT="$WORK/a6-mac-old.txt"
run_script a6-mac-old "$A6M" "$OUT"
check 'A6 mac: Ventura = FAIL Critical' "$OUT" '\[FAIL\] +OS version support - macOS Ventura \(13\.6\.7\) no longer receives security updates'
stub "$BIN" sw_vers 'case "$1" in -productVersion) echo 15.7 ;; -buildVersion) echo 24G100 ;; esac'
run_script a6-mac-old "$A6M" "$OUT.15"
check 'A6 mac: Sequoia = PASS, oldest supported' "$OUT.15" '\[PASS\] +OS version support - macOS Sequoia \(15\.7\) still receives security updates, but it is the oldest'
stub "$BIN" sw_vers 'case "$1" in -productVersion) echo 28.0 ;; -buildVersion) echo 27A1 ;; esac'
run_script a6-mac-old "$A6M" "$OUT.28"
check 'A6 mac: newer than table = WARN Low' "$OUT.28" '\[WARN\] +OS version support - macOS 28 is newer than this script'
stub "$BIN" sw_vers 'case "$1" in -productVersion) echo 14.8.9 ;; -buildVersion) echo 23J1 ;; esac'
run_script a6-mac-old "$A6M" "$OUT.14"
check 'A6 mac: Sonoma ended with its last security update date' "$OUT.14" '\[FAIL\] +OS version support - macOS Sonoma \(14\.8\.9\) no longer receives security updates \(Apple.s last security update for it: 2026-08-06\)'
stub "$BIN" sw_vers 'case "$1" in -productVersion) echo 27.0.1 ;; -buildVersion) echo 27A1 ;; esac'
run_script a6-mac-old "$A6M" "$OUT.27"
check 'A6 mac: macOS 27 = current' "$OUT.27" '\[PASS\] +OS version support - macOS Golden Gate \(27\.0\.1\) is the current macOS version'

# =========================================================================================
# A7 get-router-security-check.sh (Linux branch; every network command is a stub)
# =========================================================================================
A7=core-infrastructure/networking/diagnostics/get-router-security-check.sh
new_env a7-router
linux_net 'default via 198.51.100.1 dev eth0 metric 100' '2: eth0    inet 198.51.100.23/24 scope global eth0'
stub "$BIN" resolvectl 'printf "Global:\nLink 2 (eth0): 198.51.100.1 203.0.113.53\n"'
stub "$BIN" nc 'ip=; port=; for a in "$@"; do ip=$port; port=$a; done; case "$ip:$port" in 198.51.100.1:80|198.51.100.1:443|198.51.100.1:23) exit 0 ;; *) exit 1 ;; esac'
# perl answers the SSDP discovery: the router (an Internet Gateway Device) and a TV.
stub "$BIN" perl 'printf "198.51.100.1\tST=urn:schemas-upnp-org:device:InternetGatewayDevice:1;LOCATION=http://198.51.100.1:5000/rootDesc.xml;SERVER=Linux UPnP/1.0 MiniUPnPd\n198.51.100.77\tST=urn:dial-multiscreen-org:service:dial:1;LOCATION=http://198.51.100.77:8008/dd.xml;SERVER=Linux\n203.0.113.9\tST=upnp:rootdevice;LOCATION=http://203.0.113.9/x;SERVER=x\n"'
cat >"$BIN/curl" <<'STUB'
#!/bin/sh
# curl stub: writes canned headers/bodies for the router; records every URL requested.
hdr=/dev/null; out=/dev/null; url=; data=
while [ $# -gt 0 ]; do
    case "$1" in
        -D) hdr=$2; shift 2 ;;
        -o) out=$2; shift 2 ;;
        --data-binary) data=$2; shift 2 ;;
        -m | -A | -H | -r | --noproxy) shift 2 ;;
        http*) url=$1; shift ;;
        *) shift ;;
    esac
done
echo "$url" >>"$(dirname "$0")/../curl-urls"
case "$url" in
    http://198.51.100.1:80/) printf 'HTTP/1.1 302 Found\r\nLocation: https://198.51.100.1/\r\nServer: lighttpd\r\n\r\n' >"$hdr"; : >"$out" ;;
    https://198.51.100.1:443/) printf 'HTTP/1.1 200 OK\r\nServer: lighttpd\r\n\r\n' >"$hdr"; printf '<html><head><title>NETGEAR Router R7000</title></head></html>' >"$out" ;;
    http://198.51.100.1:5000/rootDesc.xml) printf 'HTTP/1.1 200 OK\r\n\r\n' >"$hdr"; printf '<?xml version="1.0"?><root><device><friendlyName>R7000</friendlyName><manufacturer>NETGEAR</manufacturer><modelName>R7000</modelName><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId><controlURL>/ctl/IPConn</controlURL></service></serviceList></device></root>' >"$out" ;;
    http://198.51.100.1:5000/ctl/IPConn)
        case "$data" in
            *GetExternalIPAddress*) printf 'HTTP/1.1 200 OK\r\n\r\n' >"$hdr"; printf '<s:Envelope><s:Body><u:GetExternalIPAddressResponse><NewExternalIPAddress>10.0.0.2</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>' >"$out" ;;
            *'<NewPortMappingIndex>0<'*) printf 'HTTP/1.1 200 OK\r\n\r\n' >"$hdr"; printf '<s:Envelope><s:Body><u:R><NewRemoteHost></NewRemoteHost><NewExternalPort>3389</NewExternalPort><NewProtocol>TCP</NewProtocol><NewInternalPort>3389</NewInternalPort><NewInternalClient>198.51.100.40</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>RDP</NewPortMappingDescription><NewLeaseDuration>0</NewLeaseDuration></u:R></s:Body></s:Envelope>' >"$out" ;;
            *) printf 'HTTP/1.1 500 Internal Server Error\r\n\r\n' >"$hdr"; : >"$out" ;;
        esac ;;
    *) exit 7 ;;
esac
exit 0
STUB
chmod +x "$BIN/curl"
OUT="$WORK/a7-router.txt"
run_script a7-router "$A7" "$OUT" --output "$WORK/a7-router/export"
check 'A7: exit 0' "$OUT.rc" '^0$'
check 'A7: scope printed' "$OUT" 'Router  : 198\.51\.100\.1   \(this computer 198\.51\.100\.23, subnet 198\.51\.100\.0/24\)'
check 'A7: router DNS = PASS' "$OUT" '\[PASS\] +DNS 198\.51\.100\.1 - Local DNS: the router'
check 'A7: unknown public DNS = WARN' "$OUT" '\[WARN\] +DNS 203\.0\.113\.53 - Unrecognised public DNS server'
check 'A7: HTTP redirects to HTTPS = PASS' "$OUT" '\[PASS\] +Admin page encryption - Admin page uses HTTPS \(https://198\.51\.100\.1:443/\)'
check 'A7: router identified' "$OUT" 'Router identification - Admin page reports: lighttpd \| NETGEAR Router R7000|Router identification - Admin page reports: NETGEAR Router R7000 \| lighttpd'
check 'A7: Telnet on the router = FAIL' "$OUT" '\[FAIL\] +Router Telnet'
check 'A7: UPnP on = WARN' "$OUT" '\[WARN\] +Router UPnP - UPnP is ON \(198\.51\.100\.1 answered'
check 'A7: other UPnP device (off-subnet answer ignored)' "$OUT" 'UPnP devices - 1 other device\(s\) .*198\.51\.100\.77$'
check 'A7: model from UPnP description' "$OUT" 'Router model \(UPnP\) - R7000 / NETGEAR'
check 'A7: private external address = double NAT WARN' "$OUT" '\[WARN\] +Internet address - .*private \(10\.0\.0\.2\)'
check 'A7: RDP port forward = WARN High' "$OUT" '\[WARN\] +UPnP port forward 3389/TCP - Internet port 3389/TCP is forwarded to 198\.51\.100\.40:3389'
check 'A7: no terminal -> checklist not asked' "$OUT" 'Checklist questions are not being asked'
check 'A7: checklist items recorded as not verified' "$OUT" 'Checklist: AdminPassword - Not verified'
check_not 'A7: nothing outside the router contacted' "$WORK/a7-router/curl-urls" '203\.0\.113|198\.51\.100\.(77|40)'
check_not 'A7: no ERROR findings' "$OUT" '\[ERROR\]'
json=$(find "$WORK/a7-router/export" -name '*.json' 2>/dev/null | head -n 1)
[ -n "$json" ] && check 'A7: checklist ID matches Windows' "$json" '"Id": "A7\.Checklist\.Checklist-AdminPassword"'

new_env a7-vpn
linux_net 'default via 10.8.0.1 dev tun0 metric 50' '5: tun0    inet 10.8.0.5/24 scope global tun0'
OUT="$WORK/a7-vpn.txt"
run_script a7-vpn "$A7" "$OUT" --skip-checklist-prompt
check 'A7 VPN only: SKIPPED, router not contacted' "$OUT" '\[SKIPPED\] Gateway - Only a VPN or virtual adapter'
check_not 'A7 VPN only: no admin page probing' "$OUT" 'Admin page encryption'

# =========================================================================================
# A8 get-home-device-inventory.sh (Linux branch)
# =========================================================================================
A8=endpoint-systems/audit/software-inventory/get-home-device-inventory.sh
new_env a8-linux
mkdir -p "$FAKE/sys/class/dmi/id" "$FAKE/proc" "$FAKE/home/alice" "$FAKE/home/bob" "$FAKE/home/carol"
printf 'LENOVO\n' >"$FAKE/sys/class/dmi/id/sys_vendor"
printf 'ThinkPad X1\n' >"$FAKE/sys/class/dmi/id/product_name"
printf 'model name\t: Mock CPU 3000\n' >"$FAKE/proc/cpuinfo"
printf 'MemTotal:       16777216 kB\n' >"$FAKE/proc/meminfo"
printf '1000.0 1.0\n' >"$FAKE/proc/uptime"
mkdir -p "$FAKE/etc"
printf 'root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000:Alice,,,:/home/alice:/bin/bash\nbob:x:1001:1001:Bob:/home/bob:/bin/bash\nsvc:x:1002:1002::/home/svc:/usr/sbin/nologin\n' >"$FAKE/etc/passwd"
printf 'sudo:x:27:alice\n' >"$FAKE/etc/group"
stub "$BIN" dpkg-query 'printf "anydesk|7.0.0|package|\nbash|5.2|package|\ntransmission-gtk|4.0.5|package|\nx11vnc|0.9.16|package|\n"'
stub "$BIN" snap 'printf "Name Version Rev Tracking Publisher Notes\nfirefox 131.0 1 latest/stable mozilla -\n"'
stub "$BIN" ps 'printf "/usr/bin/gnome-shell\n/home/alice/Downloads/rustdesk\n/usr/bin/bash\n"'
stub "$BIN" last 'case "$*" in *bob*) echo "bob      tty2         :0               Mon Jan  6 10:00:00 2025 - Mon Jan  6 11:00:00 2025  (01:00)" ;; *) echo "alice    tty2         :0               Fri Oct 16 09:00:00 2026   still logged in" ;; esac'
OUT="$WORK/a8-linux.txt"
run_script a8-linux "$A8" "$OUT" --approved-remote-tool AnyDesk --output "$WORK/a8-linux/export"
check 'A8 linux: exit 0' "$OUT.rc" '^0$'
check 'A8 linux: approved list from the command line' "$OUT" 'Approved remote tools - AnyDesk \(from --approved-remote-tool\)'
check 'A8 linux: device details' "$OUT" 'Device - LENOVO ThinkPad X1 \(S/N \(needs sudo\)\)'
check 'A8 linux: accounts (nologin skipped, admin marked)' "$OUT" 'Local accounts - 2 local account\(s\): alice \(admin\), bob'
check 'A8 linux: unused account = WARN' "$OUT" '\[WARN\] +Account "bob" unused - Account "bob" last signed in 2025-01-06'
check 'A8 linux: empty-password check needs sudo' "$OUT" '\[SKIPPED\] Account passwords'
check 'A8 linux: orphaned home folder' "$OUT" 'Orphaned profiles - Home folder /home/carol has no matching account'
check 'A8 linux: software count (packages + snaps)' "$OUT" 'Installed software - 5 package'
check 'A8 linux: approved tool = INFO' "$OUT" '\[INFO\] +Remote-access tool: AnyDesk - installed: anydesk 7\.0\.0 \(approved remote tool\)'
check 'A8 linux: portable RustDesk running = WARN High' "$OUT" '\[WARN\] +Remote-access tool: RustDesk - running now: rustdesk; NOT installed'
check 'A8 linux: x11vnc = VNC WARN' "$OUT" '\[WARN\] +Remote-access tool: VNC \(UltraVNC/TightVNC/RealVNC/TigerVNC\) - installed: x11vnc'
check 'A8 linux: default Transmission = INFO' "$OUT" '\[INFO\] +Peer-to-peer software: transmission-gtk - .*default Ubuntu desktop'
check_not 'A8 linux: no ERROR findings' "$OUT" '\[ERROR\]'
json=$(find "$WORK/a8-linux/export" -name '*.json' 2>/dev/null | head -n 1)
[ -n "$json" ] && check 'A8 linux: tool ID matches Windows' "$json" '"Id": "A8\.Software\.Remote-access-tool-RustDesk"'

# A8 macOS app folders: /Applications, the user's ~/Applications (one folder level deep), and
# every user's ~/Applications with --all-users as root. Device commands are stubbed.
new_env a8-mac
stub "$BIN" uname 'case "$1" in -s) echo Darwin ;; -n) echo mockmac ;; *) echo Darwin ;; esac'
stub "$BIN" id 'case "$1" in -u) echo 501 ;; -un) echo alice ;; *) echo "uid=501(alice)" ;; esac'
stub "$BIN" dscl 'case "$*" in
    *"-list /Users UniqueID"*) printf "_www 70\nalice 501\nbob 502\n" ;;
    *"/Groups/admin GroupMembership"*) echo "GroupMembership: root alice" ;;
    *"/Users/alice NFSHomeDirectory"*) echo "NFSHomeDirectory: /Users/alice" ;;
    *"/Users/bob NFSHomeDirectory"*) echo "NFSHomeDirectory: /Users/bob" ;;
    *RealName*) printf "RealName:\n Mock User\n" ;;
esac'
# Info.plist files hold just the version; "defaults read FILE KEY" prints it.
stub "$BIN" defaults '[ "$1" = read ] && [ -f "$2" ] && head -n 1 "$2"'
for c in system_profiler sysctl sw_vers profiles dsconfigad df uptime last ps; do stub "$BIN" "$c" 'exit 0'; done
mac_app() { mkdir -p "$FAKE/$1.app/Contents" && printf '%s\n' "$2" >"$FAKE/$1.app/Contents/Info.plist"; }
mac_app Applications/Safari 18.0
mac_app Applications/Utilities/Terminal 2.14
mac_app Users/alice/Applications/AnyDesk 9.0.1
mac_app 'Users/alice/Applications/Chrome Apps.localized/Gmail' 1.0
mac_app Users/bob/Applications/TeamViewer 15.50
OUT="$WORK/a8-mac.txt"
run_script a8-mac "$A8" "$OUT" --output "$WORK/a8-mac/export"
check 'A8 mac: /Applications + ~/Applications, one level deep' "$OUT" 'Installed software - 4 app\(s\) in /Applications and ~/Applications'
check 'A8 mac: app in ~/Applications flagged' "$OUT" '\[WARN\] +Remote-access tool: AnyDesk - installed: AnyDesk 9\.0\.1'
check_not 'A8 mac: other user'"'"'s ~/Applications not read without --all-users' "$OUT" 'TeamViewer'
csv=$(find "$WORK/a8-mac/export" -name '*_Software.csv' 2>/dev/null | head -n 1)
check 'A8 mac: ~/Applications subfolder app with the user as scope' "$csv" 'Gmail.*User: alice'
run_script a8-mac "$A8" "$OUT.all" --all-users
check 'A8 mac: --all-users without root = SKIPPED' "$OUT.all" "\\[SKIPPED\\] Other users' software - Skipped: requires root"
stub "$BIN" id 'case "$1" in -u) echo 0 ;; -un) echo root ;; *) echo "uid=0(root)" ;; esac'
export SUDO_USER=alice
run_script a8-mac "$A8" "$OUT.root" --all-users --output "$WORK/a8-mac/export-root"
unset SUDO_USER
check 'A8 mac: --all-users as root counts other users' "$OUT.root" "Other users' software - Also listing the apps in 1 other user"
check 'A8 mac: --all-users lists every user'"'"'s ~/Applications' "$OUT.root" 'Installed software - 5 app\(s\)'
check 'A8 mac: other user'"'"'s remote tool flagged' "$OUT.root" '\[WARN\] +Remote-access tool: TeamViewer - installed: TeamViewer 15\.50'
csv=$(find "$WORK/a8-mac/export-root" -name '*_Software.csv' 2>/dev/null | head -n 1)
check 'A8 mac: under sudo, the user who ran sudo keeps their scope' "$csv" 'AnyDesk.*User: alice'
check 'A8 mac: other user scope' "$csv" 'TeamViewer.*User: bob'

# =========================================================================================
for f in "$WORK"/*/network-calls; do
    if [ -s "$f" ]; then FAILED=$((FAILED + 1)); printf 'FAIL: network stub called (%s):\n' "$f"; cat "$f"; else PASSED=$((PASSED + 1)); fi
done

if [ "$KEEP" -eq 1 ]; then printf 'Work folder kept: %s\n' "$WORK"; else rm -rf "$WORK"; fi
printf '\n%s passed, %s failed (mocked platforms, bash %s)\n' "$PASSED" "$FAILED" "$BASH_VERSION"
[ "$FAILED" -eq 0 ]
