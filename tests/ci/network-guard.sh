#!/usr/bin/env bash
# CI only (GitHub Actions runners): blocks and counts network traffic from the test account, so a
# job fails if any script it runs tries to reach beyond the runner. Never run on a client computer.
#
#   sudo bash tests/ci/network-guard.sh start USER    block and count USER's traffic
#   sudo bash tests/ci/network-guard.sh canary USER   prove the guard sees attempts (192.0.2.1, TEST-NET-1)
#   sudo bash tests/ci/network-guard.sh check REPO SUMMARY_DIR
#                                                     exit 1 if anything was blocked after the canary,
#                                                     if a workflow passes the active-network switch, or
#                                                     if a harness summary reports active cases run
#
# Linux (iptables owner match): every packet USER sends to an address other than loopback, and every
# DNS query USER sends (port 53, the loopback stub resolver included), is rejected and counted.
# macOS (pf): USER's TCP/UDP to anything but loopback, USER's DNS queries on port 53, and ICMP echo
# requests from any account, are blocked and counted. Name lookups through mDNSResponder are not
# visible to pf by account; the Linux job covers the shared bash code for that.
set -u

STATE=/var/tmp/msp-network-guard
ANCHOR=com.apple/msp-ci-guard
OS=$(uname -s)

die() { printf 'network-guard: %s\n' "$1" >&2; exit 1; }

[ "$(id -u)" = '0' ] || die 'run with sudo'
[ "${GITHUB_ACTIONS-}" = 'true' ] || die 'CI only: GITHUB_ACTIONS is not true'

blocked_count() {
    # Packets blocked so far by the guard rules.
    if [ "$OS" = 'Linux' ]; then
        { iptables -L MSPGUARD -n -v -x; ip6tables -L MSPGUARD -n -v -x; } 2>/dev/null |
            awk '$3 == "REJECT" { s += $1 } END { print s + 0 }'
    else
        pfctl -a "$ANCHOR" -vsr 2>/dev/null |
            awk '/^block/ { b = 1; next } /^pass/ { b = 0; next }
                 b { for (i = 1; i < NF; i++) if ($i == "Packets:") s += $(i + 1) } END { print s + 0 }'
    fi
}

show_blocked() {
    if [ "$OS" = 'Linux' ]; then
        iptables -L MSPGUARD -n -v -x
        ip6tables -L MSPGUARD -n -v -x
        journalctl -k --no-pager 2>/dev/null | grep 'MSPGUARD ' | tail -n 40
    else
        pfctl -a "$ANCHOR" -vsr
    fi
}

start() {
    user=$1
    id "$user" >/dev/null 2>&1 || die "no account $user"
    if [ "$OS" = 'Linux' ]; then
        for t in iptables ip6tables; do
            "$t" -N MSPGUARD || die "$t: cannot create chain"
            "$t" -A MSPGUARD -p udp --dport 53 -j LOG --log-prefix 'MSPGUARD ' --log-uid
            "$t" -A MSPGUARD -p udp --dport 53 -j REJECT
            "$t" -A MSPGUARD -p tcp --dport 53 -j LOG --log-prefix 'MSPGUARD ' --log-uid
            "$t" -A MSPGUARD -p tcp --dport 53 -j REJECT
            "$t" -A MSPGUARD -o lo -j RETURN
            "$t" -A MSPGUARD -j LOG --log-prefix 'MSPGUARD ' --log-uid
            "$t" -A MSPGUARD -j REJECT
            "$t" -I OUTPUT 1 -m owner --uid-owner "$user" -j MSPGUARD || die "$t: cannot hook OUTPUT"
        done
        printf 'hosts lookup order: %s\n' "$(grep '^hosts:' /etc/nsswitch.conf)"
    elif [ "$OS" = 'Darwin' ]; then
        uid=$(id -u "$user")
        cat >"$STATE.pf" <<EOF
block return out log quick proto { tcp, udp } from any to any port 53 user $uid
pass out quick on lo0 all
block return out log quick proto { tcp, udp } all user $uid
block return out log quick inet proto icmp all icmp-type echoreq
block return out log quick inet6 proto icmp6 all icmp6-type echoreq
EOF
        pfctl -f /etc/pf.conf 2>/dev/null
        pfctl -a "$ANCHOR" -f "$STATE.pf" || die 'pf: cannot load rules'
        pfctl -E 2>&1 | grep -i token >"$STATE.token"
        pfctl -a "$ANCHOR" -sr
    else
        die "unsupported system $OS"
    fi
    echo "network guard on for $user"
}

attempt() {
    # attempt USER WHAT COMMAND... - runs COMMAND as USER for at most 5 seconds; reports whether the
    # blocked count went up.
    user=$1
    what=$2
    shift 2
    before=$(blocked_count)
    sudo -u "$user" "$@" >/dev/null 2>&1 </dev/null &
    pid=$!
    n=0
    while kill -0 "$pid" 2>/dev/null && [ "$n" -lt 5 ]; do sleep 1; n=$((n + 1)); done
    kill "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
    after=$(blocked_count)
    if [ "$after" -gt "$before" ]; then
        printf 'canary %-28s blocked and counted (%s packet(s))\n' "$what" $((after - before))
        return 0
    fi
    printf 'canary %-28s NOT SEEN by the guard\n' "$what"
    return 1
}

canary() {
    user=$1
    rc=0
    attempt "$user" 'TCP to 192.0.2.1:9' /bin/bash -c 'exec 3<>/dev/tcp/192.0.2.1/9' || rc=1
    if [ "$OS" = 'Linux' ]; then
        attempt "$user" 'ping 192.0.2.1' ping -c 1 -W 1 192.0.2.1 || rc=1
        attempt "$user" 'DNS lookup (.invalid name)' getent hosts msp-guard-canary.invalid || rc=1
    else
        attempt "$user" 'ping 192.0.2.1' ping -c 1 -t 1 192.0.2.1 || rc=1
        attempt "$user" 'UDP to 192.0.2.1:53' /bin/bash -c 'echo x >/dev/udp/192.0.2.1/53' || rc=1
    fi
    [ "$rc" -eq 0 ] || { show_blocked; die 'the guard did not see every canary attempt'; }
    blocked_count >"$STATE.baseline"
}

check() {
    repo=$1
    summaries=$2
    rc=0
    [ -f "$STATE.baseline" ] || die 'no baseline: start and canary did not run'
    baseline=$(cat "$STATE.baseline")
    now=$(blocked_count)
    if [ "$now" -gt "$baseline" ]; then
        printf 'FAIL: %s packet(s) from the test account were blocked: a script tried to reach beyond the runner.\n' $((now - baseline))
        show_blocked
        rc=1
    else
        echo 'PASS: nothing from the test account was blocked after the canary.'
    fi
    if grep -rn -- 'AllowActiveNetwork' "$repo/.github/workflows" >/dev/null 2>&1; then
        echo 'FAIL: a workflow file mentions the active-network switch.'
        grep -rn -- 'AllowActiveNetwork' "$repo/.github/workflows"
        rc=1
    fi
    found=0
    for f in "$summaries"/harness-summary-*.md; do
        [ -f "$f" ] || continue
        found=1
        if ! grep -q '^Active network cases run: 0$' "$f" || ! grep -q '^-AllowActiveNetwork: not given$' "$f"; then
            printf 'FAIL: %s reports active network cases.\n' "$f"
            rc=1
        fi
    done
    [ "$found" -eq 1 ] || { echo 'FAIL: no harness summary to check.'; rc=1; }
    return "$rc"
}

case "${1-}" in
    start) [ $# -eq 2 ] || die 'usage: start USER'; start "$2" ;;
    canary) [ $# -eq 2 ] || die 'usage: canary USER'; canary "$2" ;;
    check) [ $# -eq 3 ] || die 'usage: check REPO SUMMARY_DIR'; check "$2" "$3" ;;
    *) die 'usage: start USER | canary USER | check REPO SUMMARY_DIR' ;;
esac
