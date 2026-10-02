#!/bin/bash
# t09-non-ethernet.sh - falsifier for matrix item 24 (non-Ethernet
# interfaces).
#
# The module hardcodes DLT_EN10MB; activating on an L3 device (wireguard,
# tun) must be refused with a clear error naming the link type. Generic
# XDP attaches to ANY device, so without the ARPHRD check the activate
# would succeed and produce garbage Ethernet-framed captures: success
# here is the falsified outcome. A wireguard device is preferred (clean
# lifecycle); a socat-held tun is the fallback. veth must stay accepted.
set -u
# shellcheck disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
guard
build_helpers
mk_tmp
T=t09
NONETHER=""
KIND=""
TUN_PID=""

# shellcheck disable=SC2329  # invoked via trap
cleanup() {
    if [ -n "$TUN_PID" ]; then
        kill "$TUN_PID" 2>/dev/null || true
    fi
    ip link del pcxwg0 2>/dev/null || true
    ip link del pcxtun0 2>/dev/null || true
    cleanup_common
}
trap cleanup EXIT

setup_rig

if modprobe wireguard 2>/dev/null &&
        ip link add pcxwg0 type wireguard 2>/dev/null; then
    ip link set pcxwg0 up
    NONETHER=pcxwg0
    KIND=wireguard
elif require_tool socat; then
    socat -u "TUN:10.231.78.1/24,tun-name=pcxtun0,iff-up" - \
        >/dev/null 2>&1 &
    TUN_PID=$!
    sleep 0.5
    if ip link show pcxtun0 >/dev/null 2>&1; then
        NONETHER=pcxtun0
        KIND=tun
    fi
fi

if [ -z "$NONETHER" ]; then
    result $T "non-Ethernet device cleanly refused" SKIP \
        "no wireguard module and no socat-held tun available"
else
    timeout 10 "$HELPER_BIN/xdp_capture" -A "xdp:$NONETHER" \
        >"$TMP/ne.log" 2>&1
    RC=$?
    if [ "$RC" -eq 0 ]; then
        result $T "non-Ethernet device cleanly refused" FAIL \
            "activated on $KIND device: DLT_EN10MB garbage capture, refusal contract falsified"
    elif [ "$RC" -eq 4 ] &&
            grep -Eiq 'ether|link.?type|arphrd' "$TMP/ne.log"; then
        result $T "non-Ethernet device cleanly refused" PASS \
            "$KIND: $(grep ACTIVATE_ERR "$TMP/ne.log")"
    elif [ "$RC" -eq 124 ]; then
        result $T "non-Ethernet device cleanly refused" FAIL \
            "hang activating on $KIND device"
    else
        result $T "non-Ethernet device cleanly refused" FAIL \
            "$KIND refused but error text does not name the link type: $(tail -n1 "$TMP/ne.log")"
    fi
fi

# Control arm: veth must still be accepted.
timeout 10 "$HELPER_BIN/xdp_capture" -A "xdp:$HOST_IF" >"$TMP/veth.log" 2>&1
RC=$?
if [ "$RC" -eq 0 ] && grep -q ACTIVATE_OK "$TMP/veth.log"; then
    result $T "veth (Ethernet) still accepted" PASS ""
else
    result $T "veth (Ethernet) still accepted" FAIL \
        "$(tail -n1 "$TMP/veth.log")"
fi

finish
