#!/bin/bash
# t01-takeover.sh - falsifier for matrix item 1 (takeover semantics).
#
# While an XDP capture holds (veth0, queue 0), a concurrent AF_PACKET
# capture on veth0 must go dark for the redirected traffic: redirect is
# exclusive, there is no tee at the XDP layer. This darkness is the
# EXPECTED behavior; the falsifier would be AF_PACKET still seeing the
# flow (which would mean the module is not actually redirecting).
#
# Method: one tcpdump (AF_PACKET) session on veth0 spans two phases.
# Phase 1, no XDP: 40 datagrams, proves the observer sees the flow.
# Phase 2, XDP capture active: 40 more datagrams of the same flow (the
# default rig pins all inbound to queue 0). AF_PACKET total must stay
# ~40; the XDP capture must deliver ~40.
set -u
# shellcheck disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
guard
build_helpers
mk_tmp
T=t01
TCPDUMP_PID=""

# shellcheck disable=SC2329  # invoked via trap
cleanup() {
    if [ -n "$TCPDUMP_PID" ]; then
        kill "$TCPDUMP_PID" 2>/dev/null || true
    fi
    cleanup_common
}
trap cleanup EXIT

if ! require_tool tcpdump || ! require_tool socat; then
    result $T "AF_PACKET goes dark under XDP takeover" SKIP \
        "tcpdump or socat missing"
    finish
fi

setup_rig

tcpdump -i "$HOST_IF" -nn -p -w "$TMP/afp.pcap" \
    'udp and dst port 9001' >/dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 1

# Phase 1: AF_PACKET alone must see these.
gen_udp_flow 40 7101 9001
sleep 0.5

# Phase 2: XDP capture takes the queue.
"$HELPER_BIN/xdp_capture" -f 'udp and dst port 9001' -c 40 -w 15 -t 250 \
    "xdp:$HOST_IF" >"$TMP/xdp.log" 2>&1 &
XDP_PID=$!
if ! wait_for_line "$TMP/xdp.log" ACTIVATE_OK 5; then
    result $T "AF_PACKET goes dark under XDP takeover" FAIL \
        "xdp capture failed to activate: $(tail -n1 "$TMP/xdp.log")"
    finish
fi
gen_udp_flow 40 7101 9001
wait "$XDP_PID" || true
sleep 0.5
kill -TERM "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true
TCPDUMP_PID=""

XDP_N=$(sed -n 's/^DELIVERED //p' "$TMP/xdp.log")
XDP_N=${XDP_N:-0}
AFP_N=$(tcpdump -r "$TMP/afp.pcap" 2>/dev/null | wc -l)

# Expected: AFP ~40 (phase 1 only; phase 2 dark), XDP ~40 (phase 2).
if [ "$XDP_N" -ge 36 ] && [ "$AFP_N" -ge 36 ] && [ "$AFP_N" -le 50 ]; then
    result $T "AF_PACKET goes dark under XDP takeover" PASS \
        "afp=$AFP_N (40 baseline, dark under takeover), xdp=$XDP_N of 40"
elif [ "$AFP_N" -gt 50 ]; then
    result $T "AF_PACKET goes dark under XDP takeover" FAIL \
        "afp=$AFP_N >50: AF_PACKET still sees redirected traffic, no takeover (xdp=$XDP_N)"
elif [ "$AFP_N" -lt 36 ]; then
    result $T "AF_PACKET goes dark under XDP takeover" FAIL \
        "afp=$AFP_N <36: baseline observer broken, darkness assertion vacuous (xdp=$XDP_N)"
else
    result $T "AF_PACKET goes dark under XDP takeover" FAIL \
        "xdp=$XDP_N of 40: capture itself missed the flow (afp=$AFP_N)"
fi

finish
