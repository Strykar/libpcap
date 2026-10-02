#!/bin/bash
# t02-queue-miss.sh - falsifier for matrix item 4 (single-queue binding vs
# whole-interface capture).
#
# The module binds (ifname, queue 0) only. With the ns peer given 4 TX
# queues, veth hashes each flow to a queue by the sender's TX queue pick,
# so 48 distinct UDP flows spread across host RX queues 0-3 and the
# queue-0 capture must MISS roughly three quarters of them, while the
# peer side sees everything. Falsified if the xdp capture sees ~all
# flows (the module would secretly be whole-interface).
set -u
# shellcheck disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
guard
build_helpers
mk_tmp
T=t02
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
    result $T "queue-0 capture misses queue>0 flows" SKIP \
        "tcpdump or socat missing"
    finish
fi

setup_rig 4   # peer gets 4 TX queues: flows spread across host RX queues

# Peer-side ground truth (ESTIMATE.md item 23: same-interface AF_PACKET
# is blind to redirected frames; the peer side sees its own egress).
ip netns exec "$NS" tcpdump -i "$PEER_IF" -nn -p -w "$TMP/peer.pcap" \
    'udp and dst port 9002' >/dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 1

"$HELPER_BIN/xdp_capture" -f 'udp and dst port 9002' -c 100000 -w 12 \
    -t 250 "xdp:$HOST_IF" >"$TMP/xdp.log" 2>&1 &
XDP_PID=$!
if ! wait_for_line "$TMP/xdp.log" ACTIVATE_OK 5; then
    result $T "queue-0 capture misses queue>0 flows" FAIL \
        "xdp capture failed to activate: $(tail -n1 "$TMP/xdp.log")"
    finish
fi

gen_udp_flows 48 4 9002    # 192 datagrams over 48 flows, sports 7200-7247
sleep 1
wait "$XDP_PID" || true
kill -TERM "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true
TCPDUMP_PID=""

XDP_N=$(sed -n 's/^DELIVERED //p' "$TMP/xdp.log")
XDP_N=${XDP_N:-0}
PEER_N=$(tcpdump -r "$TMP/peer.pcap" 2>/dev/null | wc -l)

# Expected: peer ~192, xdp ~48 (the quarter of flows hashing to queue 0).
THRESH=$((PEER_N * 3 / 4))
if [ "$PEER_N" -lt 180 ]; then
    result $T "queue-0 capture misses queue>0 flows" FAIL \
        "peer ground truth saw only $PEER_N of 192: generator/observer broken"
elif [ "$XDP_N" -eq 0 ]; then
    result $T "queue-0 capture misses queue>0 flows" FAIL \
        "xdp=0 of peer=$PEER_N: no flow hashed to queue 0 (p~1e-6) or capture broken; rerun"
elif [ "$XDP_N" -le "$THRESH" ]; then
    result $T "queue-0 capture misses queue>0 flows" PASS \
        "xdp=$XDP_N of peer=$PEER_N: queue>0 flows missed as the single-queue contract says"
else
    result $T "queue-0 capture misses queue>0 flows" FAIL \
        "xdp=$XDP_N of peer=$PEER_N: queue-0 socket saw (nearly) everything, single-queue claim falsified"
fi

finish
