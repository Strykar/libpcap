#!/bin/bash
# t07-stats.sh - falsifier for matrix item 10 (stats_op / ps_drop
# semantics).
#
# Contract: ps_recv counts post-filter delivered packets only (userspace
# filter rejects are excluded; DPDK's pre-filter counting is flagged
# do-not-copy). 40 matching datagrams plus 25 non-matching ones arrive;
# ps_recv and the delivered count must both be exactly 40, ps_drop 0.
set -u
# shellcheck disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
guard
build_helpers
mk_tmp
T=t07
trap cleanup_common EXIT

if ! require_tool socat; then
    result $T "ps_recv matches post-filter count" SKIP "socat missing"
    finish
fi

setup_rig

"$HELPER_BIN/xdp_capture" -f 'udp and dst port 9007' -c 0 -w 8 -t 250 \
    "xdp:$HOST_IF" >"$TMP/xdp.log" 2>&1 &
XDP_PID=$!
if ! wait_for_line "$TMP/xdp.log" ACTIVATE_OK 5; then
    result $T "ps_recv matches post-filter count" FAIL \
        "xdp capture failed to activate: $(tail -n1 "$TMP/xdp.log")"
    finish
fi

gen_udp_flow 40 7107 9007    # matching
gen_udp_flow 25 7108 9008    # non-matching: filtered in userspace
wait "$XDP_PID" || true

DELIVERED=$(sed -n 's/^DELIVERED //p' "$TMP/xdp.log")
DELIVERED=${DELIVERED:-0}
RECV=$(sed -n 's/^STATS recv=\([0-9]*\).*/\1/p' "$TMP/xdp.log")
RECV=${RECV:--1}
DROP=$(sed -n 's/^STATS recv=[0-9]* drop=\([0-9]*\).*/\1/p' "$TMP/xdp.log")
DROP=${DROP:--1}

if [ "$DELIVERED" -eq 40 ] && [ "$RECV" -eq 40 ] && [ "$DROP" -eq 0 ]; then
    result $T "ps_recv matches post-filter count" PASS \
        "delivered=40 ps_recv=40 ps_drop=0 (25 non-matching excluded)"
elif [ "$RECV" -eq 65 ]; then
    result $T "ps_recv matches post-filter count" FAIL \
        "ps_recv=65: counts pre-filter (the DPDK deviation the matrix forbids)"
else
    result $T "ps_recv matches post-filter count" FAIL \
        "delivered=$DELIVERED ps_recv=$RECV ps_drop=$DROP (want 40/40/0)"
fi

finish
