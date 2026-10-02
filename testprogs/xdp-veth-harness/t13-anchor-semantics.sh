#!/bin/bash
# t13-anchor-semantics.sh - rider falsifier for matrix item 12 (promisc
# anchor socket semantics).
#
# Activate with promisc=1, then assert:
#   (a) the interface promiscuity counter incremented (the
#       PACKET_MR_PROMISC membership took effect), and
#   (b) the anchor packet socket's receive queue stays ZERO under
#       traffic: an unbound proto-0 PF_PACKET socket receives nothing,
#       so nobody has to drain it. On FAIL the documented fallback is
#       attaching a reject-all cBPF filter to the anchor.
# The anchor is located in /proc/net/packet by intersecting the helper
# pid's socket inodes with proto-0000 rows. The anchor is never bound, so
# its Iface column is 0 (NOT the veth ifindex) - confirmed against a live
# /proc/net/packet; the inode intersection is what pins it to this helper.
# RcvQ is the Rmem column.
set -u
# shellcheck disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
guard
build_helpers
mk_tmp
T=t13
PID=""

# shellcheck disable=SC2329  # invoked via trap
cleanup() {
    if [ -n "$PID" ]; then
        kill "$PID" 2>/dev/null || true
    fi
    cleanup_common
}
trap cleanup EXIT

promiscuity() {
    ip -d link show "$1" | grep -o 'promiscuity [0-9]*' | head -n1 \
        | awk '{print $2}'
}

if ! require_tool socat; then
    result $T "promisc anchor: counter + zero RcvQ" SKIP "socat missing"
    finish
fi

setup_rig

BASE_PROM=$(promiscuity "$HOST_IF")

"$HELPER_BIN/xdp_capture" -p -f 'udp and dst port 9013' -c 0 -w 20 -t 250 \
    "xdp:$HOST_IF" >"$TMP/xdp.log" 2>&1 &
PID=$!
if ! wait_for_line "$TMP/xdp.log" ACTIVATE_OK 5; then
    result $T "promisc anchor: counter + zero RcvQ" FAIL \
        "promisc capture failed to activate: $(tail -n1 "$TMP/xdp.log")"
    finish
fi
sleep 0.3

# (a) promiscuity counter incremented
CUR_PROM=$(promiscuity "$HOST_IF")
if [ "$CUR_PROM" -eq $((BASE_PROM + 1)) ]; then
    result $T "promisc: ip -d promiscuity counter incremented" PASS \
        "promiscuity $BASE_PROM -> $CUR_PROM"
else
    result $T "promisc: ip -d promiscuity counter incremented" FAIL \
        "promiscuity $BASE_PROM -> $CUR_PROM (want +1)"
fi

# Traffic the anchor must NOT queue.
gen_udp_flow 60 7113 9013
pump_burst 200
sleep 0.5

# (b) anchor socket RcvQ stays zero. The anchor is an unbound proto-0
# PF_PACKET socket, so its Iface column is 0; the helper's socket inodes
# disambiguate it from any other process's proto-0 sockets.
INODES=$(find "/proc/$PID/fd" -lname 'socket:*' -printf '%l\n' 2>/dev/null \
    | sed 's/socket:\[\(.*\)\]/\1/')
ANCHOR_RMEM=""
while read -r INO RMEM; do
    for I in $INODES; do
        if [ "$I" = "$INO" ]; then
            ANCHOR_RMEM=$RMEM
            break 2
        fi
    done
done < <(awk \
    'NR > 1 && $4 == "0000" && $5 == 0 {print $9, $7}' /proc/net/packet)

if [ -z "$ANCHOR_RMEM" ]; then
    result $T "promisc anchor RcvQ zero under traffic" FAIL \
        "no unbound proto-0 packet socket (Iface 0) found for pid $PID in /proc/net/packet"
elif [ "$ANCHOR_RMEM" -eq 0 ]; then
    result $T "promisc anchor RcvQ zero under traffic" PASS \
        "anchor RcvQ=0 after 260 inbound packets"
else
    result $T "promisc anchor RcvQ zero under traffic" FAIL \
        "anchor queues traffic (RcvQ=$ANCHOR_RMEM): attach the reject-all cBPF filter fallback"
fi

kill -TERM "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
PID=""
sleep 0.3
END_PROM=$(promiscuity "$HOST_IF")
echo "info: promiscuity after capture exit: $END_PROM (baseline $BASE_PROM)"

finish
