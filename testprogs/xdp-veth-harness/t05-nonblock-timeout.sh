#!/bin/bash
# t05-nonblock-timeout.sh - falsifiers for matrix items 14 and 15
# (nonblock mapping, timeout mapping).
#
# Arm 1: with pcap_setnonblock(1) and an idle interface, one
# pcap_dispatch must return 0 immediately (<100 ms).
# Arm 2: blocking with timeout_ms=600 on an idle interface, one
# pcap_dispatch must return 0 after ~600 ms (450-2500 ms tolerance).
set -u
# shellcheck disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
guard
build_helpers
mk_tmp
T=t05
trap cleanup_common EXIT

setup_rig

# Arm 1: nonblock idle -> immediate 0.
timeout 10 "$HELPER_BIN/xdp_capture" -n -1 -t 250 "xdp:$HOST_IF" \
    >"$TMP/nb.log" 2>&1 || true
RET=$(awk '/^DISPATCH_RET/ {print $2}' "$TMP/nb.log")
ELAPSED=$(awk '/^DISPATCH_RET/ {print $4}' "$TMP/nb.log")
if [ "${RET:-x}" = "0" ] && [ "${ELAPSED:-99999}" -lt 100 ]; then
    result $T "nonblock idle returns 0 immediately" PASS \
        "ret=0 in ${ELAPSED}ms"
elif [ -z "${RET:-}" ]; then
    result $T "nonblock idle returns 0 immediately" FAIL \
        "no DISPATCH_RET (hang or activate failure): $(tail -n1 "$TMP/nb.log")"
else
    result $T "nonblock idle returns 0 immediately" FAIL \
        "ret=$RET elapsed=${ELAPSED}ms (want ret=0 in <100ms)"
fi

# Arm 2: blocking idle honors timeout_ms. Arm 1's XSK release is async,
# so settle before rebinding queue 0 or this activate races it to EBUSY.
settle_queue
timeout 10 "$HELPER_BIN/xdp_capture" -1 -t 600 "xdp:$HOST_IF" \
    >"$TMP/to.log" 2>&1 || true
RET=$(awk '/^DISPATCH_RET/ {print $2}' "$TMP/to.log")
ELAPSED=$(awk '/^DISPATCH_RET/ {print $4}' "$TMP/to.log")
if [ "${RET:-x}" = "0" ] && [ "${ELAPSED:-0}" -ge 450 ] &&
        [ "${ELAPSED:-99999}" -le 2500 ]; then
    result $T "blocking dispatch honors timeout_ms=600" PASS \
        "ret=0 in ${ELAPSED}ms"
elif [ -z "${RET:-}" ]; then
    result $T "blocking dispatch honors timeout_ms=600" FAIL \
        "no DISPATCH_RET within 10s (timeout not honored): $(tail -n1 "$TMP/to.log")"
else
    result $T "blocking dispatch honors timeout_ms=600" FAIL \
        "ret=$RET elapsed=${ELAPSED}ms (want ret=0 in 450-2500ms)"
fi

finish
