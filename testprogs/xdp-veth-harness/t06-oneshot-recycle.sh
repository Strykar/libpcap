#!/bin/bash
# t06-oneshot-recycle.sh - falsifier for matrix item 18 (oneshot vs
# recycled umem frames).
#
# pcap_next's returned pointer must survive ring recycling: the module's
# oneshot callback memcpys out of the umem frame (pcap-linux pattern)
# because the frame returns to the fill ring at batch end and the kernel
# rewrites it. The helper grabs one packet, then the script pumps 500
# inbound frames (fill depth is 256, so the original frame is certainly
# reused), then the helper re-compares the pointer against a shadow copy.
# If BUILD_DIR is ASan-instrumented the helper runs under strict
# ASAN_OPTIONS as well; otherwise only the functional assert runs.
set -u
# shellcheck disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
guard
build_helpers
mk_tmp
T=t06
trap cleanup_common EXIT

if ! require_tool socat; then
    result $T "oneshot data survives ring wrap" SKIP "socat missing"
    finish
fi

setup_rig

ASAN_NOTE="ASan leg skipped (BUILD_DIR not ASan-instrumented)"
if [ "$PCAP_ASAN" = 1 ]; then
    export ASAN_OPTIONS="abort_on_error=1:detect_leaks=0"
    ASAN_NOTE="ran under ASan (abort_on_error=1)"
fi

FIFO="$TMP/oneshot.fifo"
mkfifo "$FIFO"
"$HELPER_BIN/xdp_oneshot" "xdp:$HOST_IF" <"$FIFO" >"$TMP/oneshot.log" 2>&1 &
HPID=$!
exec 3>"$FIFO"

if ! wait_for_line "$TMP/oneshot.log" ACTIVATE_OK 5; then
    result $T "oneshot data survives ring wrap" FAIL \
        "helper failed to activate: $(tail -n1 "$TMP/oneshot.log")"
    exec 3>&-
    finish
fi

# One datagram for pcap_next to grab.
gen_udp_flow 1 7106 9006
if ! wait_for_line "$TMP/oneshot.log" PUMP_NOW 10; then
    result $T "oneshot data survives ring wrap" FAIL \
        "helper never captured the probe packet: $(tail -n1 "$TMP/oneshot.log")"
    kill "$HPID" 2>/dev/null || true
    exec 3>&-
    finish
fi

# Cycle every fill-ring frame while the helper holds its pointer.
pump_burst 500
sleep 1
echo "done" >&3
wait "$HPID"
RC=$?
exec 3>&-

if grep -q ONESHOT_STABLE "$TMP/oneshot.log"; then
    result $T "oneshot data survives ring wrap" PASS "$ASAN_NOTE"
elif grep -q ONESHOT_MUTATED "$TMP/oneshot.log"; then
    result $T "oneshot data survives ring wrap" FAIL \
        "returned bytes mutated under ring wrap: oneshot aliases a recycled umem frame"
elif [ "$RC" -ge 128 ]; then
    result $T "oneshot data survives ring wrap" FAIL \
        "helper died with signal $((RC - 128)) ($ASAN_NOTE)"
else
    result $T "oneshot data survives ring wrap" FAIL \
        "$(tail -n1 "$TMP/oneshot.log")"
fi

finish
