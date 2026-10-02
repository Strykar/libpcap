#!/bin/bash
# t15-enodev-races.sh - falsifiers for the ENODEV class (matrix items 9
# and 28): ip link del racing the activate window, and the xdp:any /
# xdp:nonexistent name shapes.
#
# Race arm: 12 iterations of activate-vs-delete on a throwaway veth pair
# with the delete delayed 0-50 ms to scan the window. Every iteration
# must end in either a successful activate or a clean
# PCAP_ERROR_NO_SUCH_DEVICE (-5); a hang, a crash, or a non-ENODEV error
# falsifies the clean-error contract.
# Name arms: "any" is not a netdev and the module must not pretend it
# is; both xdp:any and xdp:nonexistent must yield NO_SUCH_DEVICE.
set -u
# shellcheck disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
guard
build_helpers
mk_tmp
T=t15

# shellcheck disable=SC2329  # invoked via trap
cleanup() {
    ip link del pcxrace0 2>/dev/null || true
    cleanup_common
}
trap cleanup EXIT

# --- race arm ----------------------------------------------------------------
OK=0
ENODEV=0
OTHER=0
HANG=0
CRASH=0
OTHER_NOTE=""
for I in $(seq 1 12); do
    ip link add pcxrace0 type veth peer name pcxrace1 || continue
    ip link set pcxrace0 up
    ip link set pcxrace1 up
    timeout 5 "$HELPER_BIN/xdp_capture" -A xdp:pcxrace0 \
        >"$TMP/race.log" 2>&1 &
    HP=$!
    DELAY=$(awk -v i="$I" 'BEGIN { printf "%.3f", (i % 6) * 0.01 }')
    sleep "$DELAY"
    ip link del pcxrace0 2>/dev/null || true
    wait "$HP"
    RC=$?
    if [ "$RC" -eq 124 ]; then
        HANG=$((HANG + 1))
    elif [ "$RC" -ge 128 ]; then
        CRASH=$((CRASH + 1))
    elif grep -q ACTIVATE_OK "$TMP/race.log"; then
        OK=$((OK + 1))
    elif grep -q 'status=-5' "$TMP/race.log"; then
        ENODEV=$((ENODEV + 1))
    else
        OTHER=$((OTHER + 1))
        OTHER_NOTE=$(tail -n1 "$TMP/race.log")
    fi
    ip link del pcxrace0 2>/dev/null || true
done

if [ "$HANG" -eq 0 ] && [ "$CRASH" -eq 0 ] && [ "$OTHER" -eq 0 ]; then
    result $T "ip link del racing activate -> clean ENODEV class" PASS \
        "12 iterations: $OK activated, $ENODEV NO_SUCH_DEVICE, no hang/crash/other"
else
    result $T "ip link del racing activate -> clean ENODEV class" FAIL \
        "hang=$HANG crash=$CRASH other=$OTHER (ok=$OK enodev=$ENODEV) ${OTHER_NOTE:+last-other: $OTHER_NOTE}"
fi

# --- name arms ---------------------------------------------------------------
setup_rig   # ensure a sane host state; the names below must still fail

timeout 10 "$HELPER_BIN/xdp_capture" -A xdp:any >"$TMP/any.log" 2>&1
RC=$?
if [ "$RC" -eq 4 ] && grep -q 'status=-5' "$TMP/any.log"; then
    result $T "xdp:any -> NO_SUCH_DEVICE" PASS ""
elif [ "$RC" -eq 0 ]; then
    result $T "xdp:any -> NO_SUCH_DEVICE" FAIL \
        "xdp:any activated; 'any' is not a netdev the module can bind"
else
    result $T "xdp:any -> NO_SUCH_DEVICE" FAIL \
        "want status=-5, got: $(tail -n1 "$TMP/any.log")"
fi

timeout 10 "$HELPER_BIN/xdp_capture" -A xdp:pcxnodev0 >"$TMP/nodev.log" 2>&1
RC=$?
if [ "$RC" -eq 4 ] && grep -q 'status=-5' "$TMP/nodev.log"; then
    result $T "xdp:nonexistent -> NO_SUCH_DEVICE" PASS ""
else
    result $T "xdp:nonexistent -> NO_SUCH_DEVICE" FAIL \
        "want status=-5, got: $(tail -n1 "$TMP/nodev.log")"
fi

finish
