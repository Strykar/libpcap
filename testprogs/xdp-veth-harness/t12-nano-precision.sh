#!/bin/bash
# t12-nano-precision.sh - falsifier for matrix items 6 and 29 (nano
# precision claimed but unreachable).
#
# Capture with PCAP_TSTAMP_PRECISION_NANO and assert the timestamps carry
# genuine nanosecond-range values: across ~20 packets at least one
# fractional part must not be a multiple of 1000 (micro values scaled up
# would all be), and none may exceed 999999999. NANO_NOTSUP from
# pcap_set_tstamp_precision reproduces the item-29 skeleton bug (the
# precision list is never registered in create).
set -u
# shellcheck disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
guard
build_helpers
mk_tmp
T=t12
trap cleanup_common EXIT

setup_rig

"$HELPER_BIN/xdp_capture" -N -f icmp -c 20 -w 10 -t 250 "xdp:$HOST_IF" \
    >"$TMP/nano.log" 2>&1 &
PID=$!
sleep 1
if grep -q NANO_NOTSUP "$TMP/nano.log"; then
    wait "$PID" 2>/dev/null || true
    result $T "nano timestamps carry ns-range values" FAIL \
        "pcap_set_tstamp_precision(NANO) refused: precision list never registered (item 29)"
    finish
fi
if ! wait_for_line "$TMP/nano.log" ACTIVATE_OK 5; then
    wait "$PID" 2>/dev/null || true
    result $T "nano timestamps carry ns-range values" FAIL \
        "capture failed to activate: $(tail -n1 "$TMP/nano.log")"
    finish
fi

gen_ping 25 0.05
wait "$PID" || true

TOTAL=0
NONMULT=0
OVERFLOW=0
while read -r _ _ FRAC _ _; do
    TOTAL=$((TOTAL + 1))
    if [ $((FRAC % 1000)) -ne 0 ]; then
        NONMULT=$((NONMULT + 1))
    fi
    if [ "$FRAC" -gt 999999999 ]; then
        OVERFLOW=$((OVERFLOW + 1))
    fi
done < <(grep '^PKT ' "$TMP/nano.log")

if [ "$TOTAL" -ge 10 ] && [ "$NONMULT" -ge 1 ] && [ "$OVERFLOW" -eq 0 ]; then
    result $T "nano timestamps carry ns-range values" PASS \
        "$NONMULT of $TOTAL fractional parts not multiples of 1000, none >999999999"
elif [ "$TOTAL" -lt 10 ]; then
    result $T "nano timestamps carry ns-range values" FAIL \
        "only $TOTAL packets captured, sample too small"
elif [ "$OVERFLOW" -gt 0 ]; then
    result $T "nano timestamps carry ns-range values" FAIL \
        "$OVERFLOW of $TOTAL fractional parts exceed 999999999"
else
    result $T "nano timestamps carry ns-range values" FAIL \
        "all $TOTAL fractional parts are multiples of 1000: micro values delivered as nano"
fi

finish
