#!/bin/bash
# t04-breakloop.sh - falsifier for matrix item 13 (breakloop wakeup).
#
# A pcap_dispatch blocked on an idle interface (timeout 0 = forever) must
# return PCAP_ERROR_BREAK promptly when another thread calls
# pcap_breakloop (the eventfd-in-poll-set contract). Uses the compiled
# xdp_breakloop helper: in-tree threadsignaltest sleeps a fixed 60 s
# before breaking, too slow for a harness leg.
set -u
# shellcheck disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
guard
build_helpers
mk_tmp
T=t04
trap cleanup_common EXIT

setup_rig

timeout 15 "$HELPER_BIN/xdp_breakloop" "xdp:$HOST_IF" >"$TMP/b.log" 2>&1
RC=$?

if grep -q BREAK_OK "$TMP/b.log"; then
    result $T "breakloop wakes blocked dispatch" PASS \
        "$(grep BREAK_OK "$TMP/b.log")"
elif [ "$RC" -eq 124 ]; then
    result $T "breakloop wakes blocked dispatch" FAIL \
        "hang: pcap_breakloop did not wake the blocked dispatch within 15s"
else
    result $T "breakloop wakes blocked dispatch" FAIL \
        "$(tail -n1 "$TMP/b.log")"
fi

finish
