#!/bin/bash
# t10-rfmon-protocol.sh - falsifiers for matrix items 27 and 25.
#
# Arm 1: pcap_set_rfmon(1) then activate must return
#        PCAP_ERROR_RFMON_NOTSUP (-6), not silently ignore the request.
# Arm 2: pcap_set_protocol_linux(nonzero) then activate must refuse
#        loudly with PCAP_ERROR and an error text naming the protocol,
#        not silently capture everything.
set -u
# shellcheck disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
guard
build_helpers
mk_tmp
T=t10
trap cleanup_common EXIT

setup_rig

# Arm 1: rfmon.
timeout 10 "$HELPER_BIN/xdp_status" rfmon "xdp:$HOST_IF" \
    >"$TMP/rfmon.log" 2>&1 || true
if grep -q 'ACTIVATE_ERR status=-6' "$TMP/rfmon.log"; then
    result $T "rfmon request -> RFMON_NOTSUP" PASS ""
elif grep -q ACTIVATE_OK "$TMP/rfmon.log"; then
    result $T "rfmon request -> RFMON_NOTSUP" FAIL \
        "rfmon request silently ignored, activate succeeded (item 27)"
else
    result $T "rfmon request -> RFMON_NOTSUP" FAIL \
        "want status=-6, got: $(tail -n1 "$TMP/rfmon.log")"
fi

# Arm 2: nonzero protocol.
timeout 10 "$HELPER_BIN/xdp_status" proto "xdp:$HOST_IF" \
    >"$TMP/proto.log" 2>&1 || true
if grep -q 'ACTIVATE_ERR' "$TMP/proto.log" &&
        grep -Eiq 'protocol' "$TMP/proto.log"; then
    result $T "nonzero protocol -> loud refusal" PASS \
        "$(grep ACTIVATE_ERR "$TMP/proto.log")"
elif grep -q ACTIVATE_OK "$TMP/proto.log"; then
    result $T "nonzero protocol -> loud refusal" FAIL \
        "pcap_set_protocol_linux(3) silently ignored, activate succeeded (item 25)"
elif grep -q 'ACTIVATE_ERR' "$TMP/proto.log"; then
    result $T "nonzero protocol -> loud refusal" FAIL \
        "refused but error text does not name the protocol: $(tail -n1 "$TMP/proto.log")"
else
    result $T "nonzero protocol -> loud refusal" FAIL \
        "$(tail -n1 "$TMP/proto.log")"
fi

finish
