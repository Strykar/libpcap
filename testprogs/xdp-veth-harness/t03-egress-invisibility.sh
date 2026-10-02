#!/bin/bash
# t03-egress-invisibility.sh - falsifier for matrix item 7 (ingress-only
# capture, setdirection_op NULL).
#
# XDP is an RX driver hook: locally originated egress never traverses it.
# The host pings the ns peer through veth0: the 20 echo requests are
# egress on veth0 (must be invisible), the 20 echo replies are inbound
# (must be captured). Expected count ~20; ~40 falsifies ingress-only.
set -u
# shellcheck disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
guard
build_helpers
mk_tmp
T=t03
trap cleanup_common EXIT

setup_rig

"$HELPER_BIN/xdp_capture" -f icmp -c 0 -w 8 -t 250 "xdp:$HOST_IF" \
    >"$TMP/xdp.log" 2>&1 &
XDP_PID=$!
if ! wait_for_line "$TMP/xdp.log" ACTIVATE_OK 5; then
    result $T "egress invisible, inbound replies visible" FAIL \
        "xdp capture failed to activate: $(tail -n1 "$TMP/xdp.log")"
    finish
fi

# Host-side ping: requests egress veth0, ns replies ingress veth0. The
# replies are then consumed by the XSK, so ping reports 100% loss; that
# is the takeover working, not a failure.
ping -I "$HOST_IF" -c 20 -i 0.1 -W 0.2 "$PEER_IP" >/dev/null 2>&1 || true
wait "$XDP_PID" || true

N=$(sed -n 's/^DELIVERED //p' "$TMP/xdp.log")
N=${N:-0}

if [ "$N" -ge 16 ] && [ "$N" -le 24 ]; then
    result $T "egress invisible, inbound replies visible" PASS \
        "captured $N icmp (expect ~20 replies, not ~40 with requests)"
elif [ "$N" -gt 24 ]; then
    result $T "egress invisible, inbound replies visible" FAIL \
        "captured $N icmp of 20 expected: egress packets are visible, ingress-only claim falsified"
else
    result $T "egress invisible, inbound replies visible" FAIL \
        "captured only $N icmp of ~20 replies: inbound path broken, invisibility assertion vacuous"
fi

finish
