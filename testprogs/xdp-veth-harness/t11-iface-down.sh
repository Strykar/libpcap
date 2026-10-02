#!/bin/bash
# t11-iface-down.sh - OBSERVATION script for matrix item 28 (link down /
# link deleted mid-capture). Open question: does plain "ip link set down"
# raise any event on the xsk fd at all? Device unregister wakes the
# socket (netdev notifier sets sk_err); plain down plausibly produces
# nothing (poll times out, dispatch sees silence), which would make the
# module's "interface went down" error path unreachable. Phases a, b and
# d therefore RECORD what happens instead of presuming a branch; only
# unbounded behavior fails them.
#
# Phase a: link down mid-capture, classified as one of
#          SILENT-WAIT   dispatch keeps timing out, no error
#          ERROR-RETURN  pcap_dispatch returns PCAP_ERROR with message
#          HANG          no return within the bound (the only FAIL)
#          Pass = bounded behavior + the classification recorded as data.
# Phase b: bring the link back up, resend traffic: record whether
#          delivery RESUMES (XSK bind survival across down/up is
#          driver-dependent; this datum decides the man-page text).
# Phase c: ip link del mid-capture -> hard assertion: error return with
#          disappeared-class wording, bounded time.
# Phase d: tail-survival: queue descriptors, take the link down, only
#          then start dispatching (xdp_capture -D): record whether the
#          pre-event descriptors are RETRIEVABLE or LOST (decides
#          whether the error path should drain before reporting).
set -u
# shellcheck disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
guard
build_helpers
mk_tmp
T=t11
trap cleanup_common EXIT

setup_rig

# --- phase a: link down mid-capture, classify --------------------------------
F_A="link down mid-capture: bounded + classified"
timeout 20 "$HELPER_BIN/xdp_capture" -t 250 -c 0 -w 8 "xdp:$HOST_IF" \
    >"$TMP/a.log" 2>&1 &
PID=$!
if wait_for_line "$TMP/a.log" ACTIVATE_OK 5; then
    gen_ping 60 0.05 &      # ~3 s of traffic spanning the down
    PINGER=$!
    if wait_for_line "$TMP/a.log" '^PKT' 5; then
        sleep 0.5
        ip link set "$HOST_IF" down
        wait "$PID"
        RC=$?
        if [ "$RC" -eq 124 ]; then
            result $T "$F_A" FAIL \
                "HANG: dispatch did not return within the bound after link down"
        elif grep -q DISPATCH_ERR "$TMP/a.log"; then
            result $T "$F_A" PASS \
                "classification=ERROR-RETURN: $(grep -m1 DISPATCH_ERR "$TMP/a.log")"
        elif [ "$RC" -eq 0 ] && grep -q DELIVERED "$TMP/a.log"; then
            result $T "$F_A" PASS \
                "classification=SILENT-WAIT: no event on the xsk fd, dispatch timed out to the wall budget with no error"
        else
            result $T "$F_A" FAIL \
                "unclassifiable: rc=$RC: $(tail -n1 "$TMP/a.log")"
        fi
    else
        kill "$PID" 2>/dev/null || true
        wait "$PID" 2>/dev/null || true
        result $T "$F_A" FAIL \
            "no pre-down delivery, classification vacuous: $(tail -n1 "$TMP/a.log")"
    fi
    wait "$PINGER" 2>/dev/null || true
else
    wait "$PID" 2>/dev/null || true
    result $T "$F_A" FAIL \
        "capture failed to activate: $(tail -n1 "$TMP/a.log")"
fi
ip link set "$HOST_IF" up 2>/dev/null || true

# --- phase b: down, then up, does delivery resume? ----------------------------
# Phase a's capture has exited; settle the async queue-0 release before
# rebinding or this activate races it to EBUSY (not part of the datum).
settle_queue
F_B="down/up mid-capture: delivery resumption datum"
timeout 25 "$HELPER_BIN/xdp_capture" -k -t 250 -c 0 -w 12 "xdp:$HOST_IF" \
    >"$TMP/b.log" 2>&1 &
PID=$!
if wait_for_line "$TMP/b.log" ACTIVATE_OK 5; then
    gen_ping 10 0.05
    if wait_for_line "$TMP/b.log" '^PKT' 5; then
        sleep 0.5   # let in-flight deliveries settle before the baseline
        N1=$(grep -c '^PKT' "$TMP/b.log")
        ip link set "$HOST_IF" down
        sleep 1
        ip link set "$HOST_IF" up
        sleep 1
        gen_ping 10 0.05
        sleep 1
        wait "$PID"
        RC=$?
        N2=$(grep -c '^PKT' "$TMP/b.log")
        ERRS=$(grep -c DISPATCH_ERR "$TMP/b.log")
        if [ "$RC" -eq 124 ]; then
            result $T "$F_B" FAIL \
                "HANG: helper did not return within the bound across down/up"
        elif [ "$N2" -gt "$N1" ]; then
            result $T "$F_B" PASS \
                "RESUMES: pre-down=$N1 post-up=$((N2 - N1)) dispatch_err_lines=$ERRS; XSK bind survived down/up on veth"
        else
            result $T "$F_B" PASS \
                "NO-RESUME: pre-down=$N1 post-up=0 dispatch_err_lines=$ERRS; delivery did not resume after down/up on veth"
        fi
    else
        kill "$PID" 2>/dev/null || true
        wait "$PID" 2>/dev/null || true
        result $T "$F_B" FAIL \
            "no pre-down delivery, resumption datum vacuous: $(tail -n1 "$TMP/b.log")"
    fi
else
    wait "$PID" 2>/dev/null || true
    result $T "$F_B" FAIL \
        "capture failed to activate: $(tail -n1 "$TMP/b.log")"
fi
ip link set "$HOST_IF" up 2>/dev/null || true

# --- phase c: link deleted mid-capture (hard assertion) -----------------------
# Link-del IS detectable: NETDEV_UNREGISTER sets sk_err=ENETDOWN on the
# xsk socket (probed live with getsockopt(SO_ERROR)), even though xsk_poll
# never raises POLLERR. The module checks SO_ERROR on the idle-timeout
# path and reports "The interface disappeared". So this is a hard
# assertion: a disappeared-class error is the PASS, SILENT is a FAIL (the
# SO_ERROR detection regressed), a hang is a FAIL. (Plain-down in phase a
# sets no sk_err and stays genuinely SILENT - that is the documented
# limitation, not this case.) Real-NIC behavior still unverified.
# Phase b's capture has exited; settle the async queue-0 release first.
settle_queue
F_C="link del mid-capture -> disappeared-class error"
timeout 15 "$HELPER_BIN/xdp_capture" -t 250 -c 0 -w 10 "xdp:$HOST_IF" \
    >"$TMP/c.log" 2>&1 &
PID=$!
if wait_for_line "$TMP/c.log" ACTIVATE_OK 5; then
    sleep 0.5
    ip link del "$HOST_IF"
    wait "$PID"
    RC=$?
    if [ "$RC" -eq 124 ]; then
        result $T "$F_C" FAIL \
            "HANG: dispatch never returned after the device vanished"
    elif grep -q DISPATCH_ERR "$TMP/c.log" &&
            grep -Eiq 'disappear|no such device|enodev|enxio|removed|gone' \
                "$TMP/c.log"; then
        result $T "$F_C" PASS \
            "$(grep -m1 DISPATCH_ERR "$TMP/c.log") (via SO_ERROR=ENETDOWN, not POLLERR)"
    elif grep -q DISPATCH_ERR "$TMP/c.log"; then
        result $T "$F_C" FAIL \
            "errored but text lacks a disappeared class: $(grep -m1 DISPATCH_ERR "$TMP/c.log")"
    else
        result $T "$F_C" FAIL \
            "SILENT: link-del raised no dispatch error (rc=$RC); the SO_ERROR check should have caught ENETDOWN"
    fi
else
    wait "$PID" 2>/dev/null || true
    result $T "$F_C" FAIL \
        "capture failed to activate: $(tail -n1 "$TMP/c.log")"
fi

# --- phase d: tail-survival of pre-down descriptors ---------------------------
# Activate with a 5 s pre-dispatch delay (-D 5000): the burst lands in
# the RX ring and the link goes down BEFORE the first dispatch call ever
# runs. Whatever the loop then delivers is the tail-survival datum.
F_D="tail-survival of pre-down descriptors"
setup_rig   # phase c deleted the rig
timeout 25 "$HELPER_BIN/xdp_capture" -D 5000 -k -t 250 -c 0 -w 4 \
    "xdp:$HOST_IF" >"$TMP/d.log" 2>&1 &
PID=$!
if wait_for_line "$TMP/d.log" ACTIVATE_OK 5; then
    T0=$SECONDS
    pump_burst 100 &        # ~1 s of sends into the unconsumed RX ring
    BURST=$!
    sleep 1.5
    ip link set "$HOST_IF" down
    DOWN_AT=$((SECONDS - T0))
    wait "$BURST" 2>/dev/null || true
    wait "$PID"
    RC=$?
    GOT=$(grep -c '^PKT' "$TMP/d.log")
    ERRS=$(grep -c DISPATCH_ERR "$TMP/d.log")
    STATS=$(grep -m1 '^STATS' "$TMP/d.log" || true)
    if [ "$RC" -eq 124 ]; then
        result $T "$F_D" FAIL \
            "HANG: helper did not return within the bound"
    elif [ "$DOWN_AT" -ge 5 ]; then
        result $T "$F_D" FAIL \
            "sequencing broke: link down landed ${DOWN_AT}s after activate, outside the 5s pre-dispatch window"
    elif [ "$GOT" -gt 0 ]; then
        result $T "$F_D" PASS \
            "RETRIEVABLE: $GOT of ~100 pre-down descriptors delivered after the down (dispatch_err_lines=$ERRS, $STATS)"
    else
        result $T "$F_D" PASS \
            "LOST: 0 pre-down descriptors delivered (dispatch_err_lines=$ERRS, $STATS); a/b proved the delivery path on this rig shape"
    fi
else
    wait "$PID" 2>/dev/null || true
    result $T "$F_D" FAIL \
        "capture failed to activate: $(tail -n1 "$TMP/d.log")"
fi

finish
