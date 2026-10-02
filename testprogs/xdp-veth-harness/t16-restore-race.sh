#!/bin/bash
# t16-restore-race.sh - falsifier for the cross-handle rx-vlan-offload
# restore race, state-machine assertions only (tag semantics are not
# veth-assertable). The module clears rx-vlan-offload at activate and
# restores it at cleanup per handle, with no cross-handle refcount: the
# first handle's close re-enables the feature under a still-capturing
# second handle, which silently goes tagless. This script makes that
# documented hazard visible as ethtool -k transitions across two
# concurrent handles on different queues (HOST_IF has numrxqueues 4
# from setup_rig).
#
# Sequence: baseline on (SKIP if veth pins the feature fixed) ->
# A=xdp:HOST_IF:0 activates (reads off) -> B=xdp:HOST_IF:1 activates
# while A holds (still off; B records no restore) -> close A (reads ON
# under live B: the hazard) -> close B (stays ON: B restores nothing).
# Closes are kill -TERM against xdp_capture -S: the helper breakloops
# and exits through pcap_close, so the module's cleanup-time restore
# actually runs (a raw kill would skip it).
set -u
# shellcheck disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
guard
build_helpers
mk_tmp
T=t16
PIDA=""
PIDB=""

# shellcheck disable=SC2329  # invoked via trap
cleanup() {
    local p
    for p in "$PIDA" "$PIDB"; do
        if [ -n "$p" ]; then
            kill -TERM "$p" 2>/dev/null || true
            wait "$p" 2>/dev/null || true
        fi
    done
    cleanup_common
}
trap cleanup EXIT

setup_rig

rxvlan_state() {
    ethtool -k "$HOST_IF" 2>/dev/null | sed -n 's/^rx-vlan-offload: *//p'
}

# --- baseline: rx-vlan-offload on -------------------------------------------
STATE=$(rxvlan_state)
case $STATE in
*fixed*)
    result $T "cross-handle rxvlan restore race" SKIP \
        "veth pins rx-vlan-offload ($STATE); state transitions not assertable"
    finish
    ;;
off)
    ethtool -K "$HOST_IF" rxvlan on >/dev/null 2>&1 || true
    STATE=$(rxvlan_state)
    ;;
esac
if [ "$STATE" != on ]; then
    result $T "cross-handle rxvlan restore race" SKIP \
        "cannot establish rx-vlan-offload=on baseline (state: ${STATE:-absent})"
    finish
fi

# --- handle A on queue 0: activate must clear the feature --------------------
timeout 60 "$HELPER_BIN/xdp_capture" -S -t 250 -c 0 -w 45 "xdp:$HOST_IF:0" \
    >"$TMP/a.log" 2>&1 &
PIDA=$!
if ! wait_for_line "$TMP/a.log" ACTIVATE_OK 5; then
    wait "$PIDA" 2>/dev/null || true
    PIDA=""
    result $T "cross-handle rxvlan restore race" FAIL \
        "handle A (queue 0) failed to activate: $(tail -n1 "$TMP/a.log")"
    finish
fi
STATE=$(rxvlan_state)
if [ "$STATE" = off ]; then
    result $T "A(q0) activate clears rx-vlan-offload" PASS ""
else
    result $T "A(q0) activate clears rx-vlan-offload" FAIL \
        "ethtool reads '$STATE' under an active handle, want off"
fi

# --- handle B on queue 1 while A holds: already off, no restore recorded -----
timeout 60 "$HELPER_BIN/xdp_capture" -S -t 250 -c 0 -w 45 "xdp:$HOST_IF:1" \
    >"$TMP/b.log" 2>&1 &
PIDB=$!
if ! wait_for_line "$TMP/b.log" ACTIVATE_OK 5; then
    wait "$PIDB" 2>/dev/null || true
    PIDB=""
    result $T "cross-handle rxvlan restore race" FAIL \
        "handle B (queue 1) failed to activate under A: $(tail -n1 "$TMP/b.log")"
    finish
fi
STATE=$(rxvlan_state)
if [ "$STATE" = off ]; then
    result $T "B(q1) under A: rx-vlan-offload stays off" PASS ""
else
    result $T "B(q1) under A: rx-vlan-offload stays off" FAIL \
        "ethtool reads '$STATE' with both handles active, want off"
fi

# --- close A: restore fires while B still captures (the hazard) --------------
kill -TERM "$PIDA"
wait "$PIDA" 2>/dev/null || true
PIDA=""
STATE=$(rxvlan_state)
if ! kill -0 "$PIDB" 2>/dev/null; then
    result $T "close A -> offload restored under live B" FAIL \
        "B exited before the post-close-A assertion; race not observable (state: $STATE)"
elif [ "$STATE" = on ]; then
    result $T "close A -> offload restored under live B" PASS \
        "B is now silently tagless: the documented cross-handle restore hazard"
else
    result $T "close A -> offload restored under live B" FAIL \
        "ethtool reads '$STATE' after close A under live B, want on (no restore fired?)"
fi

# --- close B: saw already-off at activate, so restores nothing ---------------
kill -TERM "$PIDB"
wait "$PIDB" 2>/dev/null || true
PIDB=""
STATE=$(rxvlan_state)
if [ "$STATE" = on ]; then
    result $T "close B -> offload stays on, no restore" PASS ""
else
    result $T "close B -> offload stays on, no restore" FAIL \
        "ethtool reads '$STATE' after close B, want on (B restored a snapshot it never set?)"
fi

finish
