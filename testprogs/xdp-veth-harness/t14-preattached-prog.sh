#!/bin/bash
# t14-preattached-prog.sh - falsifier for matrix item 31 (already-attached
# XDP prog defeats the default-prog attach).
#
# Pre-attach a minimal XDP program DIRECTLY via netlink (ip link ...
# xdpgeneric obj), bypassing the libxdp dispatcher: the module's
# xsk_socket__create must then fail, and the contract is a clear error
# naming the conflict (a generic strerror(EBUSY) does not satisfy it).
# Candidate objects: xdp-tools' packaged filters, then a clang-compiled
# helpers/bpf/xdp_pass.c, else SKIP with the manual command documented.
set -u
# shellcheck disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
guard
build_helpers
mk_tmp
T=t14
ATTACHED=0

# shellcheck disable=SC2329  # invoked via trap
cleanup() {
    if [ "$ATTACHED" -eq 1 ]; then
        ip link set dev "$HOST_IF" xdpgeneric off 2>/dev/null || true
    fi
    cleanup_common
}
trap cleanup EXIT

setup_rig

# Find an attachable XDP object.
OBJ=""
for CAND in /usr/lib/bpf/xdpfilt_alw_all.o /usr/lib/bpf/xdp-dispatcher.o; do
    if [ -f "$CAND" ] &&
            ip link set dev "$HOST_IF" xdpgeneric obj "$CAND" sec xdp \
                >/dev/null 2>&1; then
        OBJ=$CAND
        ATTACHED=1
        break
    fi
done
if [ -z "$OBJ" ] && require_tool clang; then
    if clang -O2 -target bpf -c "$HELPER_DIR/bpf/xdp_pass.c" \
            -o "$HELPER_BIN/xdp_pass.o" 2>"$TMP/clang.log" &&
        ip link set dev "$HOST_IF" xdpgeneric obj "$HELPER_BIN/xdp_pass.o" \
            sec xdp >/dev/null 2>&1; then
        OBJ="$HELPER_BIN/xdp_pass.o"
        ATTACHED=1
    fi
fi
if [ -z "$OBJ" ]; then
    result $T "pre-attached XDP prog -> clear conflict error" SKIP \
        "no loadable XDP object; manual: ip link set dev $HOST_IF xdpgeneric obj <prog.o> sec xdp, then expect a conflict error from activate"
    finish
fi
if ! ip link show "$HOST_IF" | grep -q xdp; then
    result $T "pre-attached XDP prog -> clear conflict error" SKIP \
        "attach of $OBJ reported success but no xdp flag on $HOST_IF"
    finish
fi

timeout 10 "$HELPER_BIN/xdp_capture" -A "xdp:$HOST_IF" >"$TMP/c.log" 2>&1
RC=$?
if [ "$RC" -eq 0 ]; then
    result $T "pre-attached XDP prog -> clear conflict error" FAIL \
        "activated despite the pre-attached prog (displaced it, or attach silently failed)"
elif [ "$RC" -eq 4 ] && grep -Eiq 'prog|attach|conflict' "$TMP/c.log"; then
    result $T "pre-attached XDP prog -> clear conflict error" PASS \
        "$(grep ACTIVATE_ERR "$TMP/c.log") [obj: $(basename "$OBJ")]"
elif [ "$RC" -eq 4 ]; then
    result $T "pre-attached XDP prog -> clear conflict error" FAIL \
        "refused but error text does not name the conflict: $(grep ACTIVATE_ERR "$TMP/c.log")"
elif [ "$RC" -eq 124 ]; then
    result $T "pre-attached XDP prog -> clear conflict error" FAIL \
        "hang activating against a pre-attached prog"
else
    result $T "pre-attached XDP prog -> clear conflict error" FAIL \
        "$(tail -n1 "$TMP/c.log")"
fi

finish
