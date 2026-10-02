#!/bin/bash
# t08-privileges.sh - falsifier for matrix item 22 (privilege model:
# 3 distinct EPERM sites + RLIMIT_MEMLOCK).
#
# Shape 1: no capabilities at all (setpriv to uid 65534, caps cleared by
#          the uid change) -> PCAP_ERROR_PERM_DENIED naming the missing
#          capabilities.
# Shape 2: full root caps EXCEPT CAP_IPC_LOCK, RLIMIT_MEMLOCK=64k (the
#          umem registration charges locked_vm) -> PERM_DENIED with a
#          memlock hint in the error text.
# Shape 3: full caps (plain root) -> activate succeeds.
#
# /home may be mode 750, so shape 1 stages the helper and libpcap.so
# into a world-readable /run dir before dropping to uid 65534.
set -u
# shellcheck disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
guard
build_helpers
mk_tmp
T=t08
STAGE=""

# shellcheck disable=SC2329  # invoked via trap
cleanup() {
    if [ -n "$STAGE" ]; then
        rm -rf "$STAGE"
    fi
    cleanup_common
}
trap cleanup EXIT

setup_rig

# --- shape 1: no caps -------------------------------------------------------
if require_tool setpriv; then
    STAGE=$(mktemp -d /run/pcxdp-stage.XXXXXX)
    chmod 755 "$STAGE"
    cp "$HELPER_BIN/xdp_capture" "$STAGE/"
    chmod 755 "$STAGE/xdp_capture"
    if [ "${PCAP_LIB##*.}" != "a" ]; then
        cp -a "$PCAP_LIBDIR"/libpcap.so* "$STAGE/" 2>/dev/null || true
        chmod 755 "$STAGE"/libpcap.so* 2>/dev/null || true
    fi
    setpriv --reuid 65534 --regid 65534 --clear-groups \
        env LD_LIBRARY_PATH="$STAGE" "$STAGE/xdp_capture" -A "xdp:$HOST_IF" \
        >"$TMP/p1.log" 2>&1
    RC=$?
    if [ "$RC" -eq 4 ] && grep -q 'status=-8' "$TMP/p1.log" &&
            grep -q 'CAP_' "$TMP/p1.log"; then
        result $T "no caps -> PERM_DENIED naming caps" PASS \
            "$(grep ACTIVATE_ERR "$TMP/p1.log")"
    elif [ "$RC" -eq 0 ]; then
        result $T "no caps -> PERM_DENIED naming caps" FAIL \
            "activated as uid 65534 with no caps"
    else
        result $T "no caps -> PERM_DENIED naming caps" FAIL \
            "want status=-8 + CAP_* in text, got: $(tail -n1 "$TMP/p1.log")"
    fi
else
    result $T "no caps -> PERM_DENIED naming caps" SKIP "setpriv missing"
fi

# --- shape 2: caps but RLIMIT_MEMLOCK 64k -----------------------------------
# CAP_IPC_LOCK must go too, or the kernel bypasses the memlock limit when
# accounting umem pages.
if require_tool capsh; then
    capsh --drop=cap_ipc_lock -- -c \
        "ulimit -l 64 && exec '$HELPER_BIN/xdp_capture' -A 'xdp:$HOST_IF'" \
        >"$TMP/p2.log" 2>&1
    RC=$?
    if [ "$RC" -eq 4 ] && grep -q 'status=-8' "$TMP/p2.log" &&
            grep -Eiq 'memlock|locked memory|RLIMIT' "$TMP/p2.log"; then
        result $T "memlock 64k -> PERM_DENIED with memlock hint" PASS \
            "$(grep ACTIVATE_ERR "$TMP/p2.log")"
    elif [ "$RC" -eq 0 ]; then
        result $T "memlock 64k -> PERM_DENIED with memlock hint" FAIL \
            "activated despite 64k RLIMIT_MEMLOCK (2MiB umem should not fit)"
    else
        result $T "memlock 64k -> PERM_DENIED with memlock hint" FAIL \
            "want status=-8 + memlock hint, got: $(tail -n1 "$TMP/p2.log")"
    fi
else
    result $T "memlock 64k -> PERM_DENIED with memlock hint" SKIP \
        "capsh missing"
fi

# --- shape 3: full caps -----------------------------------------------------
timeout 10 "$HELPER_BIN/xdp_capture" -A "xdp:$HOST_IF" >"$TMP/p3.log" 2>&1
RC=$?
if [ "$RC" -eq 0 ] && grep -q ACTIVATE_OK "$TMP/p3.log"; then
    result $T "full caps -> activate succeeds" PASS ""
else
    result $T "full caps -> activate succeeds" FAIL \
        "$(tail -n1 "$TMP/p3.log")"
fi

finish
