#!/bin/bash
# t17-dispatcher-netraw.sh - settle the verify-in-script claims from external
# review: where is the module's rx-vlan-offload PCAP_WARNING path live, and
# how small can the capability set get? Activate clears rx-vlan-offload via
# ETHTOOL_SFEATURES (CAP_NET_ADMIN-gated). When the same process also
# performs the XDP attach, missing NET_ADMIN fails the attach first
# (PERM_DENIED) and the warning is unreachable. But with a libxdp
# dispatcher ALREADY attached and its bpffs pins readable, the bind path is
# xsk socket creation (CAP_NET_RAW) plus an XSKMAP update through a map fd
# libxdp must first acquire - and the acquisition route decides the minimal
# set: BPF_MAP_GET_FD_BY_ID is CAP_SYS_ADMIN-gated, bpf_obj_get on the pins
# is file access plus CAP_BPF.
#
# Phase 2 drops ONLY cap_net_admin (uid 0 and everything else retained,
# including CAP_SYS_ADMIN). It settles whether the warning path is live at
# all:
#
#   A: activate returns PCAP_WARNING naming rx-vlan-offload, capture
#      delivers packets, and offload reads on at activation AND after the
#      capture -> the warning path is live without NET_ADMIN (the claim
#      item 22 needs; NOT yet the minimal-set claim).
#   B: activate fails PERM_DENIED at the BIND site (errbuf says "binding
#      to") -> xsk bind is NET_ADMIN-gated, the warning path is dead code
#      everywhere, and the original privilege-floor claim was right as
#      written. PASS: the job is settling the claim, not forcing A.
#
# Phase 2b reruns at the minimal set {cap_net_raw,cap_bpf}, uid 0 kept so
# bpffs pin file permissions stay out of the picture; uid 0 is also
# mechanically load-bearing, since the bounding-set regrant on exec
# happens only for root (a nonroot variant needs ambient-cap plumbing,
# out of v1 scope). Its outcome writes the man-page-grade sentence. 2b
# passing means the pinned-path route suffices; 2b failing PERM_DENIED
# makes the by-id (SYS_ADMIN) route the HYPOTHESIS, which a conditional
# phase 2c at {net_raw,bpf,sys_admin} converts into a measurement by
# isolation: 2c-A confirms the by-id route and earns the floor sentence,
# 2c-B means an unmodeled gate and the floor sentence is withheld. The
# isolation is clean both ways because bpf_capable() treats SYS_ADMIN as
# a superset of BPF, so adding it back can only grant. 2b is skipped
# when phase 2 lands outcome B (a fortiori) or when no tool can express
# the minimal set.
# Both dropped runs are wrapped in prlimit --memlock=unlimited, applied
# outside the drop, so RLIMIT_MEMLOCK asymmetry (phase 2 retains
# CAP_IPC_LOCK, 2b does not) cannot burn the run at the umem stage; the
# man-page floor stays "subject to RLIMIT_MEMLOCK" regardless.
#
# Anything else (hang, unexpected error class, EPERM from a non-bind
# stage) is a FAIL with detail.
#
# Phase 1 (root) plants the residue: a brief root capture, then TERM; the
# libxdp dispatcher + default prog stay attached after close and
# rx-vlan-offload must read on again (the warning needs a set feature to
# fail clearing). Phase 3 (root, in the exit trap) unloads the residual
# dispatcher (removing its pin dir as a last resort), restores the offload
# baseline recorded at entry, and tears down.
set -u
# shellcheck disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
guard
build_helpers
mk_tmp
T=t17
PID1=""
PID2=""
PIN=""
RXVLAN_BASELINE=""

# shellcheck disable=SC2329  # invoked via trap
cleanup() {
    local p
    for p in "$PID1" "$PID2"; do
        if [ -n "$p" ]; then
            kill -TERM "$p" 2>/dev/null || true
            wait "$p" 2>/dev/null || true
        fi
    done
    # Phase 3: the dispatcher residue outlives every handle; unload it so
    # its bpffs pins do not leak past the rig (ifindexes get reused).
    if require_tool xdp-loader; then
        xdp-loader unload "$HOST_IF" --all >/dev/null 2>&1 || true
    fi
    ip link set dev "$HOST_IF" xdp off 2>/dev/null || true
    ip link set dev "$HOST_IF" xdpgeneric off 2>/dev/null || true
    # A bpf_link-attached dispatcher survives ip-link detach when
    # xdp-loader is absent; rig deletion kills the attachment but the
    # dead pin dir would linger. xdp-loader unload above removes the
    # pins, so this only sweeps the now-empty dir: rmdir, never rm -rf
    # on a discovered path. If something still holds it, leave it (the
    # pin dir is ifindex-namespaced, so a stale one is harmless clutter,
    # not a correctness problem) rather than force a recursive remove.
    if [ -n "$PIN" ] && [ -d "$PIN" ]; then
        rmdir "$PIN" 2>/dev/null || true
    fi
    # Restore the recorded baseline, not an assumed "on": stays correct
    # even if HOST_IF ever stops being rig-owned veth.
    case $RXVLAN_BASELINE in
    on|off)
        ethtool -K "$HOST_IF" rxvlan "$RXVLAN_BASELINE" \
            >/dev/null 2>&1 || true
        ;;
    esac
    cleanup_common
}
trap cleanup EXIT

setup_rig

rxvlan_state() {
    ethtool -k "$HOST_IF" 2>/dev/null | sed -n 's/^rx-vlan-offload: *//p'
}
RXVLAN_BASELINE=$(rxvlan_state)

# Privilege-drop tooling. Phase 2 needs "drop one cap"; phase 2b needs
# "keep exactly two", which setpriv expresses directly and capsh needs a
# computed drop list for. Name dialects differ: capsh (libcap) takes
# cap_-prefixed names, setpriv (libcap-ng) takes prefix-less ones
# (net_admin, bpf) - verified empirically, the wrong dialect fails at
# parse with "unknown capability".
HAVE_CAPSH=0
HAVE_SETPRIV=0
MIN_TOOL=""
require_tool capsh && HAVE_CAPSH=1
require_tool setpriv && HAVE_SETPRIV=1
if [ "$HAVE_CAPSH" = 0 ] && [ "$HAVE_SETPRIV" = 0 ]; then
    result $T "dispatcher residue + no-NET_ADMIN bind" SKIP \
        "neither capsh nor setpriv available"
    finish
fi

# Memlock parity: CAP_IPC_LOCK bypasses umem accounting and is retained
# in phase 2 but dropped in 2b/2c; raise the limit outside the drop so a
# small default cannot fail the umem stage (the limit is inherited
# across exec, no CAP_SYS_RESOURCE needed after). Default env, a no-op
# exec wrapper, so the array is never empty: bash < 4.4 rejects empty
# "${a[@]}" under set -u and the harness travels with the branch.
PRELIM=(env)
if require_tool prlimit; then
    PRELIM=(prlimit --memlock=unlimited:unlimited)
fi

# --- baseline: rx-vlan-offload on (t16 precedent) ----------------------------
STATE=$RXVLAN_BASELINE
case $STATE in
*fixed*)
    result $T "dispatcher residue + no-NET_ADMIN bind" SKIP \
        "veth pins rx-vlan-offload ($STATE); the clear cannot fail informatively"
    finish
    ;;
off)
    ethtool -K "$HOST_IF" rxvlan on >/dev/null 2>&1 || true
    STATE=$(rxvlan_state)
    ;;
esac
if [ "$STATE" != on ]; then
    result $T "dispatcher residue + no-NET_ADMIN bind" SKIP \
        "cannot establish rx-vlan-offload=on baseline (state: ${STATE:-absent})"
    finish
fi

# --- phase 1 (root): plant the dispatcher residue ----------------------------
timeout 30 "$HELPER_BIN/xdp_capture" -S -t 250 -c 0 -w 20 "xdp:$HOST_IF" \
    >"$TMP/p1.log" 2>&1 &
PID1=$!
if ! wait_for_line "$TMP/p1.log" ACTIVATE_OK 5; then
    wait "$PID1" 2>/dev/null || true
    PID1=""
    result $T "root capture leaves dispatcher residue" FAIL \
        "root activate failed: $(tail -n1 "$TMP/p1.log")"
    finish
fi
kill -TERM "$PID1"
wait "$PID1" 2>/dev/null || true
PID1=""

# Native and generic attach report differently in ip link output.
XDP_ID=$(ip link show dev "$HOST_IF" 2>/dev/null \
    | sed -n 's|.*prog/xdp\(generic\)\{0,1\} id \([0-9][0-9]*\).*|\2|p' \
    | head -n1)
if [ -z "$XDP_ID" ]; then
    if ip link show dev "$HOST_IF" | grep -q xdp; then
        XDP_ID=unknown
    else
        result $T "root capture leaves dispatcher residue" SKIP \
            "no XDP prog on $HOST_IF after close; no residue to bind through"
        finish
    fi
fi
IFINDEX=$(cat "/sys/class/net/$HOST_IF/ifindex")
PIN=$(find /sys/fs/bpf -maxdepth 4 -name "dispatch-${IFINDEX}-*" \
    2>/dev/null | head -n1)
result $T "root capture leaves dispatcher residue" PASS \
    "prog id $XDP_ID; pins: ${PIN:-not discoverable under /sys/fs/bpf}"

# Precondition: the closed handle's cleanup restore put the feature back
# on. If it did not (that state machine is t16's falsifier, not this
# one's), re-establish by hand so the dropped-cap clear has something to
# do.
STATE=$(rxvlan_state)
if [ "$STATE" != on ]; then
    ethtool -K "$HOST_IF" rxvlan on >/dev/null 2>&1 || true
    STATE=$(rxvlan_state)
fi
if [ "$STATE" != on ]; then
    result $T "dispatcher residue + no-NET_ADMIN bind" SKIP \
        "rx-vlan-offload reads '$STATE' after close and manual re-enable; warning has nothing to fail at"
    finish
fi

# Launch the helper under a reduced capability set. $1 = log file,
# $2 = mode: noadmin (drop only cap_net_admin) or minimal (bounding set
# reduced to cap_net_raw,cap_bpf). uid 0 kept in both, deliberately.
run_dropped() {
    local log=$1 mode=$2
    case $mode in
    noadmin)
        if [ "$HAVE_CAPSH" = 1 ]; then
            timeout 40 "${PRELIM[@]}" capsh --drop=cap_net_admin -- -c \
                "exec '$HELPER_BIN/xdp_capture' -S -t 250 -c 5 -w 12 'xdp:$HOST_IF'" \
                >"$log" 2>&1 &
        else
            timeout 40 "${PRELIM[@]}" setpriv --bounding-set -net_admin \
                "$HELPER_BIN/xdp_capture" -S -t 250 -c 5 -w 12 \
                "xdp:$HOST_IF" >"$log" 2>&1 &
        fi
        ;;
    minimal)
        if [ "$MIN_TOOL" = setpriv ]; then
            timeout 40 "${PRELIM[@]}" setpriv \
                --bounding-set -all,+net_raw,+bpf \
                "$HELPER_BIN/xdp_capture" -S -t 250 -c 5 -w 12 \
                "xdp:$HOST_IF" >"$log" 2>&1 &
        else
            local drop
            drop=$(capsh --print | sed -n 's/^Bounding set =//p' \
                | tr -d ' ' | tr ',' '\n' \
                | grep -v -e '^cap_net_raw$' -e '^cap_bpf$' \
                | paste -sd, -)
            timeout 40 "${PRELIM[@]}" capsh --drop="$drop" -- -c \
                "exec '$HELPER_BIN/xdp_capture' -S -t 250 -c 5 -w 12 'xdp:$HOST_IF'" \
                >"$log" 2>&1 &
        fi
        ;;
    minplus)
        if [ "$MIN_TOOL" = setpriv ]; then
            timeout 40 "${PRELIM[@]}" setpriv \
                --bounding-set -all,+net_raw,+bpf,+sys_admin \
                "$HELPER_BIN/xdp_capture" -S -t 250 -c 5 -w 12 \
                "xdp:$HOST_IF" >"$log" 2>&1 &
        else
            local drop
            drop=$(capsh --print | sed -n 's/^Bounding set =//p' \
                | tr -d ' ' | tr ',' '\n' \
                | grep -v -e '^cap_net_raw$' -e '^cap_bpf$' \
                    -e '^cap_sys_admin$' \
                | paste -sd, -)
            timeout 40 "${PRELIM[@]}" capsh --drop="$drop" -- -c \
                "exec '$HELPER_BIN/xdp_capture' -S -t 250 -c 5 -w 12 'xdp:$HOST_IF'" \
                >"$log" 2>&1 &
        fi
        ;;
    esac
    PID2=$!
}

# Re-establish the feature so a dropped-cap clear has something to do;
# the floor verdict does not depend on it, but the warning side of a
# phase is deterministic only when the bit is verifiably on again.
reestablish_rxvlan() {
    local phase=$1 s
    ethtool -K "$HOST_IF" rxvlan on >/dev/null 2>&1 || true
    s=$(rxvlan_state)
    if [ "$s" != on ]; then
        result $T "$phase: rxvlan precondition" SKIP \
            "rx-vlan-offload reads '$s' after re-enable; floor verdict unaffected, warning side unexercised"
    fi
}

# Classify one dropped-cap run. $1 = log, $2 = label prefix.
# Sets OUTCOME to A, B, or FAIL (FAIL rows are emitted here).
classify_run() {
    local log=$1 label=$2 errline
    OUTCOME=FAIL
    if ! wait_for_line "$log" ACTIVATE_ 10; then
        kill -TERM "$PID2" 2>/dev/null || true
        wait "$PID2" 2>/dev/null || true
        PID2=""
        result $T "$label: activate" FAIL \
            "no activate status within 10s (last: $(tail -n1 "$log"))"
        return
    fi
    if grep -q ACTIVATE_ERR "$log"; then
        wait "$PID2" 2>/dev/null || true
        PID2=""
        errline=$(grep ACTIVATE_ERR "$log" | head -n1)
        # Pin the failure to the bind site: the umem arm says "cannot
        # register", the bind arm says "binding to". An EPERM from
        # another stage must not masquerade as outcome B.
        if echo "$errline" | grep -q 'status=-8' && \
           echo "$errline" | grep -q 'binding to'; then
            OUTCOME=B
        elif echo "$errline" | grep -q 'status=-8'; then
            result $T "$label: activate" FAIL \
                "PERM_DENIED from a non-bind stage: $errline"
        else
            result $T "$label: activate" FAIL \
                "unexpected error class (want bind-site status=-8 or a warning): $errline"
        fi
        return
    fi
    OUTCOME=A
}

# --- phase 2: uid 0, only CAP_NET_ADMIN dropped ------------------------------
# Phase 1's capture exited; settle the async queue-0 release before
# phase 2 binds. settle_queue, NOT reset_xdp: the planted dispatcher is
# the whole point of this test and must survive.
settle_queue
run_dropped "$TMP/p2.log" noadmin
classify_run "$TMP/p2.log" "noadmin"
case $OUTCOME in
B)
    # NOTE: probed post-run, the denial is at libxdp's dispatcher
    # load/attach (BPF_PROG_LOAD freplace + BPF_LINK_CREATE), NOT the
    # kernel's xsk bind (which needs only NET_RAW). Clean close removes
    # the dispatcher, so phase 2 reloads from scratch; the floor measured
    # here is NET_RAW+NET_ADMIN+BPF. See ESTIMATE.md item 22 / note (f).
    result $T "noadmin -> PERM_DENIED on dispatcher reload, warn path dead" PASS \
        "OUTCOME B: $(grep ACTIVATE_ERR "$TMP/p2.log" | head -n1); 2b moot (no rideable dispatcher; clean close removed it)"
    finish
    ;;
FAIL)
    finish
    ;;
esac

# OUTCOME A territory. Read the feature state while the handle is live,
# again after the capture completes; the "stays on" label is earned only
# by both reads (the second also catches a hypothetical close-path
# restore firing despite rxvlan_restore=0).
STATE_LIVE=$(rxvlan_state)
WARNLINE=$(grep ACTIVATE_WARN "$TMP/p2.log" | head -n1)
if [ -n "$WARNLINE" ] && echo "$WARNLINE" | grep -Eiq 'rx.?vlan'; then
    result $T "noadmin activate -> PCAP_WARNING names rxvlan" PASS \
        "$WARNLINE"
elif [ -n "$WARNLINE" ]; then
    result $T "noadmin activate -> PCAP_WARNING names rxvlan" FAIL \
        "warning text does not name rx-vlan-offload: $WARNLINE"
else
    # Free fail-open detector: the feature-probe silent-skip path lands
    # exactly here (no warning, offload still on).
    result $T "noadmin activate -> PCAP_WARNING names rxvlan" FAIL \
        "activate returned 0 with no warning under dropped NET_ADMIN (offload reads '$STATE_LIVE')"
fi

gen_ping 30
wait_for_line "$TMP/p2.log" '^DELIVERED' 12 || true
kill -TERM "$PID2" 2>/dev/null || true
wait "$PID2" 2>/dev/null || true
PID2=""
STATE_POST=$(rxvlan_state)
DELIV=$(sed -n 's/^DELIVERED //p' "$TMP/p2.log" | head -n1)
if [ -n "$DELIV" ] && [ "$DELIV" -gt 0 ] 2>/dev/null; then
    result $T "noadmin capture via dispatcher delivers pkts" PASS \
        "DELIVERED $DELIV (warning path LIVE without NET_ADMIN)"
else
    result $T "noadmin capture via dispatcher delivers pkts" FAIL \
        "no packets delivered (DELIVERED ${DELIV:-absent}): $(tail -n1 "$TMP/p2.log")"
fi

if [ "$STATE_LIVE" = on ] && [ "$STATE_POST" = on ]; then
    result $T "rx-vlan-offload stays on through warned capture" PASS \
        "live=$STATE_LIVE post=$STATE_POST"
else
    result $T "rx-vlan-offload stays on through warned capture" FAIL \
        "live='$STATE_LIVE' post='$STATE_POST', want on/on (clear or close-restore acted without NET_ADMIN?)"
fi

# --- phase 2b: minimal set {cap_net_raw,cap_bpf} -----------------------------
# Writes the man-page-grade sentence: 2b passing means the pinned-path
# route (file access + CAP_BPF) suffices; 2b failing PERM_DENIED at the
# bind site hands attribution to the 2c isolation control below rather
# than inferring the by-id route from the denial alone.
if [ "$HAVE_SETPRIV" = 1 ] && \
   setpriv --bounding-set -all,+net_raw,+bpf true 2>/dev/null; then
    MIN_TOOL=setpriv
elif [ "$HAVE_CAPSH" = 1 ]; then
    # Fall through to capsh's computed drop list instead of skipping:
    # setpriv being unable to express the set (pre-5.8 kernel, old
    # util-linux) does not mean the set is inexpressible.
    MIN_TOOL=capsh
fi
if [ -z "$MIN_TOOL" ]; then
    result $T "minimal-set {NET_RAW,BPF} bind" SKIP \
        "no tool can express the minimal set (setpriv cannot parse bpf, capsh absent)"
    finish
fi
reestablish_rxvlan "minimal-set"
run_dropped "$TMP/p2b.log" minimal
classify_run "$TMP/p2b.log" "minimal-set"
case $OUTCOME in
B)
    result $T "minimal-set {NET_RAW,BPF} bind -> PERM_DENIED at bind" PASS \
        "B at the minimal set while noadmin passed: $(grep ACTIVATE_ERR "$TMP/p2b.log" | head -n1); attributing the gate via 2c"
    # --- phase 2c: isolation control {net_raw,bpf,sys_admin} ----------
    # 2b-B attributes the denial across a ~35-capability differential;
    # only SYS_ADMIN survives the script's own engineering (uid 0 owner
    # access covers the DAC pair, PRELIM covers IPC_LOCK, PERFMON has no
    # xsk role), but that is a model, not a measurement. Restore exactly
    # SYS_ADMIN: A confirms the by-id route by isolation and earns the
    # floor sentence, B means an unmodeled gate and the floor sentence
    # is withheld.
    reestablish_rxvlan "minplus"
    run_dropped "$TMP/p2c.log" minplus
    classify_run "$TMP/p2c.log" "minplus"
    case $OUTCOME in
    A)
        gen_ping 30
        wait_for_line "$TMP/p2c.log" '^DELIVERED' 12 || true
        kill -TERM "$PID2" 2>/dev/null || true
        wait "$PID2" 2>/dev/null || true
        PID2=""
        DELIV=$(sed -n 's/^DELIVERED //p' "$TMP/p2c.log" | head -n1)
        # Free second warning-liveness datum: SYS_ADMIN does not satisfy
        # ethtool's ns_capable(CAP_NET_ADMIN) gate, so the clear should
        # still fail and the warning still fire under minplus.
        if grep -q ACTIVATE_WARN "$TMP/p2c.log"; then
            WARN2C=yes
        else
            WARN2C=no
        fi
        if [ -n "$DELIV" ] && [ "$DELIV" -gt 0 ] 2>/dev/null; then
            result $T "minplus {NET_RAW,BPF,SYS_ADMIN} bind" PASS \
                "DELIVERED $DELIV with SYS_ADMIN restored: by-id (SYS_ADMIN) fd route confirmed by isolation; dispatcher-riding floor is NET_RAW+BPF+SYS_ADMIN, subject to RLIMIT_MEMLOCK (the self-attach floor, NET_RAW+NET_ADMIN+BPF, is unaffected); warning fired under minplus: $WARN2C"
        else
            result $T "minplus {NET_RAW,BPF,SYS_ADMIN} bind" FAIL \
                "activated but no packets (DELIVERED ${DELIV:-absent}): $(tail -n1 "$TMP/p2c.log")"
        fi
        ;;
    B)
        result $T "minplus {NET_RAW,BPF,SYS_ADMIN} bind" FAIL \
            "PERM_DENIED persists with SYS_ADMIN restored: unmodeled gate, floor sentence withheld; investigate before any doc text"
        ;;
    esac
    ;;
A)
    gen_ping 30
    wait_for_line "$TMP/p2b.log" '^DELIVERED' 12 || true
    kill -TERM "$PID2" 2>/dev/null || true
    wait "$PID2" 2>/dev/null || true
    PID2=""
    DELIV=$(sed -n 's/^DELIVERED //p' "$TMP/p2b.log" | head -n1)
    if [ -n "$DELIV" ] && [ "$DELIV" -gt 0 ] 2>/dev/null; then
        result $T "minimal-set {NET_RAW,BPF} bind" PASS \
            "DELIVERED $DELIV: pinned-path fd route confirmed; man-page floor is NET_RAW+BPF given a pre-attached dispatcher with accessible pins, subject to RLIMIT_MEMLOCK"
    else
        result $T "minimal-set {NET_RAW,BPF} bind" FAIL \
            "activated but no packets (DELIVERED ${DELIV:-absent}): $(tail -n1 "$TMP/p2b.log")"
    fi
    ;;
esac

finish
