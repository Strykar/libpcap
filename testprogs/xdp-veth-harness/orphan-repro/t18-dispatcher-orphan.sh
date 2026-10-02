#!/usr/bin/env bash
# t18 - SIGKILL-orphan dispatcher: directly measure the Toke-note Q1 claims.
#
# Uses a standalone libxdp binder (orphan_binder, no libpcap) that mirrors
# the module's bind flags, plus an in-kernel XSKMAP read (xskmap_peek), so
# the central "the XSKMAP entry does not clear, it blackholes" claim is
# OBSERVED, not inferred from the traffic drop. Run as root.
#
# Phases and what each decides:
#   A baseline ping, no XDP            -> stack reachable (control)
#   B bind libxdp xsk on q0            -> dispatcher attached, native?
#   C peek XSKMAP slot 0, LIVE         -> populated=1 (probe positive control)
#   D ping while live                  -> takeover loss (not the blackhole)
#   E SIGKILL the binder               -> dispatcher orphaned, process gone
#   F ping each second after kill      -> blackhole + how long it persists
#   G peek XSKMAP slot 0, ORPHAN       -> THE READ: persists(1) or clears(0)
#   H xdp redirect tracepoints         -> mechanism: still redirecting?
#   I clean_ref_probe                  -> is it a no-op? ping still dropped?
#   J reap_probe (multiprog__detach)   -> reaps dispatcher? stack resumes?
#   K rebind attempts after detach     -> EBUSY for how long (queue residue)?
#   L ip link xdp off + teardown
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
cd "$HERE"
# shellcheck source=/dev/null
source ../common.sh

STAMP=$(date +%Y%m%d-%H%M%S)
LOG="$HERE/run-$STAMP.log"
RES="$HERE/results-$STAMP.md"
: >"$LOG"; : >"$RES"

say()  { echo "$*" | tee -a "$LOG"; }
run()  { echo "+ $*" >>"$LOG"; "$@" >>"$LOG" 2>&1; }
note() { printf '| %s | %s | %s |\n' "$1" "$2" "$3" >>"$RES"; }

ping_n() { # ping_n <count> -> "<recv>/<count>"
    local c=$1 out rec
    out=$(ip netns exec "$NS" ping -c "$c" -i 0.2 -W 1 -q "$HOST_IP" 2>/dev/null)
    echo "$out" >>"$LOG"
    rec=$(echo "$out" | sed -n 's/.*, \([0-9]\+\) received.*/\1/p')
    echo "${rec:-0}/$c"
}
find_xskmap() { bpftool map show 2>/dev/null | awk -F: '/xskmap/{print $1}' | tail -1 | tr -d ' '; }
xdp_line() { ip -d link show "$HOST_IF" 2>/dev/null | tr '\n' ' ' | grep -oE 'prog/xdp[a-z]* id [0-9]+' | head -1; }
TRACE=/sys/kernel/tracing
[ -d "$TRACE/events/xdp" ] || TRACE=/sys/kernel/debug/tracing

[ "$(id -u)" -eq 0 ] || { echo "must run as root"; exit 2; }

printf '# t18 dispatcher-orphan direct measurement %s\n\n' "$STAMP" >>"$RES"
printf '| phase | observation | verdict vs Q1 claim |\n|--|--|--|\n' >>"$RES"

BPID=0
cleanup() {
    [ "${BPID:-0}" -gt 0 ] && kill -9 "$BPID" 2>/dev/null
    echo 0 >"$TRACE/events/xdp/enable" 2>/dev/null
    ip link set dev "$HOST_IF" xdp off 2>/dev/null
    teardown_rig
    chown -R "${SUDO_UID:-0}:${SUDO_GID:-0}" "$HERE" 2>/dev/null
}
trap cleanup EXIT

say "== setup: fresh veth, peer 1 txq (all inbound -> host rxq0) =="
setup_rig 1
sleep 0.3

# ---- A ----
A=$(ping_n 4)
say "A baseline (no XDP): ping $A"
note A "ping $A (no XDP)" "$([ "${A%%/*}" -gt 0 ] && echo 'control OK: stack reachable' || echo 'CONTROL FAIL')"

# ---- B ----
say "== B: bind libxdp xsk on $HOST_IF q0 =="
: >"$HERE/.binder.out"
./orphan_binder "$HOST_IF" 0 >"$HERE/.binder.out" 2>&1 &
BPID=$!
for _ in $(seq 1 25); do grep -q BOUND "$HERE/.binder.out" && break; sleep 0.1; done
cat "$HERE/.binder.out" >>"$LOG"
if ! grep -q BOUND "$HERE/.binder.out"; then
    say "B FAILED to bind:"; cat "$HERE/.binder.out" | tee -a "$LOG"
    note B "orphan_binder failed to bind" "ABORT"; exit 1
fi
XL=$(xdp_line); MAPID=$(find_xskmap)
say "B bound pid=$BPID; $XL; xskmap id=$MAPID"
note B "attached: $XL; xskmap id=$MAPID" "$(echo "$XL" | grep -q 'prog/xdp ' && echo 'NATIVE confirmed' || echo "mode=$XL")"

# ---- C ---- positive control for the probe
PC=$(./xskmap_peek "$MAPID" 0 2>>"$LOG"); say "C peek LIVE: $PC"
note C "$PC" "$(echo "$PC" | grep -q 'populated=1' && echo 'probe works: live slot reads populated' || echo 'PROBE SUSPECT')"

# ---- D ----
D=$(ping_n 4); say "D ping while live capture: $D (takeover loss expected, not the blackhole)"
note D "ping $D while live" "takeover (expected loss)"

# ---- E ----
say "== E: SIGKILL the binder =="
kill -9 "$BPID" 2>/dev/null; wait "$BPID" 2>/dev/null; BPID=0
sleep 0.3
GONE=$(ps -o pid= -p "${BPID:-0}" 2>/dev/null | wc -l)
XL2=$(xdp_line)
say "E process gone; dispatcher now: $XL2"
note E "binder killed; dispatcher still: $XL2" "$([ -n "$XL2" ] && echo 'dispatcher orphaned (still attached)' || echo 'dispatcher gone on its own')"

# ---- F ---- blackhole timing
say "== F: ping once per second after kill =="
declare -a FR
firstok=""
for t in $(seq 1 8); do
    r=$(ping_n 1)
    FR[$t]=$r
    say "  t=${t}s ping $r"
    [ -z "$firstok" ] && [ "${r%%/*}" -gt 0 ] && firstok=$t
    sleep 0.6
done
if [ -z "$firstok" ]; then
    note F "ping 0/1 every second through t=8s: ${FR[*]}" "BLACKHOLE persists >=8s (claim: >=5s) -> HOLDS"
else
    note F "first reply at t=${firstok}s: ${FR[*]}" "recovered on its own at ${firstok}s"
fi

# ---- G ---- the key in-kernel read
PG=$(./xskmap_peek "$MAPID" 0 2>>"$LOG"); say "G peek ORPHAN: $PG"
if echo "$PG" | grep -q 'populated=1'; then
    note G "$PG" "ENTRY PERSISTS after SIGKILL -> blackhole claim CONFIRMED by map read"
elif echo "$PG" | grep -q 'populated=0'; then
    note G "$PG" "ENTRY CLEARED -> email's 'does not clear' is FALSIFIED; blackhole (if any) has another cause"
else
    note G "$PG" "peek failed/ambiguous (see log)"
fi

# ---- H ---- redirect tracepoints (mechanism)
say "== H: xdp redirect tracepoints during a post-kill ping =="
if [ -w "$TRACE/events/xdp/enable" ]; then
    echo > "$TRACE/trace"; echo 1 > "$TRACE/events/xdp/enable"
    ping_n 4 >/dev/null
    sleep 0.2; echo 0 > "$TRACE/events/xdp/enable"
    rmap=$(grep -c 'xdp_redirect_map[: ]' "$TRACE/trace" 2>/dev/null); rmap=${rmap:-0}
    rmaperr=$(grep -c 'xdp_redirect_map_err' "$TRACE/trace" 2>/dev/null); rmaperr=${rmaperr:-0}
    rerr=$(grep -c 'xdp_redirect_err' "$TRACE/trace" 2>/dev/null); rerr=${rerr:-0}
    rexc=$(grep -c 'xdp_exception' "$TRACE/trace" 2>/dev/null); rexc=${rexc:-0}
    cp "$TRACE/trace" "$HERE/trace-H-$STAMP.txt" 2>/dev/null
    say "H redirect_map=$rmap redirect_map_err=$rmaperr redirect_err=$rerr exception=$rexc"
    if [ "$rmap" -gt 0 ] || [ "$rmaperr" -gt 0 ]; then hv='still redirecting into XSKMAP -> not XDP_PASS'; else hv='no redirects (would mean XDP_PASS)'; fi
    note H "redirect_map=$rmap map_err=$rmaperr err=$rerr exc=$rexc" "$hv"
else
    say "H tracefs not writable, skipped"; note H "tracefs unavailable" "SKIP"
fi

# ---- I ---- clean_references no-op?
say "== I: clean_ref_probe =="
CI=$(./clean_ref_probe "$HOST_IF" 2>>"$LOG"); say "I $CI"
AI=$(ping_n 2); say "I ping after clean_references: $AI"
note I "$CI ; ping $AI" "$(echo "$CI" | grep -qE '= 0' && [ "${AI%%/*}" -eq 0 ] && echo 'no-op confirmed (returns 0, still blackholed)' || echo 'see log')"

# ---- J ---- reap via multiprog__detach
say "== J: reap_probe (xdp_multiprog__detach) =="
CJ=$(./reap_probe "$HOST_IF" 2>>"$LOG"); say "J"; echo "$CJ" | tee -a "$LOG"
sleep 0.3
AJ=$(ping_n 4); say "J ping after detach: $AJ"
XL3=$(xdp_line)
note J "detach output captured; dispatcher now:'${XL3:-none}'; ping $AJ" "$([ "${AJ%%/*}" -gt 0 ] && echo 'detach reaps dispatcher, stack RESUMES' || echo 'still dropped after detach')"

# ---- K ---- rebind EBUSY duration after detach
say "== K: time-to-rebind after detach =="
kstart=$(date +%s.%N); ksucc=""
for i in $(seq 1 24); do
    : >"$HERE/.try.out"
    ./orphan_binder "$HOST_IF" 0 >"$HERE/.try.out" 2>&1 &
    TP=$!
    sleep 0.3
    if grep -q BOUND "$HERE/.try.out"; then
        kel=$(echo "$(date +%s.%N) - $kstart" | bc 2>/dev/null)
        ksucc=$kel; kill -9 "$TP" 2>/dev/null; wait "$TP" 2>/dev/null; break
    fi
    wait "$TP" 2>/dev/null   # failure path: binder already exited
    grep -q 'create' "$HERE/.try.out" && echo "  try $i: $(cat "$HERE/.try.out")" >>"$LOG"
    sleep 0.2
done
if [ -n "$ksucc" ]; then
    say "K rebind succeeded after ~${ksucc}s"
    note K "rebind succeeded ~${ksucc}s after detach" "$(awk -v x="$ksucc" 'BEGIN{exit !(x>1)}' && echo 'queue-ownership residue EBUSYs for seconds -> HOLDS' || echo 'rebound quickly (<1s)')"
else
    say "K never rebound within ~12s"
    note K "no successful rebind within ~12s" "residue outlasts window"
fi

# ---- L ----
say "== L: ip link xdp off + teardown =="
ip link set dev "$HOST_IF" xdp off 2>>"$LOG" || true
say "DONE. results=$RES log=$LOG"
