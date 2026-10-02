#!/usr/bin/env bash
# t19 - the gap t18 left: does a fresh bind succeed WHILE the stray
# dispatcher is still attached (no xdp_multiprog__detach first)? t18's
# phase K detached before rebinding, so it could not tell whether the
# crash-orphan is a real third EBUSY source. This settles it.
set -u
HERE=$(cd "$(dirname "$0")" && pwd); cd "$HERE"
# shellcheck source=/dev/null
source ../common.sh
[ "$(id -u)" -eq 0 ] || { echo "must run as root"; exit 2; }
BPID=0
cleanup() {
    [ "${BPID:-0}" -gt 0 ] && kill -9 "$BPID" 2>/dev/null
    ip link set dev "$HOST_IF" xdp off 2>/dev/null
    teardown_rig
    chown -R "${SUDO_UID:-0}:${SUDO_GID:-0}" "$HERE" 2>/dev/null
}
trap cleanup EXIT

xdp_line() { ip -d link show "$HOST_IF" 2>/dev/null | tr '\n' ' ' | grep -oE 'prog/xdp[a-z]* id [0-9]+' | head -1; }

setup_rig 1; sleep 0.3
echo "== bind A, then SIGKILL, then rebind WITHOUT detaching =="
: >"$HERE/.a.out"
./orphan_binder "$HOST_IF" 0 >"$HERE/.a.out" 2>&1 & BPID=$!
for _ in $(seq 1 25); do grep -q BOUND "$HERE/.a.out" && break; sleep 0.1; done
grep -q BOUND "$HERE/.a.out" || { echo "A failed to bind:"; cat "$HERE/.a.out"; exit 1; }
echo "A: $(cat "$HERE/.a.out"); dispatcher=$(xdp_line)"

kill -9 "$BPID" 2>/dev/null; wait "$BPID" 2>/dev/null; BPID=0
sleep 0.05   # minimal settle; we WANT to catch any transient residue
echo "after SIGKILL: dispatcher still=$(xdp_line)"

# Rebind attempts, NO detach in between. Record first outcome + time.
start=$(date +%s.%N); first=""; n=0
for i in $(seq 1 30); do
    n=$i
    : >"$HERE/.b.out"
    ./orphan_binder "$HOST_IF" 0 >"$HERE/.b.out" 2>&1 & TP=$!
    sleep 0.2
    if grep -q BOUND "$HERE/.b.out"; then
        first="BOUND@$(echo "$(date +%s.%N) - $start" | bc)s (attempt $i)"
        kill -9 "$TP" 2>/dev/null; wait "$TP" 2>/dev/null
        break
    fi
    wait "$TP" 2>/dev/null
    out=$(tr -d '\n' <"$HERE/.b.out")
    echo "  attempt $i (stray dispatcher attached, no detach): $out"
    [ -z "$first" ] && first="$out"
done
echo
echo "RESULT: naive rebind (no detach) first outcome after $n attempts: $first"
echo "dispatcher after: $(xdp_line)"
ip link set dev "$HOST_IF" xdp off 2>/dev/null || true
