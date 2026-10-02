#!/usr/bin/env bash
# t20 - live-owner EBUSY: does a SECOND bind on a queue a live XSK already
# owns return EBUSY? The design email lists this as one of two real EBUSY
# conflicts, but only the foreign-prog leg (t14) was ever tested.
set -u
HERE=$(cd "$(dirname "$0")" && pwd); cd "$HERE"
# shellcheck source=/dev/null
source ../common.sh
[ "$(id -u)" -eq 0 ] || { echo "must run as root"; exit 2; }
APID=0
cleanup() {
    [ "${APID:-0}" -gt 0 ] && kill -9 "$APID" 2>/dev/null
    ip link set dev "$HOST_IF" xdp off 2>/dev/null
    teardown_rig
    chown -R "${SUDO_UID:-0}:${SUDO_GID:-0}" "$HERE" 2>/dev/null
}
trap cleanup EXIT

setup_rig 1; sleep 0.3
: >"$HERE/.a.out"
./orphan_binder "$HOST_IF" 0 >"$HERE/.a.out" 2>&1 & APID=$!
for _ in $(seq 1 25); do grep -q BOUND "$HERE/.a.out" && break; sleep 0.1; done
grep -q BOUND "$HERE/.a.out" || { echo "A failed to bind:"; cat "$HERE/.a.out"; exit 1; }
echo "A (live owner, q0): $(grep BOUND "$HERE/.a.out")"

# B: a second bind on the SAME queue while A is still alive.
: >"$HERE/.b.out"
./orphan_binder "$HOST_IF" 0 >"$HERE/.b.out" 2>&1
RC=$?
echo "B (second bind, A still live): rc=$RC out=[$(tr -d '\n' <"$HERE/.b.out")]"
if grep -qiE 'busy|= -16' "$HERE/.b.out"; then
    echo "RESULT: live-owner second bind -> EBUSY (CONFIRMED as a real conflict)"
elif grep -q BOUND "$HERE/.b.out"; then
    echo "RESULT: live-owner second bind -> SUCCEEDED (claim FALSE; not an EBUSY source)"
else
    echo "RESULT: live-owner second bind -> OTHER errno (see out)"
fi
kill -0 "$APID" 2>/dev/null && echo "(A confirmed still alive during B)"
