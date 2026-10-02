# shellcheck shell=bash
# common.sh - shared rig for the AF_XDP libpcap veth falsifier harness.
#
# Sourced by every tNN script and run-all.sh. Provides:
#   guard            refuse unless root, BUILD_DIR is an XDP-enabled libpcap
#                    build (nm for pcap_xdp_* symbols), ip/ethtool/nm present
#   build_helpers    compile helpers/*.c against BUILD_DIR on first use
#   setup_rig [txq]  netns + veth pair; host side HOST_IF has numrxqueues 4;
#                    the ns peer defaults to 1 TX queue, which pins every
#                    ns-originated packet to host RX queue 0 (veth picks the
#                    peer RX queue from the sender TX queue), where the
#                    module binds; t02 passes 4 to spread flows across queues
#   teardown_rig
#   gen_ping / pump_burst / gen_udp_flow / gen_udp_flows   traffic from the ns
#   result <script> <falsifier> <PASS|FAIL|SKIP> <note>
#   finish           exit 1 if any FAIL was recorded by this script

[ -n "${BASH_VERSION:-}" ] || { echo "bash required" >&2; exit 2; }
set -u

HARNESS_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
HELPER_DIR="$HARNESS_DIR/helpers"
HELPER_BIN="$HARNESS_DIR/helpers/bin"

NS=pcxdp
HOST_IF=veth0
PEER_IF=veth1
HOST_IP=10.231.77.1
PEER_IP=10.231.77.2

RESULTS_FILE=${RESULTS_FILE:-}
HARNESS_FAILED=0
TMP=""

die() { echo "FATAL: $*" >&2; exit 2; }

result() {
    # result <script> <falsifier> <PASS|FAIL|SKIP> <note>
    local script=$1 falsifier=$2 verdict=$3 note=$4
    note=${note//$'\n'/ }
    note=${note//|/;}
    printf '%-22s %-46s %-4s %s\n' "$script" "$falsifier" "$verdict" "$note"
    if [ -n "$RESULTS_FILE" ]; then
        printf '| %s | %s | %s | %s |\n' \
            "$script" "$falsifier" "$verdict" "$note" >>"$RESULTS_FILE"
    fi
    if [ "$verdict" = FAIL ]; then
        HARNESS_FAILED=1
    fi
    return 0
}

finish() { exit "$HARNESS_FAILED"; }

require_tool() { command -v "$1" >/dev/null 2>&1; }

guard() {
    [ "$(id -u)" -eq 0 ] || die "must run as root (netns, veth, XDP attach)"
    [ -n "${BUILD_DIR:-}" ] || \
        die "BUILD_DIR must point at a libpcap build with XDP enabled"
    [ -d "$BUILD_DIR" ] || die "BUILD_DIR '$BUILD_DIR' is not a directory"
    local tool
    for tool in ip ethtool nm; do
        require_tool "$tool" || die "required tool missing: $tool"
    done

    # Locate the built library.
    PCAP_LIB=""
    local d f
    for d in "$BUILD_DIR" "$BUILD_DIR/run" "$BUILD_DIR/.libs"; do
        for f in "$d"/libpcap.so "$d"/libpcap.so.* "$d"/libpcap.a; do
            if [ -e "$f" ]; then
                PCAP_LIB=$f
                break 2
            fi
        done
    done
    [ -n "$PCAP_LIB" ] || \
        die "no libpcap.so/libpcap.a under BUILD_DIR '$BUILD_DIR'"
    PCAP_LIBDIR=$(dirname "$PCAP_LIB")

    # The XDP module must actually be in this build.
    if ! { nm -D --defined-only "$PCAP_LIB" 2>/dev/null;
           nm --defined-only "$PCAP_LIB" 2>/dev/null; } \
            | grep -q 'pcap_xdp_'; then
        strings "$PCAP_LIB" 2>/dev/null | grep -q 'AF_XDP socket' || \
            die "no pcap_xdp_* symbols in $PCAP_LIB: not an XDP-enabled build"
    fi

    # Built testprogs (CMake: BUILD_DIR/run, autotools: BUILD_DIR/testprogs).
    TESTPROGS=""
    for d in "$BUILD_DIR/run" "$BUILD_DIR/testprogs"; do
        if [ -x "$d/capturetest" ]; then
            TESTPROGS=$d
            break
        fi
    done
    [ -n "$TESTPROGS" ] || \
        die "no built testprogs under BUILD_DIR (build the 'testprogs' target)"

    # libpcap source tree, for the public headers the helpers compile against.
    if [ -z "${PCAP_SRC:-}" ]; then
        if [ -f "$BUILD_DIR/CMakeCache.txt" ]; then
            PCAP_SRC=$(sed -n 's/^pcap_SOURCE_DIR:STATIC=//p' \
                "$BUILD_DIR/CMakeCache.txt" | head -n 1)
            [ -n "$PCAP_SRC" ] || \
                PCAP_SRC=$(sed -n 's/^CMAKE_HOME_DIRECTORY:INTERNAL=//p' \
                    "$BUILD_DIR/CMakeCache.txt" | head -n 1)
        elif [ -f "$BUILD_DIR/Makefile" ]; then
            PCAP_SRC=$(sed -n 's/^srcdir *= *//p' "$BUILD_DIR/Makefile" \
                | head -n 1)
            # In-tree autotools builds emit a relative srcdir (often .);
            # resolve it against BUILD_DIR, not the harness CWD.
            case $PCAP_SRC in
            ""|/*) ;;
            *) PCAP_SRC="$BUILD_DIR/$PCAP_SRC" ;;
            esac
        fi
        [ -n "${PCAP_SRC:-}" ] || PCAP_SRC="$HARNESS_DIR/../../libpcap"
    fi
    PCAP_SRC=$(cd "$PCAP_SRC" 2>/dev/null && pwd) || \
        die "cannot resolve libpcap source dir (set PCAP_SRC)"
    [ -f "$PCAP_SRC/pcap.h" ] || \
        die "no pcap.h in '$PCAP_SRC' (set PCAP_SRC to the libpcap source)"

    # ASan-instrumented build? (t06 runs its ASan leg only if so)
    PCAP_ASAN=0
    if { nm -D "$PCAP_LIB" 2>/dev/null; nm "$PCAP_LIB" 2>/dev/null; } \
            | grep -q '__asan_init'; then
        PCAP_ASAN=1
    fi

    export PCAP_LIB PCAP_LIBDIR PCAP_SRC PCAP_ASAN TESTPROGS
}

build_helpers() {
    mkdir -p "$HELPER_BIN"
    local cc=${CC:-cc} extra="" asanflag="" src out

    # The helper's RUNPATH resolves the SONAME (libpcap.so.1), not the
    # versioned filename. An in-tree autotools build can leave only
    # libpcap.so.1.x.x in the build dir; without the SONAME symlink the
    # dynamic linker silently falls back to the system libpcap, which has
    # no xdp: module, and every xdp:IFNAME activate returns
    # NO_SUCH_DEVICE. Ensure the symlink in our (writable) PCAP_LIBDIR.
    if [ "${PCAP_LIB##*.}" != "a" ]; then
        local soname
        soname=$(objdump -p "$PCAP_LIB" 2>/dev/null \
            | sed -n 's/^ *SONAME *//p' | head -n1)
        if [ -n "$soname" ] && \
           [ "$soname" != "$(basename "$PCAP_LIB")" ] && \
           [ ! -e "$PCAP_LIBDIR/$soname" ]; then
            ln -sf "$(basename "$PCAP_LIB")" "$PCAP_LIBDIR/$soname" || \
                die "cannot create SONAME symlink in $PCAP_LIBDIR"
        fi
    fi
    if [ "${PCAP_LIB##*.}" = "a" ]; then
        # Static archive: pull in its own dependencies.
        extra=$(pkg-config --libs libxdp libbpf 2>/dev/null) || \
            extra="-lxdp -lbpf"
    fi
    if [ "$PCAP_ASAN" = 1 ]; then
        asanflag="-fsanitize=address"
    fi
    for src in "$HELPER_DIR"/*.c; do
        out="$HELPER_BIN/$(basename "$src" .c)"
        # Also rebuild when the library is newer: a helper linked against an
        # earlier build carries that build's RUNPATH, and once that dir is
        # gone the loader falls back to the system libpcap (no xdp: module),
        # so every activate fails NO_SUCH_DEVICE while the testprogs pass.
        if [ ! -x "$out" ] || [ "$src" -nt "$out" ] || \
           [ "$PCAP_LIB" -nt "$out" ]; then
            # shellcheck disable=SC2086
            "$cc" -O1 -g -Wall $asanflag -I"$PCAP_SRC" -o "$out" "$src" \
                "$PCAP_LIB" -Wl,-rpath,"$PCAP_LIBDIR" -lpthread $extra || \
                die "helper compile failed: $src"
        fi
    done
}

setup_rig() {
    # setup_rig [peer_txq]   peer_txq=1 (default) pins all inbound traffic
    # to host RX queue 0; peer_txq=4 spreads flows across host RX queues.
    local peer_txq=${1:-1}
    teardown_rig
    ip netns add "$NS" || die "ip netns add $NS failed"
    ip link add "$HOST_IF" numrxqueues 4 numtxqueues 4 type veth \
        peer name "$PEER_IF" numrxqueues 4 numtxqueues "$peer_txq" \
        netns "$NS" || die "veth creation failed"
    sysctl -qw "net.ipv6.conf.$HOST_IF.disable_ipv6=1" 2>/dev/null || true
    ip netns exec "$NS" sysctl -qw \
        "net.ipv6.conf.$PEER_IF.disable_ipv6=1" 2>/dev/null || true
    # XDP-on-veth hygiene: super-MTU offload skbs cannot traverse XDP.
    ethtool -K "$HOST_IF" tso off gso off gro off >/dev/null 2>&1 || true
    ip netns exec "$NS" ethtool -K "$PEER_IF" tso off gso off gro off \
        >/dev/null 2>&1 || true
    ip addr add "$HOST_IP/24" dev "$HOST_IF"
    ip link set "$HOST_IF" up
    ip -n "$NS" addr add "$PEER_IP/24" dev "$PEER_IF"
    ip -n "$NS" link set "$PEER_IF" up
    ip -n "$NS" link set lo up
    # Static neighbors both ways: an active XDP capture consumes ARP
    # replies (takeover), so dynamic resolution would deadlock the tests.
    local host_mac peer_mac
    host_mac=$(cat "/sys/class/net/$HOST_IF/address")
    peer_mac=$(ip netns exec "$NS" cat "/sys/class/net/$PEER_IF/address")
    ip neigh replace "$PEER_IP" lladdr "$peer_mac" dev "$HOST_IF" \
        nud permanent
    ip netns exec "$NS" ip neigh replace "$HOST_IP" lladdr "$host_mac" \
        dev "$PEER_IF" nud permanent
}

teardown_rig() {
    ip link del "$HOST_IF" 2>/dev/null || true
    ip netns del "$NS" 2>/dev/null || true
}

reset_xdp() {
    # Detach any residual XDP/dispatcher from the rig interface without
    # rebuilding it. A testprog that exits without pcap_close
    # (reactivatetest's expected-error path) or is hard-killed leaves the
    # libxdp dispatcher attached, and the next bind on the same queue
    # returns EBUSY. This is the documented item-8 residue, not a
    # per-test failure; tier-0 clears it between binding sub-tests so the
    # gate measures each testprog, not the leftovers of the last one.
    if require_tool xdp-loader; then
        xdp-loader unload "$HOST_IF" --all >/dev/null 2>&1 || true
    fi
    ip link set dev "$HOST_IF" xdpgeneric off 2>/dev/null || true
    ip link set dev "$HOST_IF" xdp off 2>/dev/null || true
    settle_queue
}

settle_queue() {
    # Wait out the async XSK queue release. A clean pcap_close detaches
    # the prog synchronously (prog reads as gone immediately), but the
    # kernel's queue-0 release after the socket fd closes is deferred
    # (RCU), so a back-to-back rebind races it and returns EBUSY. There
    # is no clean observable for queue ownership; a short fixed settle is
    # the pragmatic close (empirically a sub-ms delay sufficed; 200 ms is
    # margin for a loaded box). Split out from reset_xdp so a phase that
    # must PRESERVE a deliberately-planted dispatcher (t17) can wait for
    # the queue without detaching the prog.
    sleep 0.2
}

gen_ping() {
    # gen_ping [count] [interval]  ICMP echos from the ns toward HOST_IF.
    # Replies never come back while an XDP capture holds the queue, so
    # ping reporting 100% loss is expected; hence the unconditional true.
    local count=${1:-10} interval=${2:-0.05}
    ip netns exec "$NS" ping -c "$count" -i "$interval" -W 1 -q "$HOST_IP" \
        >/dev/null 2>&1 || true
}

pump_burst() {
    # Flood pings: enough inbound frames to cycle every fill-ring slot
    # (default umem is 512 frames, fill depth 256).
    local count=${1:-500}
    ip netns exec "$NS" ping -f -c "$count" -W 2 -q "$HOST_IP" \
        >/dev/null 2>&1 || true
}

gen_udp_flow() {
    # gen_udp_flow <count> <sport> <dport>  one datagram per socat run,
    # fixed 4-tuple, so the whole flow hashes to one veth queue.
    local count=$1 sport=$2 dport=$3 i
    for ((i = 0; i < count; i++)); do
        printf 'pcxdp-%d' "$i" | ip netns exec "$NS" socat -u - \
            "UDP4-DATAGRAM:$HOST_IP:$dport,bind=$PEER_IP:$sport" \
            2>/dev/null || true
    done
}

gen_udp_flows() {
    # gen_udp_flows <nflows> <per_flow> <dport> [sport_base]
    local nflows=$1 per_flow=$2 dport=$3 base=${4:-7200} f
    for ((f = 0; f < nflows; f++)); do
        gen_udp_flow "$per_flow" $((base + f)) "$dport"
    done
}

wait_for_line() {
    # wait_for_line <file> <regex> <timeout_s>
    local file=$1 regex=$2 deadline=$((SECONDS + $3))
    while [ "$SECONDS" -lt "$deadline" ]; do
        if grep -q "$regex" "$file" 2>/dev/null; then
            return 0
        fi
        sleep 0.2
    done
    return 1
}

mk_tmp() {
    # Under run-all, HARNESS_LOG_ROOT persists raw per-test logs beside
    # the results table (FAIL triage needs errbuf text the table lacks);
    # standalone runs keep the throwaway /tmp default.
    if [ -n "${HARNESS_LOG_ROOT:-}" ]; then
        mkdir -p "$HARNESS_LOG_ROOT"
        TMP=$(mktemp -d \
            "$HARNESS_LOG_ROOT/$(basename "$0" .sh).XXXXXX")
    else
        TMP=$(mktemp -d /tmp/pcxdp.XXXXXX)
    fi
}

cleanup_common() {
    teardown_rig
    if [ -n "$TMP" ] && [ -z "${HARNESS_LOG_ROOT:-}" ]; then
        rm -rf "$TMP"
    fi
}
