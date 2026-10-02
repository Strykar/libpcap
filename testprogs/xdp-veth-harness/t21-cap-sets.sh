#!/bin/bash
# t21-cap-sets.sh - capability floor, measured with exact bounding sets.
#
# Runs the module (xdp_capture -A, libxdp dispatcher) and a direct binder
# (nodisp_binder: own attach, XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD) under
# setpriv --bounding-set=SET with strace outside the drop, and classifies
# each run: OK, the first syscall that returned EPERM, or libxdp's netlink
# attach denial (which never surfaces as a syscall error).  The library
# and binaries are staged under /run so no DAC capability is needed to
# reach a 0750 home.  Rows with an expected outcome are asserted; the
# rest are recorded.
set -u
# shellcheck disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
guard
build_helpers
mk_tmp
T=t21
STAGE=""

# shellcheck disable=SC2329  # invoked via trap
cleanup() {
    case ${STAGE:-} in
    /run/pcxdp-stage.*) rm -rf "$STAGE" ;;
    esac
    cleanup_common
}
trap cleanup EXIT

for tool in setpriv strace; do
    if ! require_tool "$tool"; then
        result $T "capability sets" SKIP "$tool missing"
        exit 0
    fi
done

# shellcheck disable=SC2046  # pkg-config output is meant to split
cc -O1 -g -Wall -o "$HELPER_BIN/nodisp_binder" "$HELPER_DIR/direct/nodisp_binder.c" \
    $(pkg-config --cflags --libs libxdp libbpf 2>/dev/null || echo "-lxdp -lbpf") \
    || die "nodisp_binder compile failed"

STAGE=$(mktemp -d /run/pcxdp-stage.XXXXXX)
chmod 755 "$STAGE"
cp -L "$PCAP_LIBDIR/libpcap.so.1" "$STAGE/libpcap.so.1"
cp "$HELPER_BIN/xdp_capture" "$HELPER_BIN/nodisp_binder" "$STAGE/"
chmod 755 "$STAGE"/*

# classify OUT STRACE -> one line
classify() {
    local out=$1 st=$2 e
    if grep -qE 'ACTIVATE_OK|^BOUND' "$out"; then
        echo "OK"; return
    fi
    if grep -qE 'Error attaching XDP program|bpf_xdp_attach: Operation not permitted' "$out"; then
        echo "attach denied (netlink EPERM)"; return
    fi
    # BPF_TOKEN_CREATE is a libbpf probe that fails harmlessly on most hosts.
    e=$(grep -E '= -1 EPERM' "$st" | grep -v BPF_TOKEN_CREATE | head -n1 | sed -E 's/^[0-9]+ +//; s/, \{.*//; s/\).*//' | cut -c1-32)
    if grep -q 'Failed to load dispatcher' "$out"; then
        echo "dispatcher load denied; first EPERM ${e:-none}"; return
    fi
    if [ -n "$e" ]; then
        echo "first EPERM $e"
    else
        echo "no EPERM: $(grep -m1 -oE 'err=.*|nodisp_binder: .*' "$out" | cut -c1-50)"
    fi
}

# run NAME SET MODE(disp|direct) EXPECT(OK|FAIL|socket|any)
run() {
    local name=$1 set=$2 mode=$3 expect=$4 out st got verdict
    out=$TMP/out-$mode-$name.txt
    st=$TMP/st-$mode-$name.txt
    setup_rig
    if [ "$mode" = disp ]; then
        timeout 40 strace -f -o "$st" -e trace=socket,bind,setsockopt,bpf \
            setpriv --bounding-set="$set" -- \
            env LD_LIBRARY_PATH="$STAGE" "$STAGE/xdp_capture" -A "xdp:$HOST_IF" \
            >"$out" 2>&1
    else
        timeout 40 strace -f -o "$st" -e trace=socket,bind,setsockopt,bpf \
            setpriv --bounding-set="$set" -- \
            "$STAGE/nodisp_binder" "$HOST_IF" 0 >"$out" 2>&1
    fi
    teardown_rig
    got=$(classify "$out" "$st")
    verdict=PASS
    case $expect in
    OK)     [ "$got" = OK ] || verdict=FAIL ;;
    FAIL)   [ "$got" != OK ] || verdict=FAIL ;;
    socket) [[ $got == *"socket(AF_XDP"* ]] || verdict=FAIL ;;
    esac
    result $T "$mode {$name}" $verdict "$got"
}

# --- module, libxdp dispatcher -------------------------------------------
run none              -all                                      disp socket
run NET_ADMIN+BPF     -all,+net_admin,+bpf                      disp socket
run RAW               -all,+net_raw                             disp FAIL
run RAW+BPF           -all,+net_raw,+bpf                        disp FAIL
run RAW+NET_ADMIN     -all,+net_raw,+net_admin                  disp FAIL
run RAW+NET_ADMIN+BPF -all,+net_raw,+net_admin,+bpf             disp FAIL
run RAW+BPF+SYS_ADMIN -all,+net_raw,+bpf,+sys_admin             disp FAIL
run RAW+NET_ADMIN+SYS_ADMIN -all,+net_raw,+net_admin,+sys_admin disp OK
run RAW+NET_ADMIN+BPF+SYS_ADMIN -all,+net_raw,+net_admin,+bpf,+sys_admin disp OK
run all-but-NET_ADMIN -net_admin                                disp FAIL

# --- direct attach, no dispatcher ------------------------------------------
run none              -all                                      direct FAIL
run RAW+BPF           -all,+net_raw,+bpf                        direct FAIL
run RAW+NET_ADMIN     -all,+net_raw,+net_admin                  direct FAIL
run RAW+NET_ADMIN+BPF -all,+net_raw,+net_admin,+bpf             direct OK
run all-but-NET_ADMIN -net_admin                                direct FAIL

echo "kernel: $(uname -r)  libxdp: $(pkg-config --modversion libxdp 2>/dev/null)  libbpf: $(pkg-config --modversion libbpf 2>/dev/null)"
