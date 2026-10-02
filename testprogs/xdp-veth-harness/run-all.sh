#!/bin/bash
# run-all.sh - execute t00..t17 in order, emit a markdown results table,
# continue past failures.
#
# usage: BUILD_DIR=/path/to/xdp-enabled-libpcap-build ./run-all.sh
set -u
# shellcheck disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
guard
build_helpers

STAMP=$(date +%Y%m%d-%H%M)
RESULTS_FILE="$HARNESS_DIR/results-$STAMP.md"
HARNESS_LOG_ROOT="$HARNESS_DIR/logs-$STAMP"
mkdir -p "$HARNESS_LOG_ROOT"
export RESULTS_FILE BUILD_DIR HARNESS_LOG_ROOT
export PCAP_SRC

{
    echo "# AF_XDP libpcap veth falsifier results, $STAMP"
    echo
    echo "- BUILD_DIR: $BUILD_DIR"
    echo "- libpcap: $PCAP_LIB"
    echo "- testprogs: $TESTPROGS"
    echo "- ASan build: $PCAP_ASAN"
    echo "- kernel: $(uname -r)"
    echo "- date: $(date -Iseconds)"
    echo "- libxdp: $(pkg-config --modversion libxdp 2>/dev/null || echo unknown)"
    echo "- libbpf: $(pkg-config --modversion libbpf 2>/dev/null || echo unknown)"
    echo "- gcc: $(gcc --version 2>/dev/null | head -n1 || echo absent)"
    echo "- clang: $(clang --version 2>/dev/null | head -n1 || echo absent)"
    echo "- iproute2: $(ip -V 2>/dev/null || echo unknown)"
    echo "- ethtool: $(ethtool --version 2>/dev/null || echo unknown)"
    echo "- util-linux (setpriv): $(setpriv --version 2>/dev/null || echo absent)"
    echo "- xdp-tools (xdp-loader): $(xdp-loader --version 2>/dev/null | head -n1 || echo absent)"
    echo "- pcap-xdp.c md5: $(md5sum "$PCAP_SRC/pcap-xdp.c" 2>/dev/null | cut -d' ' -f1 || echo unknown)"
    echo "- raw logs: $HARNESS_LOG_ROOT"
    echo
    echo "| script | falsifier | verdict | note |"
    echo "|---|---|---|---|"
} >"$RESULTS_FILE"

OVERALL=0
for SCRIPT in "$HARNESS_DIR"/t[0-9][0-9]-*.sh; do
    echo "=== $(basename "$SCRIPT")"
    if ! bash "$SCRIPT"; then
        OVERALL=1
    fi
done

echo
echo "results table: $RESULTS_FILE"
{
    echo
    if [ "$OVERALL" -eq 0 ]; then
        echo "Overall: no FAIL recorded."
    else
        echo "Overall: at least one FAIL recorded."
    fi
} >>"$RESULTS_FILE"
exit "$OVERALL"
