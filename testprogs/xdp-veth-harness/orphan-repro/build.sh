#!/bin/sh
# Build the orphan-repro binaries next to their sources.
set -e
cd "$(dirname "$0")"
CFLAGS="-O1 -g -Wall $(pkg-config --cflags libxdp libbpf)"
LIBS="$(pkg-config --libs libxdp libbpf)"
cc $CFLAGS -o orphan_binder orphan_binder.c $LIBS
cc $CFLAGS -o reap_probe reap_probe.c $LIBS
cc $CFLAGS -o clean_ref_probe clean_ref_probe.c $LIBS
clang -O2 -g -target bpf -c xskmap_peek.bpf.c -o xskmap_peek.bpf.o
cc $CFLAGS -o xskmap_peek xskmap_peek.c $LIBS
