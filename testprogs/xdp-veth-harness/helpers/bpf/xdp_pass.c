/*
 * xdp_pass - minimal XDP program for the t14 pre-attached-prog falsifier
 * (matrix item 31). Attached directly via netlink (ip link ... xdpgeneric
 * obj), i.e. NOT through the libxdp dispatcher, so a subsequent
 * xsk_socket__create must fail with a conflict.
 *
 * Only compiled if no packaged XDP object (e.g. xdp-tools'
 * /usr/lib/bpf/xdpfilt_alw_all.o) is loadable:
 *   clang -O2 -target bpf -c xdp_pass.c -o xdp_pass.o
 *
 * No kernel headers needed: XDP_PASS == 2.
 */

__attribute__((section("xdp"), used))
int xdp_pass_all(void *ctx)
{
	(void)ctx;
	return 2;	/* XDP_PASS */
}

__attribute__((section("license"), used))
char _license[] = "GPL";
