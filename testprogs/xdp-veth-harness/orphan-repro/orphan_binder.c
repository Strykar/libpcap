/*
 * orphan_binder - minimal AF_XDP binder that mirrors the libpcap xdp:
 * module's libxdp call exactly (pcap-xdp.c: libxdp_flags 0, xdp_flags 0,
 * bind_flags XDP_COPY, single queue), so the SIGKILL-orphan-dispatcher
 * behavior can be reproduced without a built libpcap. It binds, primes the
 * fill ring, prints BOUND, then blocks so the driver can SIGKILL it.
 *
 * Standalone: links only libxdp + libbpf, no libpcap. The orphan/blackhole
 * is a libxdp property (the default-program dispatcher + XSKMAP), so this is
 * the right isolation level for the Toke note's Q1.
 *
 * usage: orphan_binder IFNAME [QUEUE]
 */
#include <xdp/xsk.h>
#include <linux/if_xdp.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>

#define NUM_FRAMES	4096
#define FRAME_SIZE	XSK_UMEM__DEFAULT_FRAME_SIZE	/* 4096 */
#define FILL_PRIME	XSK_RING_PROD__DEFAULT_NUM_DESCS	/* 2048 */

int main(int argc, char **argv)
{
	struct xsk_umem *umem = NULL;
	struct xsk_socket *xsk = NULL;
	struct xsk_ring_prod fill = {0}, tx = {0};
	struct xsk_ring_cons comp = {0}, rx = {0};
	struct xsk_socket_config scfg;
	void *area = NULL;
	__u64 area_sz = (__u64)NUM_FRAMES * FRAME_SIZE;
	__u32 idx = 0, queue = 0, i;
	const char *ifname;
	int ret;

	if (argc < 2) { fprintf(stderr, "usage: %s IFNAME [QUEUE]\n", argv[0]); return 2; }
	ifname = argv[1];
	if (argc > 2) queue = (__u32)strtoul(argv[2], NULL, 0);
	if (!if_nametoindex(ifname)) { perror("if_nametoindex"); return 2; }

	area = mmap(NULL, area_sz, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (area == MAP_FAILED) { perror("mmap"); return 2; }

	ret = xsk_umem__create(&umem, area, area_sz, &fill, &comp, NULL);
	if (ret) { fprintf(stderr, "xsk_umem__create: %s\n", strerror(-ret)); return 2; }

	/* Exactly the module's flags (pcap-xdp.c:852-855). */
	memset(&scfg, 0, sizeof(scfg));
	scfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	scfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	scfg.libxdp_flags = 0;
	scfg.xdp_flags = 0;
	scfg.bind_flags = XDP_COPY;

	ret = xsk_socket__create(&xsk, ifname, queue, umem, &rx, &tx, &scfg);
	if (ret) {
		/* Same EBUSY the module reports; the driver greps this. */
		fprintf(stderr, "xsk_socket__create(%s q%u) = %d (%s)\n",
		    ifname, queue, ret, strerror(-ret));
		return 3;
	}

	idx = 0;
	ret = xsk_ring_prod__reserve(&fill, FILL_PRIME, &idx);
	if (ret == FILL_PRIME) {
		for (i = 0; i < FILL_PRIME; i++)
			*xsk_ring_prod__fill_addr(&fill, idx + i) =
			    (__u64)i * FRAME_SIZE;
		xsk_ring_prod__submit(&fill, FILL_PRIME);
	}

	printf("BOUND pid=%d if=%s ifindex=%u queue=%u\n",
	    getpid(), ifname, if_nametoindex(ifname), queue);
	fflush(stdout);

	/* Block until SIGKILL. No cleanup: that is the point. */
	for (;;)
		pause();
	return 0;
}
