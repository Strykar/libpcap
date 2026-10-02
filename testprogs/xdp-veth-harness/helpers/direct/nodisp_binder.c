/*
 * nodisp_binder - bind an AF_XDP socket on IFNAME queue QID without
 * libxdp's dispatcher: load libxdp's default redirect program directly,
 * attach it with bpf_xdp_attach(), create the socket with
 * XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD and insert it in the map.  Prints
 * BOUND on success.  Used by t21 to measure the no-dispatcher floor.
 *
 * usage: nodisp_binder IFNAME QID [PROG_OBJ]
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/mman.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/xsk.h>

#define NFRAMES	64
#define FRAME	XSK_UMEM__DEFAULT_FRAME_SIZE

static void die(const char *what, int err)
{
	fprintf(stderr, "nodisp_binder: %s: %s\n", what, strerror(err));
	exit(1);
}

int main(int argc, char **argv)
{
	const char *obj = "/usr/lib/bpf/xsk_def_xdp_prog.o";
	struct xsk_socket_config scfg;
	struct xsk_ring_prod fill;
	struct xsk_ring_cons comp, rx;
	struct bpf_object *bo;
	struct bpf_program *prog;
	struct bpf_map *map;
	struct xsk_umem *umem;
	struct xsk_socket *xsk;
	void *area;
	unsigned int ifindex;
	int qid, prog_fd, map_fd, r;

	if (argc < 3) {
		fprintf(stderr, "usage: nodisp_binder IFNAME QID [PROG_OBJ]\n");
		return 2;
	}
	qid = atoi(argv[2]);
	if (argc > 3)
		obj = argv[3];
	ifindex = if_nametoindex(argv[1]);
	if (ifindex == 0)
		die("if_nametoindex", errno);

	bo = bpf_object__open_file(obj, NULL);
	if (bo == NULL)
		die("open prog object", errno);
	r = bpf_object__load(bo);
	if (r != 0)
		die("load prog object", -r);
	prog = bpf_object__next_program(bo, NULL);
	if (prog == NULL)
		die("no program in object", ENOENT);
	prog_fd = bpf_program__fd(prog);
	map = bpf_object__find_map_by_name(bo, "xsks_map");
	if (map == NULL)
		die("xsks_map not found", ENOENT);
	map_fd = bpf_map__fd(map);

	r = bpf_xdp_attach((int)ifindex, prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST,
	    NULL);
	if (r != 0)
		die("bpf_xdp_attach", -r);

	area = mmap(NULL, NFRAMES * FRAME, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (area == MAP_FAILED)
		die("mmap", errno);
	r = xsk_umem__create(&umem, area, NFRAMES * FRAME, &fill, &comp, NULL);
	if (r != 0)
		die("xsk_umem__create", -r);

	memset(&scfg, 0, sizeof(scfg));
	scfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	scfg.tx_size = 0;
	scfg.libxdp_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD;
	scfg.xdp_flags = 0;
	scfg.bind_flags = XDP_COPY;
	r = xsk_socket__create(&xsk, argv[1], (unsigned int)qid, umem, &rx,
	    NULL, &scfg);
	if (r != 0)
		die("xsk_socket__create", -r);
	r = xsk_socket__update_xskmap(xsk, map_fd);
	if (r != 0)
		die("xsk_socket__update_xskmap", -r);

	printf("BOUND ifindex=%u queue=%d\n", ifindex, qid);
	fflush(stdout);

	xsk_socket__delete(xsk);
	xsk_umem__delete(umem);
	bpf_xdp_detach((int)ifindex, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
	bpf_object__close(bo);
	return 0;
}
