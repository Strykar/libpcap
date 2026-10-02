/*
 * xskmap_peek - loader for xskmap_peek.bpf.o.
 *
 * Reads one slot of an existing XSKMAP (the libxdp dispatcher's xsks_map)
 * by id, in-kernel, via BPF_PROG_TEST_RUN. Prints:
 *   XSKMAP id=<id> max_entries=<n> queue=<q> populated=<0|1>
 *
 * usage: xskmap_peek <map_id> [queue_idx]
 */
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

int main(int argc, char **argv)
{
	struct bpf_object *obj;
	struct bpf_map *xsks, *result;
	struct bpf_program *prog;
	struct bpf_map_info info = {0};
	__u32 ilen = sizeof(info);
	__u32 map_id, qidx = 0;
	int existing_fd, prog_fd, result_fd, err;
	int in_key = 0, out_key = 1;
	long qv, populated = -1;
	unsigned char pkt[64] = {0};

	if (argc < 2) { fprintf(stderr, "usage: %s MAP_ID [QUEUE]\n", argv[0]); return 2; }
	map_id = (__u32)strtoul(argv[1], NULL, 0);
	if (argc > 2) qidx = (__u32)strtoul(argv[2], NULL, 0);

	existing_fd = bpf_map_get_fd_by_id(map_id);
	if (existing_fd < 0) { fprintf(stderr, "get_fd_by_id(%u): %s\n", map_id, strerror(errno)); return 2; }
	if (bpf_map_get_info_by_fd(existing_fd, &info, &ilen)) {
		fprintf(stderr, "get_info_by_fd: %s\n", strerror(errno)); return 2;
	}
	if (info.type != BPF_MAP_TYPE_XSKMAP) {
		fprintf(stderr, "map %u is type %u, not XSKMAP\n", map_id, info.type); return 2;
	}

	obj = bpf_object__open_file("xskmap_peek.bpf.o", NULL);
	if (!obj || libbpf_get_error(obj)) { fprintf(stderr, "open bpf obj failed\n"); return 2; }

	xsks = bpf_object__find_map_by_name(obj, "xsks_map");
	result = bpf_object__find_map_by_name(obj, "result");
	if (!xsks || !result) { fprintf(stderr, "maps not found in obj\n"); return 2; }

	/* Match the real map so reuse_fd's strict compatibility check passes. */
	if (bpf_map__set_max_entries(xsks, info.max_entries)) {
		fprintf(stderr, "set_max_entries: %s\n", strerror(errno)); return 2;
	}
	if (bpf_map__reuse_fd(xsks, existing_fd)) {
		fprintf(stderr, "reuse_fd: %s\n", strerror(errno)); return 2;
	}

	err = bpf_object__load(obj);
	if (err) { fprintf(stderr, "load: %s\n", strerror(-err)); return 2; }

	result_fd = bpf_map__fd(result);
	qv = qidx;
	if (bpf_map_update_elem(result_fd, &in_key, &qv, BPF_ANY)) {
		fprintf(stderr, "seed queue idx: %s\n", strerror(errno)); return 2;
	}

	prog = bpf_object__find_program_by_name(obj, "peek");
	prog_fd = bpf_program__fd(prog);

	LIBBPF_OPTS(bpf_test_run_opts, topts,
	    .data_in = pkt, .data_size_in = sizeof(pkt), .repeat = 1);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	if (err) { fprintf(stderr, "test_run: %s\n", strerror(errno)); return 2; }

	if (bpf_map_lookup_elem(result_fd, &out_key, &populated)) {
		fprintf(stderr, "read result: %s\n", strerror(errno)); return 2;
	}

	printf("XSKMAP id=%u max_entries=%u queue=%u populated=%ld\n",
	    map_id, info.max_entries, qidx, populated);
	return 0;
}
