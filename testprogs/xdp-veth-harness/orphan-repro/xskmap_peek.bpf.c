/*
 * xskmap_peek.bpf.c - in-kernel read of an XSKMAP slot.
 *
 * Userspace bpf_map_lookup_elem on an XSKMAP returns -EOPNOTSUPP (this is
 * why `bpftool map dump` cannot show the value), so the only way to learn
 * whether a slot still points at a socket is an in-kernel lookup. This XDP
 * program does exactly that on a queue index passed in via the result map,
 * and writes back 1 if the slot is populated, 0 if empty. Run via
 * BPF_PROG_TEST_RUN against the existing dispatcher's xsks_map (reused by
 * fd in the loader) - it never attaches to the device, it just reads.
 *
 * XDP context is where XSKMAP lookup is unconditionally allowed, so this
 * avoids any verifier question about lookup from other program types.
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 1);		/* loader resizes to match the real map */
	__type(key, int);
	__type(value, int);
} xsks_map SEC(".maps");

/* result[0]=queue index in (loader sets it); out[0]=1 populated / 0 empty. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, int);
	__type(value, long);
} result SEC(".maps");

SEC("xdp")
int peek(struct xdp_md *ctx)
{
	int in_key = 0, out_key = 1;
	long qidx = 0, populated;
	long *q, *o;
	void *slot;

	(void)ctx;
	q = bpf_map_lookup_elem(&result, &in_key);
	if (q)
		qidx = *q;

	/* XSKMAP keys are int. */
	int key = (int)qidx;
	slot = bpf_map_lookup_elem(&xsks_map, &key);
	populated = slot ? 1 : 0;

	o = bpf_map_lookup_elem(&result, &out_key);
	if (o)
		*o = populated;
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
