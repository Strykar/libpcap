/* Which libxdp call reaps a SIGKILL-orphaned dispatcher?
 * Tries clean_references, then xdp_multiprog__get_from_ifindex + detach. */
#include <xdp/libxdp.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
	if (argc < 2) { fprintf(stderr, "usage: %s IFNAME\n", argv[0]); return 2; }
	int ifindex = if_nametoindex(argv[1]);
	if (!ifindex) { perror("if_nametoindex"); return 2; }

	int r = libxdp_clean_references(ifindex);
	printf("clean_references = %d\n", r);

	struct xdp_multiprog *mp = xdp_multiprog__get_from_ifindex(ifindex);
	if (!mp || libxdp_get_error(mp)) {
		printf("get_from_ifindex: none found (err=%ld)\n",
		    mp ? libxdp_get_error(mp) : 0L);
		return 0;
	}
	printf("get_from_ifindex: found a multiprog, mode=%d\n",
	    xdp_multiprog__attach_mode(mp));
	r = xdp_multiprog__detach(mp);
	printf("xdp_multiprog__detach = %d (%s)\n", r, r ? strerror(-r) : "ok");
	xdp_multiprog__close(mp);
	return 0;
}
