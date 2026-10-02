/* Probe: does libxdp_clean_references() reap a SIGKILL-orphaned dispatcher? */
#include <xdp/libxdp.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

int main(int argc, char **argv)
{
	if (argc < 2) { fprintf(stderr, "usage: %s IFNAME\n", argv[0]); return 2; }
	int ifindex = if_nametoindex(argv[1]);
	if (!ifindex) { perror("if_nametoindex"); return 2; }
	int r = libxdp_clean_references(ifindex);
	printf("libxdp_clean_references(%s=%d) = %d (%s)\n",
	    argv[1], ifindex, r, r ? strerror(-r) : "ok");
	return 0;
}
