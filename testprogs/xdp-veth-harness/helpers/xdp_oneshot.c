/*
 * xdp_oneshot - t06 falsifier helper (oneshot vs recycled umem frames,
 * matrix item 18).
 *
 * pcap_next returns a pointer that must survive ring recycling: the
 * module's oneshot callback must copy out of the umem frame, because the
 * frame goes back to the fill ring when the read batch ends and the
 * kernel rewrites it with the next inbound packet. Without the copy, the
 * pointer aliases a recycled frame and its bytes mutate under traffic.
 *
 * Protocol with the driving script:
 *   1. helper captures one packet via pcap_next, shadows its bytes,
 *      prints "GOT len=N" then "PUMP_NOW"
 *   2. script pumps > fill-ring-depth packets (default depth 256), then
 *      writes one line to the helper's stdin
 *   3. helper re-compares the returned pointer against the shadow:
 *      ONESHOT_STABLE (exit 0) or ONESHOT_MUTATED (exit 1)
 *
 * usage: xdp_oneshot device
 */

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static long
now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

int
main(int argc, char **argv)
{
	pcap_t *pd;
	struct pcap_pkthdr h;
	const u_char *pkt = NULL;
	u_char *shadow;
	char errbuf[PCAP_ERRBUF_SIZE], line[64];
	long t0;
	int status;
	unsigned int len;

	if (argc != 2) {
		fprintf(stderr, "usage: xdp_oneshot device\n");
		return 2;
	}
	setvbuf(stdout, NULL, _IOLBF, 0);
	pd = pcap_create(argv[1], errbuf);
	if (pd == NULL) {
		printf("CREATE_ERR %s\n", errbuf);
		return 2;
	}
	pcap_set_snaplen(pd, 65535);
	pcap_set_timeout(pd, 300);
	status = pcap_activate(pd);
	if (status < 0) {
		printf("ACTIVATE_ERR status=%d str=%s err=%s\n", status,
		    pcap_statustostr(status), pcap_geterr(pd));
		pcap_close(pd);
		return 4;
	}
	printf("ACTIVATE_OK\n");

	t0 = now_ms();
	while (now_ms() - t0 < 15000) {
		pkt = pcap_next(pd, &h);
		if (pkt != NULL)
			break;
	}
	if (pkt == NULL) {
		printf("NO_PACKET\n");
		pcap_close(pd);
		return 6;
	}
	len = h.caplen;
	shadow = malloc(len);
	if (shadow == NULL) {
		printf("OOM\n");
		return 2;
	}
	memcpy(shadow, pkt, len);
	printf("GOT len=%u\n", len);
	printf("PUMP_NOW\n");

	if (fgets(line, sizeof(line), stdin) == NULL) {
		printf("STDIN_EOF\n");
		return 6;
	}
	if (memcmp(shadow, pkt, len) == 0) {
		printf("ONESHOT_STABLE\n");
		pcap_close(pd);
		return 0;
	}
	printf("ONESHOT_MUTATED\n");
	pcap_close(pd);
	return 1;
}
