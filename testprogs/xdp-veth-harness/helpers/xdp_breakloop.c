/*
 * xdp_breakloop - t04 falsifier helper.
 *
 * Blocks in pcap_dispatch (timeout 0 = forever, idle interface) while a
 * second thread sleeps 1 s and calls pcap_breakloop. The dispatch must
 * return PCAP_ERROR_BREAK promptly (eventfd-in-poll-set contract, matrix
 * item 13). threadsignaltest exists in-tree but sleeps a fixed 60 s
 * before breaking, which is unsuitable for a harness leg.
 *
 * usage: xdp_breakloop device
 * stdout: ACTIVATE_ERR / BREAK_OK elapsed_ms=N / BREAK_BAD ...
 * exit: 0 broke promptly, 1 wrong status or too slow, 4 activate failed.
 * The caller wraps this in timeout(1) to convert a hang into exit 124.
 */

#include <pcap.h>
#include <pthread.h>
#include <stdio.h>
#include <time.h>

static pcap_t *pd;

static long
now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

static void *
breaker(void *arg)
{
	struct timespec ts = { 1, 0 };

	(void)arg;
	nanosleep(&ts, NULL);
	pcap_breakloop(pd);
	return NULL;
}

static void
cb(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
	(void)user;
	(void)h;
	(void)bytes;
}

int
main(int argc, char **argv)
{
	pthread_t tid;
	char errbuf[PCAP_ERRBUF_SIZE];
	long t0, elapsed;
	int status, n;

	if (argc != 2) {
		fprintf(stderr, "usage: xdp_breakloop device\n");
		return 2;
	}
	setvbuf(stdout, NULL, _IOLBF, 0);
	pd = pcap_create(argv[1], errbuf);
	if (pd == NULL) {
		printf("CREATE_ERR %s\n", errbuf);
		return 2;
	}
	pcap_set_snaplen(pd, 65535);
	pcap_set_timeout(pd, 0);	/* block forever */
	status = pcap_activate(pd);
	if (status < 0) {
		printf("ACTIVATE_ERR status=%d str=%s err=%s\n", status,
		    pcap_statustostr(status), pcap_geterr(pd));
		pcap_close(pd);
		return 4;
	}
	printf("ACTIVATE_OK\n");

	if (pthread_create(&tid, NULL, breaker, NULL) != 0) {
		printf("THREAD_ERR\n");
		return 2;
	}
	t0 = now_ms();
	n = pcap_dispatch(pd, -1, cb, NULL);
	elapsed = now_ms() - t0;
	pthread_join(tid, NULL);
	if (n == PCAP_ERROR_BREAK && elapsed < 8000) {
		printf("BREAK_OK elapsed_ms=%ld\n", elapsed);
		pcap_close(pd);
		return 0;
	}
	printf("BREAK_BAD status=%d str=%s elapsed_ms=%ld\n", n,
	    pcap_statustostr(n), elapsed);
	pcap_close(pd);
	return 1;
}
