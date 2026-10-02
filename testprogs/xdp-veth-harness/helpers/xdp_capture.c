/*
 * xdp_capture - workhorse helper for the AF_XDP libpcap veth falsifiers.
 *
 * usage: xdp_capture [-A] [-k] [-n] [-N] [-p] [-S] [-1] [-c count]
 *                    [-D delay_ms] [-t timeout_ms] [-w wall_secs]
 *                    [-f filter] device
 *
 *   -A   activate only, then exit (privilege/refusal probes)
 *   -k   keep dispatching after a dispatch error: print DISPATCH_ERR
 *        and stay in the loop instead of exiting 5 (t11 observes what
 *        the handle does across and after a link event)
 *   -n   pcap_setnonblock(1) after activate
 *   -N   pcap_set_tstamp_precision(NANO) before activate; if refused,
 *        prints NANO_NOTSUP and exits 3 (matrix item 29 falsifier)
 *   -p   pcap_set_promisc(1)
 *   -S   SIGTERM calls pcap_breakloop: the loop prints DISPATCH_BREAK
 *        and falls through to STATS/DELIVERED/pcap_close, so a script
 *        can close a held handle cleanly at a chosen instant (t16
 *        restore-race probes the module's cleanup-time feature restore,
 *        which a raw kill skips). Opt-in: without -S, SIGTERM kills as
 *        before and timeout(1)'s rc 124 still means hang.
 *   -1   exactly one pcap_dispatch call; prints DISPATCH_RET/ELAPSED_MS
 *   -c   stop after count delivered packets (0 = unlimited)
 *   -D   sleep delay_ms after ACTIVATE_OK before the first dispatch
 *        (t11 phase d: lets the script queue descriptors and change
 *        link state before the loop ever runs)
 *   -t   pcap timeout_ms (default 200; 0 = block forever)
 *   -w   wall-clock budget in seconds, checked between dispatch calls
 *        (ineffective while blocked with -t 0; wrap in timeout(1) then)
 *
 * Machine-readable stdout lines: CREATE_ERR, NANO_NOTSUP, ACTIVATE_ERR,
 * ACTIVATE_WARN, ACTIVATE_OK, FILTER_ERR, NONBLOCK_ERR, PKT, DISPATCH_RET,
 * DISPATCH_ERR, DISPATCH_BREAK, STATS, DELIVERED.
 *
 * Exit codes: 0 ok, 2 usage/create/filter, 3 nano refused, 4 activate
 * failed, 5 dispatch error (not with -k: errors are reported and ridden
 * out to the count/wall bound, exit 0).
 */

#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static pcap_t *pd;
static long delivered;

static long
now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

static void
cb(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
	(void)user;
	(void)bytes;
	printf("PKT %ld %ld %u %u\n", (long)h->ts.tv_sec,
	    (long)h->ts.tv_usec, h->caplen, h->len);
	delivered++;
}

static void
on_term(int sig)
{
	(void)sig;
	if (pd != NULL)
		pcap_breakloop(pd);
}

static void
usage(void)
{
	fprintf(stderr, "usage: xdp_capture [-AknNpS1] [-c count] "
	    "[-D delay_ms] [-t timeout_ms] [-w wall_secs] [-f filter] "
	    "device\n");
}

int
main(int argc, char **argv)
{
	struct sigaction sa;
	struct pcap_stat ps;
	char errbuf[PCAP_ERRBUF_SIZE];
	const char *device, *filter = NULL;
	long count = 0, wall_secs = 0, delay_ms = 0, t0;
	int opt, status, n;
	int activate_only = 0, nonblock = 0, nano = 0, promisc = 0;
	int single = 0, keep_going = 0, term_break = 0, timeout_ms = 200;

	while ((opt = getopt(argc, argv, "Ac:D:f:knNpSt:w:1")) != -1) {
		switch (opt) {
		case 'A': activate_only = 1; break;
		case 'c': count = atol(optarg); break;
		case 'D': delay_ms = atol(optarg); break;
		case 'f': filter = optarg; break;
		case 'k': keep_going = 1; break;
		case 'n': nonblock = 1; break;
		case 'N': nano = 1; break;
		case 'p': promisc = 1; break;
		case 'S': term_break = 1; break;
		case 't': timeout_ms = atoi(optarg); break;
		case 'w': wall_secs = atol(optarg); break;
		case '1': single = 1; break;
		default: usage(); return 2;
		}
	}
	if (optind != argc - 1) {
		usage();
		return 2;
	}
	device = argv[optind];
	setvbuf(stdout, NULL, _IOLBF, 0);

	pd = pcap_create(device, errbuf);
	if (pd == NULL) {
		printf("CREATE_ERR %s\n", errbuf);
		return 2;
	}
	if (nano) {
		status = pcap_set_tstamp_precision(pd,
		    PCAP_TSTAMP_PRECISION_NANO);
		if (status != 0) {
			printf("NANO_NOTSUP status=%d str=%s\n", status,
			    pcap_statustostr(status));
			pcap_close(pd);
			return 3;
		}
	}
	pcap_set_snaplen(pd, 65535);
	pcap_set_timeout(pd, timeout_ms);
	if (promisc)
		pcap_set_promisc(pd, 1);

	status = pcap_activate(pd);
	if (status < 0) {
		printf("ACTIVATE_ERR status=%d str=%s err=%s\n", status,
		    pcap_statustostr(status), pcap_geterr(pd));
		pcap_close(pd);
		return 4;
	}
	if (status > 0)
		printf("ACTIVATE_WARN status=%d err=%s\n", status,
		    pcap_geterr(pd));
	printf("ACTIVATE_OK fd=%d\n", pcap_get_selectable_fd(pd));
	if (activate_only) {
		pcap_close(pd);
		return 0;
	}

	if (term_break) {
		/* No SA_RESTART: a blocked poll must see EINTR so the
		 * breakloop flag/eventfd takes effect promptly. */
		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = on_term;
		sigaction(SIGTERM, &sa, NULL);
	}

	if (filter != NULL) {
		struct bpf_program fp;

		if (pcap_compile(pd, &fp, filter, 1,
		    PCAP_NETMASK_UNKNOWN) < 0) {
			printf("FILTER_ERR %s\n", pcap_geterr(pd));
			return 2;
		}
		if (pcap_setfilter(pd, &fp) < 0) {
			printf("FILTER_ERR %s\n", pcap_geterr(pd));
			return 2;
		}
		pcap_freecode(&fp);
	}
	if (nonblock && pcap_setnonblock(pd, 1, errbuf) < 0) {
		printf("NONBLOCK_ERR %s\n", errbuf);
		return 2;
	}

	if (delay_ms > 0)
		usleep((useconds_t)delay_ms * 1000);

	t0 = now_ms();
	if (single) {
		long a = now_ms(), b;

		n = pcap_dispatch(pd, count > 0 ? (int)count : -1, cb, NULL);
		b = now_ms();
		printf("DISPATCH_RET %d ELAPSED_MS %ld\n", n, b - a);
		if (n < 0) {
			printf("DISPATCH_ERR status=%d str=%s err=%s\n", n,
			    pcap_statustostr(n),
			    n == PCAP_ERROR ? pcap_geterr(pd) : "");
			pcap_close(pd);
			return 5;
		}
	} else {
		for (;;) {
			int want = -1;

			if (count > 0) {
				long left = count - delivered;

				if (left <= 0)
					break;
				want = left > 1000000 ? 1000000 : (int)left;
			}
			n = pcap_dispatch(pd, want, cb, NULL);
			if (n == PCAP_ERROR_BREAK) {
				printf("DISPATCH_BREAK\n");
				break;
			}
			if (n < 0) {
				printf("DISPATCH_ERR status=%d str=%s "
				    "err=%s\n", n, pcap_statustostr(n),
				    n == PCAP_ERROR ? pcap_geterr(pd) : "");
				if (!keep_going) {
					pcap_close(pd);
					return 5;
				}
				usleep(50000);	/* error may repeat instantly */
			}
			if (count > 0 && delivered >= count)
				break;
			if (wall_secs > 0 &&
			    now_ms() - t0 >= wall_secs * 1000L)
				break;
			if (nonblock && n == 0)
				usleep(10000);	/* do not spin hot */
		}
	}

	if (pcap_stats(pd, &ps) == 0)
		printf("STATS recv=%u drop=%u ifdrop=%u\n", ps.ps_recv,
		    ps.ps_drop, ps.ps_ifdrop);
	else
		printf("STATS_ERR %s\n", pcap_geterr(pd));
	printf("DELIVERED %ld\n", delivered);
	pcap_close(pd);
	return 0;
}
