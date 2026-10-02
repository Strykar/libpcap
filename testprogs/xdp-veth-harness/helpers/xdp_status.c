/*
 * xdp_status - t10 falsifier helper (matrix items 25 and 27).
 *
 * mode "rfmon": pcap_set_rfmon(1) then activate; the contract is
 * PCAP_ERROR_RFMON_NOTSUP (-6), not a silently ignored request.
 * mode "proto": pcap_set_protocol_linux(3) then activate; the contract
 * is a loud PCAP_ERROR refusal, not a silently ignored protocol.
 *
 * usage: xdp_status rfmon|proto device
 * stdout: SET_RC n, then ACTIVATE_ERR status=... / ACTIVATE_OK status=...
 * exit 0 always (the script judges the printed status), 2 on usage error.
 */

#include <pcap.h>
#include <stdio.h>
#include <string.h>

int
main(int argc, char **argv)
{
	pcap_t *pd;
	char errbuf[PCAP_ERRBUF_SIZE];
	int rc, status;

	if (argc != 3 ||
	    (strcmp(argv[1], "rfmon") != 0 && strcmp(argv[1], "proto") != 0)) {
		fprintf(stderr, "usage: xdp_status rfmon|proto device\n");
		return 2;
	}
	setvbuf(stdout, NULL, _IOLBF, 0);
	pd = pcap_create(argv[2], errbuf);
	if (pd == NULL) {
		printf("CREATE_ERR %s\n", errbuf);
		return 2;
	}
	pcap_set_snaplen(pd, 65535);
	pcap_set_timeout(pd, 200);
	if (strcmp(argv[1], "rfmon") == 0)
		rc = pcap_set_rfmon(pd, 1);
	else
		rc = pcap_set_protocol_linux(pd, 3);
	printf("SET_RC %d\n", rc);

	status = pcap_activate(pd);
	if (status < 0)
		printf("ACTIVATE_ERR status=%d str=%s err=%s\n", status,
		    pcap_statustostr(status), pcap_geterr(pd));
	else
		printf("ACTIVATE_OK status=%d\n", status);
	pcap_close(pd);
	return 0;
}
