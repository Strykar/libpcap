/*
 * Copyright (c) 2026 Avinash Duduskar. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS''AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * AF_XDP capture: "xdp:IFNAME" or "xdp:IFNAME:QID".
 *
 * One AF_XDP socket on one RX queue, through libxdp's default redirect
 * program.  Redirect consumes the frame, so the bound queue is diverted
 * from the host stack for the life of the capture; the prefix keeps that
 * opt-in.  Copy mode, RX only, the filter runs in userspace, timestamps
 * are taken at dequeue.
 */

#include <config.h>

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <linux/ethtool.h>
#include <linux/if_packet.h>
#include <linux/if_xdp.h>
#include <linux/sockios.h>

/*
 * xdp/xsk.h pulls in bpf/libbpf.h and with it linux/bpf.h, whose struct
 * bpf_insn clashes with pcap/bpf.h.  Nothing xsk.h declares needs a
 * libbpf type, so pre-define libbpf.h's guard to keep it out.
 */
#define __LIBBPF_LIBBPF_H
#include <xdp/xsk.h>

#include "pcap-int.h"
#include "pcap-xdp.h"

#define XDP_PREFIX		"xdp:"
#define XDP_PREFIX_LEN		(sizeof(XDP_PREFIX) - 1)
#define XDP_FRAME_SIZE		XSK_UMEM__DEFAULT_FRAME_SIZE	/* 4096 */
#define XDP_DEF_BUFFER_SIZE	(2 * 1024 * 1024)	/* pcap-linux default */
#define XDP_BATCH_SIZE		64

struct pcap_xdp {
	struct xsk_socket *xsk;
	struct xsk_umem *umem;
	struct xsk_ring_prod fill;	/* umem frames lent to the kernel */
	struct xsk_ring_cons comp;	/* TX completions; unused */
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;	/* never created; RX only */
	void *umem_area;
	size_t umem_size;
	u_int nframes;
	__u32 queue_id;
	char *ifname;			/* opt.device with "xdp:" stripped */
	int poll_breakloop_fd;		/* eventfd */
	int promisc_fd;			/* PACKET_MR_PROMISC anchor socket */
	int ioctl_fd;			/* SIOC* scratch; open until cleanup */
	int rxvlan_bit;			/* "rx-vlan-hw-parse" feature bit */
	u_int feat_words;		/* blocks for ETHTOOL_[GS]FEATURES */
	int rxvlan_restore;		/* offload was on; re-enable at cleanup */
	int nonblock;
	u_char *oneshot_buffer;
	uint64_t packets_read;		/* delivered, post-filter */
};

static u_int
pcap_xdp_round_pow2(u_int n)
{
	u_int v = 1;

	while (v < n)
		v <<= 1;
	return v;
}

/*
 * Netdev features are addressed by bit index, found by name in the
 * ETH_SS_FEATURES string set.
 */
static int
pcap_xdp_ethtool_ioctl(int fd, const char *ifname, void *cmd)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	pcapint_strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ifr.ifr_data = (char *)cmd;
	return ioctl(fd, SIOCETHTOOL, &ifr);
}

/* Feature name to bit index, -1 if unknown; also yields the block count. */
static int
pcap_xdp_feature_bit(int fd, const char *ifname, const char *feature,
    u_int *nwords)
{
	struct ethtool_sset_info *sset;
	struct ethtool_gstrings *strings;
	u_int count, i;
	int bit = -1;

	sset = calloc(1, sizeof(*sset) + sizeof(__u32));
	if (sset == NULL)
		return -1;
	sset->cmd = ETHTOOL_GSSET_INFO;
	sset->sset_mask = 1ULL << ETH_SS_FEATURES;
	if (pcap_xdp_ethtool_ioctl(fd, ifname, sset) == -1 ||
	    sset->sset_mask != 1ULL << ETH_SS_FEATURES) {
		free(sset);
		return -1;
	}
	count = sset->data[0];
	free(sset);
	if (count == 0)
		return -1;

	strings = calloc(1, sizeof(*strings) +
	    (size_t)count * ETH_GSTRING_LEN);
	if (strings == NULL)
		return -1;
	strings->cmd = ETHTOOL_GSTRINGS;
	strings->string_set = ETH_SS_FEATURES;
	strings->len = count;
	if (pcap_xdp_ethtool_ioctl(fd, ifname, strings) == -1) {
		free(strings);
		return -1;
	}
	for (i = 0; i < count; i++) {
		if (strncmp((const char *)strings->data +
		    i * ETH_GSTRING_LEN, feature, ETH_GSTRING_LEN) == 0) {
			bit = (int)i;
			break;
		}
	}
	free(strings);
	*nwords = (count + 31) / 32;
	return bit;
}

/* Active state of a feature bit: 1 on, 0 off, -1 unknown. */
static int
pcap_xdp_feature_active(int fd, const char *ifname, int bit, u_int nwords)
{
	struct ethtool_gfeatures *gf;
	int active;

	gf = calloc(1, sizeof(*gf) + nwords * sizeof(gf->features[0]));
	if (gf == NULL)
		return -1;
	gf->cmd = ETHTOOL_GFEATURES;
	gf->size = nwords;
	if (pcap_xdp_ethtool_ioctl(fd, ifname, gf) == -1) {
		free(gf);
		return -1;
	}
	active = (gf->features[bit / 32].active >> (bit % 32)) & 1;
	free(gf);
	return active;
}

/* Returns 0 only when the bit verifiably reads back in the new state. */
static int
pcap_xdp_feature_set(int fd, const char *ifname, int bit, u_int nwords,
    int on)
{
	struct ethtool_sfeatures *sf;
	int ret, serrno;

	sf = calloc(1, sizeof(*sf) + nwords * sizeof(sf->features[0]));
	if (sf == NULL)
		return -1;
	sf->cmd = ETHTOOL_SFEATURES;
	sf->size = nwords;
	sf->features[bit / 32].valid = 1U << (bit % 32);
	sf->features[bit / 32].requested = on ? 1U << (bit % 32) : 0;
	ret = pcap_xdp_ethtool_ioctl(fd, ifname, sf);
	serrno = errno;
	free(sf);
	if (ret == -1) {
		errno = serrno;
		return -1;
	}
	if (pcap_xdp_feature_active(fd, ifname, bit, nwords) == on)
		return 0;
	/* Fixed feature or failed readback; errno 0 covers both. */
	errno = 0;
	return -1;
}

static int
pcap_xdp_stats(pcap_t *p, struct pcap_stat *ps)
{
	struct pcap_xdp *px = p->priv;
	struct xdp_statistics xstats;
	socklen_t optlen = sizeof(xstats);

	memset(&xstats, 0, sizeof(xstats));
	if (getsockopt(p->fd, SOL_XDP, XDP_STATISTICS, &xstats, &optlen) < 0) {
		pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "xdp: XDP_STATISTICS");
		return -1;
	}
	/* Userspace filter rejects count in neither ps_recv nor ps_drop. */
	ps->ps_recv = (u_int)px->packets_read;
	ps->ps_drop = (u_int)(xstats.rx_dropped + xstats.rx_ring_full);
	ps->ps_ifdrop = (u_int)xstats.rx_fill_ring_empty_descs;
	return 0;
}

/*
 * The frame goes back to the fill ring when the batch ends, so a stored
 * pointer would alias a recycled frame.  Copy out, like pcapint_oneshot_linux.
 */
static void
pcap_xdp_oneshot(u_char *user, const struct pcap_pkthdr *h,
    const u_char *bytes)
{
	struct oneshot_userdata *sp = (struct oneshot_userdata *)user;
	pcap_t *p = sp->pd;
	struct pcap_xdp *px = p->priv;

	*sp->hdr = *h;
	memcpy(px->oneshot_buffer, bytes, h->caplen);
	*sp->pkt = px->oneshot_buffer;
}

/*
 * xsk_poll() never raises POLLERR, but NETDEV_UNREGISTER sets sk_err, so
 * a deleted interface shows up in SO_ERROR on an idle wakeup.  A link
 * merely brought down sets nothing and is not detectable here.
 * Returns 1 with errbuf set when the interface is gone, else 0.
 */
static int
pcap_xdp_iface_gone(pcap_t *p, struct pcap_xdp *px)
{
	int err = 0;
	socklen_t errlen = sizeof(err);

	if (getsockopt(p->fd, SOL_SOCKET, SO_ERROR, &err, &errlen) == -1 ||
	    err == 0)
		return 0;
	if (if_nametoindex(px->ifname) == 0)
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "The interface disappeared");
	else
		pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
		    err, "xdp: interface error");
	return 1;
}

static int
pcap_xdp_dispatch(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
{
	struct pcap_xdp *px = p->priv;
	struct pcap_pkthdr h;
	struct timespec ts;
	struct pollfd pfd[2];
	nfds_t nfds;
	__u32 idx_rx, idx_fill;
	u_int batch, nrecv, i;
	int processed = 0;
	int timeout, ret;

	if (PACKET_COUNT_IS_UNLIMITED(cnt))
		cnt = INT_MAX;

	for (;;) {
		if (p->break_loop) {
			p->break_loop = 0;
			return PCAP_ERROR_BREAK;
		}

		batch = XDP_BATCH_SIZE;
		if ((u_int)(cnt - processed) < batch)
			batch = (u_int)(cnt - processed);
		idx_rx = 0;
		nrecv = xsk_ring_cons__peek(&px->rx, batch, &idx_rx);
		if (nrecv == 0) {
			if (processed > 0 || px->nonblock)
				return processed;

			pfd[0].fd = p->fd;
			pfd[0].events = POLLIN;
			pfd[1].revents = 0;
			nfds = 1;
			if (px->poll_breakloop_fd != -1) {
				pfd[1].fd = px->poll_breakloop_fd;
				pfd[1].events = POLLIN;
				nfds = 2;
			}
			/* 0 blocks forever (poll -1); negative returns at once. */
			if (p->opt.timeout == 0)
				timeout = -1;
			else if (p->opt.timeout > 0)
				timeout = p->opt.timeout;
			else
				timeout = 0;
			ret = poll(pfd, nfds, timeout);
			if (ret < 0) {
				if (errno == EINTR)
					continue;
				pcapint_fmt_errmsg_for_errno(p->errbuf,
				    PCAP_ERRBUF_SIZE, errno, "xdp: poll");
				return PCAP_ERROR;
			}
			if (ret == 0) {
				/* Idle: check for a deleted interface first. */
				if (pcap_xdp_iface_gone(p, px))
					return PCAP_ERROR;
				return 0;
			}
			if (pfd[0].revents & (POLLERR | POLLHUP)) {
				/*
				 * Not raised by xsk_poll() today; kept for
				 * drivers that might.
				 */
				if (pcap_xdp_iface_gone(p, px))
					return PCAP_ERROR;
				snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
				    "The interface went down");
				return PCAP_ERROR;
			}
			if (pfd[1].revents & POLLIN) {
				uint64_t value;

				(void)read(px->poll_breakloop_fd, &value,
				    sizeof(value));
			}
			continue;
		}

		/* Host clock at dequeue, once per batch; no hardware stamps. */
		clock_gettime(CLOCK_REALTIME, &ts);
		h.ts.tv_sec = ts.tv_sec;
		if (p->opt.tstamp_precision == PCAP_TSTAMP_PRECISION_NANO)
			h.ts.tv_usec = (suseconds_t)ts.tv_nsec;
		else
			h.ts.tv_usec = (suseconds_t)(ts.tv_nsec / 1000);

		/*
		 * 1:1 frame recycle: each consumed rx slot frees exactly one
		 * fill slot, so this reserve cannot come up short.
		 */
		if (xsk_ring_prod__reserve(&px->fill, nrecv, &idx_fill) !=
		    nrecv) {
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
			    "xdp: fill ring reserve failed (ring accounting bug)");
			return PCAP_ERROR;
		}

		for (i = 0; i < nrecv; i++) {
			const struct xdp_desc *desc =
			    xsk_ring_cons__rx_desc(&px->rx, idx_rx + i);
			const u_char *pkt =
			    xsk_umem__get_data(px->umem_area, desc->addr);

			h.len = desc->len;
			h.caplen = min(desc->len, (bpf_u_int32)p->snapshot);
			if (p->fcode.bf_insns == NULL ||
			    pcapint_filter(p->fcode.bf_insns, p->fcode.bf_len,
			    pkt, h.len, desc->len) != 0) {
				callback(user, &h, pkt);
				/* Counted after the filter. */
				px->packets_read++;
				processed++;
			}
			*xsk_ring_prod__fill_addr(&px->fill, idx_fill + i) =
			    desc->addr & ~((__u64)XDP_FRAME_SIZE - 1);
		}

		/*
		 * Refill before returning to a caller's select() loop: poll
		 * on the xsk fd only wakes if the fill ring is stocked.
		 */
		xsk_ring_prod__submit(&px->fill, nrecv);
		xsk_ring_cons__release(&px->rx, nrecv);

		if (processed >= cnt)
			return processed;
	}
}

static int
pcap_xdp_inject(pcap_t *p, const void *buf _U_, int size _U_)
{
	/* RX only; TX would need the umem split between fill and TX use. */
	pcapint_strlcpy(p->errbuf,
	    "xdp error: packet injection is not supported",
	    PCAP_ERRBUF_SIZE);
	return PCAP_ERROR;
}

static void
pcap_xdp_breakloop(pcap_t *p)
{
	struct pcap_xdp *px = p->priv;
	uint64_t value = 1;

	pcapint_breakloop_common(p);
	if (px->poll_breakloop_fd != -1)
		(void)write(px->poll_breakloop_fd, &value, sizeof(value));
}

/*
 * Blocking lives in our own poll(); O_NONBLOCK on the fd would change
 * nothing, so nonblock is just a flag the read loop checks.
 */
static int
pcap_xdp_getnonblock(pcap_t *p)
{
	struct pcap_xdp *px = p->priv;

	return px->nonblock;
}

static int
pcap_xdp_setnonblock(pcap_t *p, int nonblock)
{
	struct pcap_xdp *px = p->priv;

	px->nonblock = nonblock;
	return 0;
}

static void
pcap_xdp_cleanup(pcap_t *p)
{
	struct pcap_xdp *px = p->priv;

	/*
	 * Socket before umem (else EBUSY), then munmap.  xsk_socket__delete
	 * closes the fd, so clear p->fd or pcapint_cleanup_live_common
	 * closes it again.  A clean close also removes libxdp's dispatcher;
	 * a killed process leaves it attached, which is harmless: traffic
	 * still passes and the queue rebinds.
	 */
	if (px->xsk != NULL) {
		xsk_socket__delete(px->xsk);
		px->xsk = NULL;
		p->fd = -1;
	}
	if (px->umem != NULL) {
		xsk_umem__delete(px->umem);
		px->umem = NULL;
	}
	if (px->umem_area != NULL) {
		munmap(px->umem_area, px->umem_size);
		px->umem_area = NULL;
	}
	/* Restore rx-vlan-offload only after the socket is gone. */
	if (px->rxvlan_restore) {
		(void)pcap_xdp_feature_set(px->ioctl_fd, px->ifname,
		    px->rxvlan_bit, px->feat_words, 1);
		px->rxvlan_restore = 0;
	}
	if (px->ioctl_fd != -1) {
		close(px->ioctl_fd);
		px->ioctl_fd = -1;
	}
	if (px->promisc_fd != -1) {
		close(px->promisc_fd);
		px->promisc_fd = -1;
	}
	if (px->poll_breakloop_fd != -1) {
		close(px->poll_breakloop_fd);
		px->poll_breakloop_fd = -1;
	}
	free(px->oneshot_buffer);
	px->oneshot_buffer = NULL;
	free(px->ifname);
	px->ifname = NULL;
	pcapint_cleanup_live_common(p);
}

static int
pcap_xdp_activate(pcap_t *p)
{
	struct pcap_xdp *px = p->priv;
	struct xsk_umem_config ucfg;
	struct xsk_socket_config scfg;
	struct ifreq ifr;
	const char *name;
	char *sep;
	unsigned int qid;
	u_int bufsize, depth, n, i;
	__u32 idx;
	int ret;
	int status = 0;

	if (p->opt.rfmon)
		return PCAP_ERROR_RFMON_NOTSUP;

	/* opt.protocol is an AF_PACKET bind value; AF_XDP has no equivalent. */
	if (p->opt.protocol != 0) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "xdp: pcap_set_protocol_linux() is not supported");
		return PCAP_ERROR;
	}

	name = p->opt.device + XDP_PREFIX_LEN;
	if (*name == '\0') {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "xdp: no interface name after \"%s\"", XDP_PREFIX);
		ret = PCAP_ERROR_NO_SUCH_DEVICE;
		goto fail;
	}
	px->ifname = strdup(name);
	if (px->ifname == NULL) {
		pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "strdup");
		ret = PCAP_ERROR;
		goto fail;
	}

	/* One socket binds one queue; traffic RSS sends elsewhere is not seen. */
	px->queue_id = 0;
	sep = strchr(px->ifname, ':');
	if (sep != NULL) {
		*sep = '\0';
		if (pcapint_get_decuint(sep + 1, NULL, &qid) != 0) {
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
			    "xdp: invalid queue id \"%s\"", sep + 1);
			ret = PCAP_ERROR_NO_SUCH_DEVICE;
			goto fail;
		}
		px->queue_id = qid;
	}

	px->ioctl_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (px->ioctl_fd == -1) {
		pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "xdp: cannot open ioctl socket");
		ret = PCAP_ERROR;
		goto fail;
	}

	/*
	 * DLT_EN10MB is fixed below; generic XDP would bind to an L3 device
	 * and hand us raw IP labelled as Ethernet, so refuse those.
	 */
	memset(&ifr, 0, sizeof(ifr));
	pcapint_strlcpy(ifr.ifr_name, px->ifname, sizeof(ifr.ifr_name));
	if (ioctl(px->ioctl_fd, SIOCGIFHWADDR, &ifr) == -1) {
		if (errno == ENODEV) {
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
			    "xdp: no such device %s", px->ifname);
			ret = PCAP_ERROR_NO_SUCH_DEVICE;
		} else {
			pcapint_fmt_errmsg_for_errno(p->errbuf,
			    PCAP_ERRBUF_SIZE, errno, "xdp: SIOCGIFHWADDR");
			ret = PCAP_ERROR;
		}
		goto fail;
	}
	if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "xdp: only Ethernet interfaces are supported");
		ret = PCAP_ERROR;
		goto fail;
	}

	/*
	 * With rx-vlan-offload on, the NIC strips the tag into the rx
	 * descriptor where XDP cannot see it.  Clear it, restore at cleanup.
	 * This must precede the bind: a feature change can rebuild the rx
	 * rings, and that tears down a bound socket.
	 */
	px->rxvlan_bit = pcap_xdp_feature_bit(px->ioctl_fd, px->ifname,
	    "rx-vlan-hw-parse", &px->feat_words);
	if (px->rxvlan_bit >= 0 &&
	    pcap_xdp_feature_active(px->ioctl_fd, px->ifname,
	    px->rxvlan_bit, px->feat_words) == 1) {
		if (pcap_xdp_feature_set(px->ioctl_fd, px->ifname,
		    px->rxvlan_bit, px->feat_words, 0) != 0) {
			if (errno == EPERM || errno == EACCES) {
				/*
				 * ETHTOOL_SFEATURES needs CAP_NET_ADMIN where
				 * the gets do not.  Warn and carry on without
				 * VLAN tags rather than fail.
				 */
				snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
				    "xdp: cannot disable rx-vlan-offload on %s (CAP_NET_ADMIN may be required); VLAN tags will not be visible",
				    px->ifname);
				status = PCAP_WARNING;
			} else if (errno == ENODEV ||
			    if_nametoindex(px->ifname) == 0) {
				/*
				 * The device went away since SIOCGIFHWADDR;
				 * the errno here is not reliable, so test
				 * the name instead.
				 */
				snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
				    "xdp: no such device %s", px->ifname);
				ret = PCAP_ERROR_NO_SUCH_DEVICE;
				goto fail;
			} else {
				snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
				    "xdp: cannot disable rx-vlan-offload on %s",
				    px->ifname);
				ret = PCAP_ERROR;
				goto fail;
			}
		} else
			px->rxvlan_restore = 1;
	}

	if (p->snapshot <= 0 || p->snapshot > MAXIMUM_SNAPLEN)
		p->snapshot = MAXIMUM_SNAPLEN;

	/*
	 * One 4096-byte frame per packet; larger packets need multi-buffer
	 * support this does not have.  buffer_size sets the umem size and so
	 * the burst tolerance; too small shows up as rx_ring_full drops.
	 */
	bufsize = p->opt.buffer_size;
	if (bufsize == 0)
		bufsize = XDP_DEF_BUFFER_SIZE;
	px->nframes = pcap_xdp_round_pow2((bufsize + XDP_FRAME_SIZE - 1) /
	    XDP_FRAME_SIZE);
	px->umem_size = (size_t)px->nframes * XDP_FRAME_SIZE;

	px->umem_area = mmap(NULL, px->umem_size, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (px->umem_area == MAP_FAILED) {
		px->umem_area = NULL;
		pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "xdp: cannot mmap %zu-byte umem", px->umem_size);
		ret = PCAP_ERROR;
		goto fail;
	}

	depth = min(px->nframes / 2, XSK_RING_CONS__DEFAULT_NUM_DESCS);
	memset(&ucfg, 0, sizeof(ucfg));
	ucfg.fill_size = depth;
	ucfg.comp_size = depth;
	ucfg.frame_size = XDP_FRAME_SIZE;
	ucfg.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM;
	ucfg.flags = XSK_UMEM__DEFAULT_FLAGS;
	ret = xsk_umem__create(&px->umem, px->umem_area, px->umem_size,
	    &px->fill, &px->comp, &ucfg);
	if (ret != 0) {
		switch (-ret) {

		case EPERM:
			/* libxdp opens the AF_XDP socket in here. */
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
			    "xdp: cannot create AF_XDP socket - CAP_NET_RAW may be required");
			ret = PCAP_ERROR_PERM_DENIED;
			break;

		case ENOBUFS:
			/* Registration charges RLIMIT_MEMLOCK. */
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
			    "xdp: cannot register %zu-byte umem - a higher RLIMIT_MEMLOCK (ulimit -l) may be required",
			    px->umem_size);
			ret = PCAP_ERROR_PERM_DENIED;
			break;

		case EAFNOSUPPORT:
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
			    "xdp: kernel lacks AF_XDP support (CONFIG_XDP_SOCKETS, Linux 4.18+)");
			ret = PCAP_ERROR_CAPTURE_NOTSUP;
			break;

		default:
			pcapint_fmt_errmsg_for_errno(p->errbuf,
			    PCAP_ERRBUF_SIZE, -ret, "xdp: cannot create umem");
			ret = PCAP_ERROR;
		}
		goto fail;
	}

	/*
	 * libxdp_flags 0: xsk_socket__create() loads libxdp's default
	 * redirect program into the dispatcher and puts this socket in its
	 * XSKMAP.  Needs a mounted bpffs and the program object at
	 * LIBXDP_OBJECT_PATH.  XDP_COPY so the bind works in any attach mode.
	 */
	memset(&scfg, 0, sizeof(scfg));
	scfg.rx_size = depth;
	scfg.tx_size = 0;		/* RX only */
	scfg.libxdp_flags = 0;
	scfg.xdp_flags = 0;
	scfg.bind_flags = XDP_COPY;
	ret = xsk_socket__create(&px->xsk, px->ifname, px->queue_id,
	    px->umem, &px->rx, NULL, &scfg);
	if (ret != 0) {
		/* Fits in errbuf after the longest prefix (-Wformat-truncation). */
		char lro_hint[128];
		u_int nwords;
		int bit;

		/*
		 * Some drivers refuse XDP while LRO is on and report EINVAL;
		 * say so when LRO is on.
		 */
		lro_hint[0] = '\0';
		bit = pcap_xdp_feature_bit(px->ioctl_fd, px->ifname,
		    "rx-lro", &nwords);
		if (bit >= 0 && pcap_xdp_feature_active(px->ioctl_fd,
		    px->ifname, bit, nwords) == 1)
			snprintf(lro_hint, sizeof(lro_hint),
			    " (LRO is enabled; some drivers refuse XDP with LRO; try ethtool -K %s lro off)",
			    px->ifname);

		switch (-ret) {

		case EPERM:
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
			    "xdp: binding to %s queue %u failed - CAP_NET_RAW, CAP_NET_ADMIN and CAP_BPF may be required",
			    px->ifname, px->queue_id);
			ret = PCAP_ERROR_PERM_DENIED;
			break;

		case EAFNOSUPPORT:
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
			    "xdp: kernel lacks AF_XDP support (CONFIG_XDP_SOCKETS, Linux 4.18+)");
			ret = PCAP_ERROR_CAPTURE_NOTSUP;
			break;

		case ENETDOWN:
			/* The status alone carries the message. */
			ret = PCAP_ERROR_IFACE_NOT_UP;
			break;

		case EINVAL:
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
			    "xdp: queue %u does not exist on %s, or the device configuration (MTU vs frame size) prevents XDP%s",
			    px->queue_id, px->ifname, lro_hint);
			ret = PCAP_ERROR;
			break;

		case EBUSY:
			/*
			 * EBUSY from the kernel for a queue another socket
			 * owns, or from libxdp for a foreign XDP program.
			 */
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
			    "xdp: queue %u on %s unavailable: another AF_XDP socket owns it, or an XDP program is attached (a crashed capture can leave a stray dispatcher attached); if residue, clear it with 'ip link set dev %s xdp off'",
			    px->queue_id, px->ifname, px->ifname);
			ret = PCAP_ERROR;
			break;

		case ENODEV:
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
			    "xdp: no such device %s", px->ifname);
			ret = PCAP_ERROR_NO_SUCH_DEVICE;
			break;

		default:
			pcapint_fmt_errmsg_for_errno(p->errbuf,
			    PCAP_ERRBUF_SIZE, -ret,
			    "xdp: cannot create AF_XDP socket on %s queue %u%s",
			    px->ifname, px->queue_id, lro_hint);
			ret = PCAP_ERROR;
		}
		goto fail;
	}

	/* Prime the fill ring; frames [depth, nframes) stay user-owned. */
	n = xsk_ring_prod__reserve(&px->fill, depth, &idx);
	if (n != depth) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
		    "xdp: cannot prime fill ring");
		ret = PCAP_ERROR;
		goto fail;
	}
	for (i = 0; i < n; i++)
		*xsk_ring_prod__fill_addr(&px->fill, idx + i) =
		    (__u64)i * XDP_FRAME_SIZE;
	xsk_ring_prod__submit(&px->fill, n);

	/* The xsk fd is pollable for RX. */
	p->fd = xsk_socket__fd(px->xsk);
	p->selectable_fd = p->fd;

	px->poll_breakloop_fd = eventfd(0, EFD_NONBLOCK);
	if (px->poll_breakloop_fd == -1) {
		pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "xdp: cannot open breakloop eventfd");
		ret = PCAP_ERROR;
		goto fail;
	}

	px->oneshot_buffer = malloc(XDP_FRAME_SIZE);
	if (px->oneshot_buffer == NULL) {
		pcapint_fmt_errmsg_for_errno(p->errbuf, PCAP_ERRBUF_SIZE,
		    errno, "malloc");
		ret = PCAP_ERROR;
		goto fail;
	}

	/*
	 * AF_XDP has no promiscuous mode of its own, so hold a PF_PACKET
	 * socket with PACKET_MR_PROMISC as a refcounted anchor; the kernel
	 * drops it with the process.  Protocol 0 and never bound, so it
	 * receives nothing.
	 */
	if (p->opt.promisc) {
		struct packet_mreq mr;

		px->promisc_fd = socket(PF_PACKET, SOCK_RAW, 0);
		if (px->promisc_fd == -1) {
			if (errno == EPERM || errno == EACCES) {
				snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
				    "xdp: promiscuous-mode anchor socket failed - CAP_NET_RAW may be required");
				ret = PCAP_ERROR_PROMISC_PERM_DENIED;
			} else {
				pcapint_fmt_errmsg_for_errno(p->errbuf,
				    PCAP_ERRBUF_SIZE, errno,
				    "xdp: cannot open promiscuous-mode anchor socket");
				ret = PCAP_ERROR;
			}
			goto fail;
		}
		memset(&mr, 0, sizeof(mr));
		mr.mr_ifindex = (int)if_nametoindex(px->ifname);
		mr.mr_type = PACKET_MR_PROMISC;
		if (mr.mr_ifindex == 0 ||
		    setsockopt(px->promisc_fd, SOL_PACKET,
		    PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) == -1) {
			if (errno == EPERM || errno == EACCES) {
				snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
				    "xdp: promiscuous mode on %s denied - CAP_NET_RAW may be required",
				    px->ifname);
				ret = PCAP_ERROR_PROMISC_PERM_DENIED;
			} else {
				pcapint_fmt_errmsg_for_errno(p->errbuf,
				    PCAP_ERRBUF_SIZE, errno,
				    "xdp: cannot enable promiscuous mode on %s",
				    px->ifname);
				ret = PCAP_ERROR;
			}
			goto fail;
		}
	}

	/* Raw L2 as the driver received it. */
	p->linktype = DLT_EN10MB;

	p->read_op = pcap_xdp_dispatch;
	p->inject_op = pcap_xdp_inject;
	p->setfilter_op = pcapint_install_bpf_program;
	/* XDP is an RX hook; egress is never seen.  NULL makes pcap.c say so. */
	p->setdirection_op = NULL;
	p->set_datalink_op = NULL;
	p->getnonblock_op = pcap_xdp_getnonblock;
	p->setnonblock_op = pcap_xdp_setnonblock;
	p->stats_op = pcap_xdp_stats;
	p->breakloop_op = pcap_xdp_breakloop;
	p->cleanup_op = pcap_xdp_cleanup;
	p->oneshot_callback = pcap_xdp_oneshot;

	return status;

fail:
	pcap_xdp_cleanup(p);
	return ret;
}

pcap_t *
pcap_xdp_create(const char *device, char *ebuf, int *is_ours)
{
	struct pcap_xdp *px;
	pcap_t *p;

	/* Only the explicit prefix is ours. */
	*is_ours = (strncmp(device, XDP_PREFIX, XDP_PREFIX_LEN) == 0);
	if (!*is_ours)
		return NULL;
	p = PCAP_CREATE_COMMON(ebuf, struct pcap_xdp);
	if (p == NULL)
		return NULL;
	p->activate_op = pcap_xdp_activate;

	/*
	 * Register nano here, or pcap_set_tstamp_precision() rejects it
	 * before activate.
	 */
	p->tstamp_precision_list = malloc(2 * sizeof(u_int));
	if (p->tstamp_precision_list == NULL) {
		pcapint_fmt_errmsg_for_errno(ebuf, PCAP_ERRBUF_SIZE, errno,
		    "malloc");
		pcap_close(p);
		return NULL;
	}
	p->tstamp_precision_list[0] = PCAP_TSTAMP_PRECISION_MICRO;
	p->tstamp_precision_list[1] = PCAP_TSTAMP_PRECISION_NANO;
	p->tstamp_precision_count = 2;

	px = p->priv;
	px->poll_breakloop_fd = -1;
	px->promisc_fd = -1;
	px->ioctl_fd = -1;
	px->rxvlan_bit = -1;
	return p;
}

int
pcap_xdp_findalldevs(pcap_if_list_t *devlistp _U_, char *err_str _U_)
{
	/* Nothing to enumerate: any Ethernet netdev opens as xdp:IFNAME. */
	return 0;
}
