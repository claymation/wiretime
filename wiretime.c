/*
 * wiretime -- Measures the time it takes packets to hit the wire, using
 *	       hardware timestamps.
 *
 * This program transmits small UDP packets and measures the time it takes
 * the packet to traverse the network protocol stack, the queue discipline
 * layer, and the driver queue before being emitted on the wire. It relies
 * on the network device timestamping the packet in hardware and providing
 * that timestamp to the caller via the socket's error queue.
 *
 * The min, median, and max latencies are recored, as well as a historgram
 * of the latency distribution. Packets exceeding a configurable latency
 * threshold can trigger a tracing snapshot, if the tracefs is mounted at
 * the usual place (/sys/kernel/tracing).
 *
 * Copyright (c) 2020 Clay McClure
 */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <linux/errqueue.h>
#include <linux/net.h>
#include <linux/net_tstamp.h>
#include <linux/pkt_sched.h>
#include <linux/sockios.h>

static FILE *snapshot;
static FILE *trace_marker;

static size_t num_packets;

static long min_lat = LONG_MAX;
static long max_lat = LONG_MIN;

#define NSAMPLES	1024U
static long samples[NSAMPLES];

#define NBINS		12U
#define BIN0		32L
static size_t bins[NBINS];

static struct timespec tstamps[3];

void sigint_handler(int __attribute__((unused))_)
{
	exit(EXIT_SUCCESS);
}

int compar(const void *p, const void *q)
{
	if (*(long *)p < *(long *)q)
		return -1;
	if (*(long *)p > *(long *)q)
		return +1;
	return 0;
}

void print_statistics()
{
	/*
	 * We don't update statistics for the first packet, because there's
	 * typically some additional latency for the first packet.
	 */
	if (num_packets)
		--num_packets;

	printf("%zu packets transmitted\n", num_packets);

	if (!num_packets)
		return;

	size_t n = num_packets > NSAMPLES ? NSAMPLES : num_packets;
	qsort(samples, n, sizeof(samples[0]), compar);

	printf("latency min/median/max = %ld/%ld/%ld us\n",
			min_lat,
			samples[n/2],
			max_lat);

	printf("distribution:\n");
	long low = 0;
	long high = BIN0;
	for (size_t i = 0; i < NBINS - 1; ++i)
	{
		printf("%5ld - %5ld us: %5zu\n", low, high, bins[i]);
		low = high + 1;
		high <<= 1;
	}
	printf("      > %5ld us: %5zu\n", low - 1, bins[NBINS - 1]);
}

void update_statistics(long latency)
{
	if (latency < min_lat)
		min_lat = latency;

	if (latency > max_lat)
		max_lat = latency;

	samples[num_packets & (NSAMPLES - 1)] = latency;

	for (size_t i = 0; i < NBINS - 1; ++i)
	{
		if (latency < (BIN0 * (1 << i))) {
			++bins[i];
			return;
		}
	}
	++bins[NBINS - 1];
};

void recv_timestamp(int sockfd)
{
	char buffer[128];
	struct msghdr msgh = {
		.msg_control = buffer,
		.msg_controllen = sizeof(buffer)
	};

	/*
	 * MSG_ERRQUEUE reads are always non-blocking.
	 */
	const ssize_t bytes = recvmsg(sockfd, &msgh, MSG_ERRQUEUE);
	if (bytes < 0)
	{
		if (errno != EAGAIN)
			perror("recvmsg");
		return;
	}

	struct scm_timestamping *tstamps_local = NULL;
	struct sock_extended_err *serr = NULL;
	struct cmsghdr *cmsg;

	for (cmsg = CMSG_FIRSTHDR(&msgh); cmsg; cmsg = CMSG_NXTHDR(&msgh, cmsg))
	{
#if defined(DEBUG_TIME_STAMP)
		fprintf(stderr,
		       " cmsg_level: %4d,"
		       " cmsg_type: %4d\n",
			cmsg->cmsg_level,
			cmsg->cmsg_type);
#endif
		if (cmsg->cmsg_level == SOL_SOCKET &&
			cmsg->cmsg_type == SCM_TIMESTAMPING)
		{
			tstamps_local = (struct scm_timestamping *)CMSG_DATA(cmsg);
#if defined(DEBUG_TIME_STAMP)
			for (int i = 0; i < 3; i++)
			{
				fprintf(stderr, "  ts %d: %7ld.%09ld\n", i,
					tstamps_local->ts[i].tv_sec,
					tstamps_local->ts[i].tv_nsec);
			}
#endif
		}

		else if (cmsg->cmsg_level == SOL_IP &&
			cmsg->cmsg_type == IP_RECVERR)
		{
			serr = (struct sock_extended_err *)CMSG_DATA(cmsg);

#if defined(DEBUG_TIME_STAMP)
			fprintf(stderr, "  ee_info: %d, ee_data: %d\n",
					serr->ee_info, serr->ee_data);
#endif
		}
	}

	if (!(tstamps_local && serr))
		return;

	if (serr->ee_info == SCM_TSTAMP_SCHED)
	{
		/*
		 * software timestamp: packet entered the packet scheduler.
		 */
		tstamps[0] = tstamps_local->ts[0];
	}
	else if (serr->ee_info == SCM_TSTAMP_SND && tstamps_local->ts[0].tv_sec)
	{
		/*
		 * software timestamp: packet passed to NIC.
		 */
		tstamps[1] = tstamps_local->ts[0];
	}
	else if (serr->ee_info == SCM_TSTAMP_SND && tstamps_local->ts[2].tv_sec)
	{
		/*
		 * hardware timestamp: packet transmitted by NIC.
		 */
		tstamps[2] = tstamps_local->ts[2];
	}
}

#define BILLION		1000000000L

void normalize(struct timespec *ts)
{
	while (ts->tv_nsec >= BILLION)
	{
		ts->tv_sec++;
		ts->tv_nsec -= BILLION;
	}
}

void synchronize(long period, long addend, void (*exceptfn)(int), int sockfd)
{
	struct timespec now;
	struct timespec next;
	struct timespec timeout;
	fd_set readfds;
	fd_set writefds;
	fd_set exceptfds;
	long error;
	int fds;

	clock_gettime(CLOCK_MONOTONIC, &now);

	/*
	 * Compute the beginning of the next cycle.
	 */
	next.tv_sec = now.tv_sec;
	next.tv_nsec = ((now.tv_nsec / period) + 1) * period;

	/*
	 * Add a bit to move out of phase with the timer interrupt.
	 */
	next.tv_nsec += addend;

	normalize(&next);

#if DEBUG_TIME_SYNC
	fputs("---\n", stderr);
	fprintf(stderr, "   now: %7ld.%09ld\n", now.tv_sec, now.tv_nsec);
	fprintf(stderr, "  next: %7ld.%09ld\n", next.tv_sec, next.tv_nsec);
#endif

	FD_ZERO(&readfds);
	FD_ZERO(&writefds);
	FD_ZERO(&exceptfds);

	do {
		timeout.tv_sec = 0;
		timeout.tv_nsec = (next.tv_sec - now.tv_sec) * BILLION
				+ (next.tv_nsec - now.tv_nsec);

		/*
		 * Select for a little less than required, because we'll
		 * oversleep.
		 */
		timeout.tv_nsec -= timeout.tv_nsec / 1024;

		FD_SET(sockfd, &readfds);
		FD_SET(sockfd, &exceptfds);

#if DEBUG_TIME_SYNC
		fprintf(stderr, "select: %7ld.%09ld\n", timeout.tv_sec, timeout.tv_nsec);
#endif

		/*
		 * Block.
		 */
		fds = pselect(sockfd + 1, &readfds, &writefds, &exceptfds, &timeout, NULL);
		if (fds < 0)
		{
			if (errno != EINTR)
			{
				perror("pselect");
				return;
			}
			continue;
		}

		if (fds && exceptfn)
		{
			exceptfn(sockfd);
		}

		clock_gettime(CLOCK_MONOTONIC, &now);

		error = (now.tv_sec - next.tv_sec) * BILLION +
			(now.tv_nsec - next.tv_nsec);

#if DEBUG_TIME_SYNC
		fprintf(stderr, "wakeup: %7ld.%09ld\n", now.tv_sec, now.tv_nsec);
		fprintf(stderr, " error: %17.9f\n", error / 1E9);
#endif
	} while (error < -50000);

#if DEBUG_TIME_SYNC
	fprintf(stderr, "\n");
#endif
}

int main(int argc, char *argv[])
{
	int err;
	unsigned optval;

	if (argc != 5)
	{
		fprintf(stderr, "usage: %s DEVICE PERIOD ADDEND THRESHOLD\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	const char *interface = argv[1];
	const long period = atol(argv[2]);
	const long addend = atol(argv[3]);
	const long threshold = atol(argv[4]);

	if (period <= 0)
	{
		fputs("error: period must be positive\n", stderr);
		exit(EXIT_FAILURE);
	}

	if (addend < 0)
	{
		fputs("error: addend must be non-negative\n", stderr);
		exit(EXIT_FAILURE);
	}

	if (threshold < 0)
	{
		fputs("error: threshold must be non-negative\n", stderr);
		exit(EXIT_FAILURE);
	}

	/*
	 * Set up kernel tracing.
	 */
	snapshot = fopen("/sys/kernel/tracing/snapshot", "w");
	trace_marker = fopen("/sys/kernel/tracing/trace_marker", "w");

	if (!snapshot || !trace_marker)
		fputs("can't take snapshot: no /sys/kernel/tracing?\n", stderr);

	const int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sockfd < 0)
	{
		perror("socket");
		exit(EXIT_FAILURE);
	}

	/*
	 * TC_PRIO_CONTROL is the highest socket priority.
	 */
	optval = TC_PRIO_CONTROL;
	err = setsockopt(sockfd, SOL_SOCKET, SO_PRIORITY,
			&optval, sizeof(optval));
	if (err < 0)
	{
		perror("setsockopt(SO_PRIORITY)");
		exit(EXIT_FAILURE);
	}

	/*
	 * Request software and hardware TX timestamps on this socket.
	 */
	optval = /* Timestamp generation flags */
		 SOF_TIMESTAMPING_TX_HARDWARE |
		 SOF_TIMESTAMPING_TX_SOFTWARE |
		 SOF_TIMESTAMPING_TX_SCHED |

		 /* Timestamp reporting flags */
		 SOF_TIMESTAMPING_SOFTWARE |
		 SOF_TIMESTAMPING_RAW_HARDWARE |

		 /* TImestamp option flags */
		 SOF_TIMESTAMPING_OPT_ID |
		 SOF_TIMESTAMPING_OPT_TSONLY |
		 SOF_TIMESTAMPING_OPT_TX_SWHW;
	
	err = setsockopt(sockfd, SOL_SOCKET, SO_TIMESTAMPING,
			&optval, sizeof(optval));
	if (err < 0)
	{
		perror("setsockopt(SO_TIMESTAMPING)");
		exit(EXIT_FAILURE);
	}

	/*
	 * Enable hardware TX timestamps on this interface.
	 */
	const struct hwtstamp_config hwtstamp_config = {
		.tx_type = HWTSTAMP_TX_ON,
	};

	struct ifreq ifreq = {
		.ifr_data = (char *)&hwtstamp_config,
	};

	strncpy(ifreq.ifr_name, interface, sizeof(ifreq.ifr_name) - 1);

	err = ioctl(sockfd, SIOCSHWTSTAMP, &ifreq);
	if (err < 0)
	{
		perror("ioctl(SIOCSHWTSTAMP)");
		exit(EXIT_FAILURE);
	}

	/*
	 * Use the PTP event message address and port, since some hardware can
	 * only timestamp PTP packets.
	 */
	const struct sockaddr_in addr = {
		.sin_family 	 = AF_INET,
		.sin_port	 = htons(319),
		.sin_addr.s_addr = inet_addr("224.0.1.129"),
	};

	err = connect(sockfd, (const struct sockaddr *)&addr, sizeof(addr));
	if (err < 0)
	{
		perror("connect");
		exit(EXIT_FAILURE);
	}

	/*
	 * PTPv2 sync message header. Some hardware can only timestamp PTPv2
	 * packets, so we need to set just enough of the header to fool them.
	 */
	const char buf[34 + 10] __attribute__ ((aligned (2))) = {
		[0]	= 0x00,	// Sync
		[1]	= 0x02, // PTPv2
	};

	uint16_t seqid = 0;

	const struct sigaction act = {
		.sa_handler = sigint_handler,
	};

	err = sigaction(SIGINT, &act, NULL);
	if (err < 0)
	{
		perror("sigaction(SIGINT)");
		exit(EXIT_FAILURE);
	}

	err = sigaction(SIGTERM, &act, NULL);
	if (err < 0)
	{
		perror("sigaction(SIGINT)");
		exit(EXIT_FAILURE);
	}

	atexit(print_statistics);

	while (1)
	{
		*(uint16_t *)&buf[30] = htons(seqid);

		if (trace_marker)
			fputs("starting slack time\n", trace_marker);

		synchronize(period, addend, recv_timestamp, sockfd);

		if (trace_marker)
			fputs("starting cycle\n", trace_marker);

		ssize_t bytes = write(sockfd, buf, sizeof(buf));
		if (bytes < 0)
		{
			perror("write");
		}
		else if (bytes != sizeof(buf))
		{
			fprintf(stderr, "short write\n");
		}
		
		if (num_packets)
		{
			if (!(tstamps[0].tv_sec &&
			      tstamps[1].tv_sec &&
			      tstamps[2].tv_sec))
			{
				if (!tstamps[0].tv_sec)
					fputs("MISSING TIMESTAMP 0\n", stderr);
				if (!tstamps[1].tv_sec)
					fputs("MISSING TIMESTAMP 1\n", stderr);
				if (!tstamps[2].tv_sec)
					fputs("MISSING TIMESTAMP 2\n", stderr);
				if (snapshot)
				{
					fputs("1\n", snapshot);
					fputs("SNAPSHOT TAKEN!\n", stderr);
				}

				continue;
			}

			long latency =
				((tstamps[2].tv_sec - tstamps[0].tv_sec) * 1000000000LL +
				 (tstamps[2].tv_nsec - tstamps[0].tv_nsec)) / 1000;

			if (trace_marker)
				fprintf(trace_marker, "%6ld us latency\n",
						latency);

			bool snapshotted = false;

			if (snapshot && threshold && latency > threshold)
			{
				fputs("1\n", snapshot);
				snapshotted = true;
			}

			fprintf(stderr, "seq: %05u, "
					"socket: %5ld.%06ld, "
					"driver: %5ld.%06ld, "
					"hw: %5ld.%06ld, "
					"latency: %5ld us %s\n",
					seqid,
					tstamps[0].tv_sec, tstamps[0].tv_nsec / 1000,
					tstamps[1].tv_sec, tstamps[1].tv_nsec / 1000,
					tstamps[2].tv_sec, tstamps[2].tv_nsec / 1000,
					latency,
					snapshotted ? "(SNAPSHOT TAKEN)" : "");

			if (num_packets > 1)
				update_statistics(latency);
		}

		++seqid;

		memset(tstamps, 0, sizeof(tstamps));

		++num_packets;
	}

	close(sockfd);
	exit(EXIT_SUCCESS);
}
