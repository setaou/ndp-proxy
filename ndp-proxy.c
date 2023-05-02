#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>  
#include <net/if.h>
#include <linux/filter.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netpacket/packet.h>
#include <getopt.h>
#include <err.h>
#include <sys/stat.h>
#include <signal.h>

#define PACKET_BUFFER_SIZE 2048

/*
 *  Packet structures
 */

struct icmp6_ns {
	struct ethhdr eth;
	struct ip6_hdr ip;
	struct nd_neighbor_solicit ns;
} __attribute__((__packed__));

struct icmp6_ns_opt {
	struct nd_opt_hdr opt;
	unsigned char lla[ETH_ALEN];
} __attribute__((__packed__));

/*
 * Functions headers
 */

#ifdef DEBUG
void print_hex(unsigned char *data, size_t len);
#endif
uint16_t icmp6_cksum(unsigned char *icmp_packet, size_t len, struct in6_addr* src, struct in6_addr* dst);
int forge_icmp6_na (unsigned char *buffer, unsigned char *srcmac, unsigned char *dstmac, struct in6_addr *srcip, struct in6_addr *dstip, struct in6_addr *target, unsigned char *lla);
int ipv6_match(struct in6_addr *a, struct in6_addr *b, int len);
void daemonize(char *pidfile);
void handle_signal(int signal);


/* 
 * Global vars
 */

int verbose = 0;				/* Verbose mode */
int daemon_mode = 0;				/* Daemon mode */
char *pidfile;					/* PID File */


/* 
 * Main
 */

int main(int argc, char **argv)
{
	int sock;			/* Socket */
	struct sockaddr_ll addr;	/* Physical layer address */

	unsigned char in_buffer[PACKET_BUFFER_SIZE];	/* Input buffer */
	unsigned char out_buffer[PACKET_BUFFER_SIZE];	/* Output buffer */
	size_t nbytes;					/* Data length */

	char interface[8];				/* Interface name */
	int interface_index;				/* Interface index */
	unsigned char interface_mac[ETH_ALEN];	/* Interface MAC address */

	struct in6_addr network;			/* Network address to proxy */
	int network_mask;				/* CIDR-style network mask */

	struct ifreq ethreq;				/* ioctl data */

	/* Linux Socket Filtering filter */
	static struct sock_filter BPF_code[] = {
		{ BPF_LD  + BPF_H   + BPF_ABS , 0, 0, 12 },
		{ BPF_JMP + BPF_JEQ + BPF_K   , 0, 5, ETH_P_IPV6 },
		{ BPF_LD  + BPF_B   + BPF_ABS , 0, 0, 20 },
		{ BPF_JMP + BPF_JEQ + BPF_K   , 0, 3, IPPROTO_ICMPV6 }, 
		{ BPF_LD  + BPF_B   + BPF_ABS , 0, 0, 54 },
		{ BPF_JMP + BPF_JEQ + BPF_K   , 0, 1, ND_NEIGHBOR_SOLICIT }, 
		{ BPF_RET + BPF_K             , 0, 0, 65535 },
		{ BPF_RET + BPF_K             , 0, 0, 0 }
	};                            
	struct sock_fprog filter = { 8, BPF_code };

	struct in6_addr *target;			/* Target IP */
	struct in6_addr *client_ip;			/* Client IP */
	unsigned char *client_mac;			/* Client MAC address */

	struct icmp6_ns *icmp6_ns;			/* ICMPv6 Neighbor Sollicitation structure */
	struct icmp6_ns_opt *icmp6_ns_opt;		/* ICMPv6 Neighbor Sollicitation option structure */

	/* CLI long options */
	struct option cli_long_options[] = {
		{"help", no_argument, NULL, 'h'},
		{"interface", required_argument, NULL, 'i'},
		{"network", required_argument, NULL, 'n'},
		{"netmask", required_argument, NULL, 'm'},
		{"verbose", no_argument, NULL, 'v'},
		{"daemon", no_argument, NULL, 'd'},
		{"pidfile", required_argument, NULL, 'p'},
		{0, 0, 0, 0}
	};
	int cli_option_index = 0;
	int cli_opt;

	/* Miscelaneous buffers used to display variables in a human readable format */
	char target_c[INET6_ADDRSTRLEN];
       	char client_ip_c[INET6_ADDRSTRLEN];
	char srcmac_c[18];
	char dstmac_c[18];
	char client_mac_c[18];
	char network_c[INET6_ADDRSTRLEN];

	/* Signals handling */
	struct sigaction sa;

	/*****************************************/

	/* Default values */
	inet_pton(AF_INET6, "::1", &network);
	strcpy(interface, "eth0");
	network_mask = 64;
	pidfile = "/var/run/ndp-proxy.pid";

	/* Signals handling */
	memset(&sa, 0, sizeof(struct sigaction));
	sa.sa_handler = handle_signal;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	/* Parse CLI args */
	for (;;)
	{
		cli_opt = getopt_long(argc, argv, "hi:m:n:p:dvq", cli_long_options, &cli_option_index);

		if (cli_opt == -1)
			break;

		switch (cli_opt)
		{
			case 'h':
				fprintf(stderr, "Options:\n"
				       " -h --help				Display this help\n"
				       " -i --interface <interface>		Sets the interface\n"
				       " -m --netmask <netmask>			Sets the netmask\n"
				       " -n --network <network>			Sets the network\n"
				       " -p --pidfile <pidfile>			Sets the pidfile\n"
				       " -d --daemon				Daemon mode\n"
				       " -v --verbose				Verbose mode\n"
				       " -q --quiet				Quiet mode\n"
				      );
				exit(0);
			case 'i':
				strncpy(interface, optarg, 7);
				interface[7] = 0;
				break;
			case 'n':
				if (inet_pton(AF_INET6, optarg, &network) != 1)
					errx(1, "invalid network address");
				break;
			case 'm':
				network_mask = atoi(optarg);
				if (network_mask < 0 || network_mask > 128)
					errx(1, "netmask must be between 0 and 128");
				break;
			case 'v':
				verbose = 1;
				break;
			case 'q':
				verbose = 0;
				break;
			case 'd':
				daemon_mode = 1;
				break;
			case 'p':
				if ((pidfile = strdup(optarg)) == NULL)
					err(1, "strdup");
				break;
		}
	}

	/* Daemonize if necessary */
	if (daemon_mode)
	{
		if (verbose) fprintf(stderr, "Daemonizing.\n");
		daemonize(pidfile);
	}

	/* Print parameters */
	if (verbose)
	{
		inet_ntop(AF_INET6, &network, network_c, INET6_ADDRSTRLEN);
		fprintf(stderr, "Listening on %s.\n"
		       "Answering for network %s/%d.\n",
		       interface,
		       network_c,
		       network_mask
		      );
	}

	/* Open the socket */
	if ( (sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IPV6))) < 0 )
		err(1, "socket");

	/* Bind to interface */
	if ( setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE , interface, strlen(interface) ) < 0 )
		err(1, "bindtodevice");

	/* Get interface MAC adress */
	memset(&ethreq, 0, sizeof(struct ifreq));
	strncpy(ethreq.ifr_name, interface, IF_NAMESIZE);
	if (ioctl(sock, SIOCGIFHWADDR ,&ethreq) == -1)
		err(1, "ioctl");
	memcpy(interface_mac, ethreq.ifr_hwaddr.sa_data, ETH_ALEN);

	/* Get interface ifindex */
	memset(&ethreq, 0, sizeof(struct ifreq));
	strncpy(ethreq.ifr_name, interface, IF_NAMESIZE);
	if (ioctl(sock, SIOCGIFINDEX ,&ethreq) == -1)
		err(1, "ioctl");
	interface_index = ethreq.ifr_ifindex;

	/* Set the network card in promiscuous mode */
	memset(&ethreq, 0, sizeof(struct ifreq));
	strncpy(ethreq.ifr_name, interface, IF_NAMESIZE);
	if (ioctl(sock, SIOCGIFFLAGS, &ethreq) == -1)
		err(1, "ioctl");
	ethreq.ifr_flags |= IFF_PROMISC;
	if (ioctl(sock, SIOCSIFFLAGS, &ethreq) == -1)
		err(1, "ioctl");

	/* Attach the filter to the socket */
	if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter))<0)
		err(1, "setsockopt");
 
	while (1)
	{
		/* Receive a packet */
		if ((nbytes = recv(sock, in_buffer, PACKET_BUFFER_SIZE, 0)) < 0)
			err(1, "recv");

		/* Decode ICMP */
		icmp6_ns = (struct icmp6_ns *)in_buffer;
		/* Decode ICMP Option if present */
		if (ntohs(icmp6_ns->ip.ip6_plen) > sizeof(struct nd_neighbor_solicit))
			icmp6_ns_opt = (struct icmp6_ns_opt *)(icmp6_ns + 1);
		else
			icmp6_ns_opt = NULL;

		/* Extract needed values */
		target = &icmp6_ns->ns.nd_ns_target;
		client_ip = &icmp6_ns->ip.ip6_src;
		client_mac = (unsigned char *)((icmp6_ns_opt != NULL) ? &icmp6_ns_opt->lla : &icmp6_ns->eth.h_source);

		/* Print a resume */
		inet_ntop(AF_INET6, target, target_c, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, client_ip, client_ip_c, INET6_ADDRSTRLEN);
		ether_ntoa_r((const struct ether_addr *) icmp6_ns->eth.h_source, srcmac_c);
		ether_ntoa_r((const struct ether_addr *) icmp6_ns->eth.h_dest, dstmac_c);
		if (verbose) fprintf(stderr, "%s > %s : Network Solicitation for target %s from %s", srcmac_c, dstmac_c, target_c, client_ip_c);
		if (icmp6_ns_opt != NULL)
		{
			ether_ntoa_r((const struct ether_addr *) client_mac, client_mac_c);
			if (verbose) fprintf(stderr, " (LLA: %s)", client_mac_c);
		}

		/* If it matches the subnet */
		if (ipv6_match(target, &network, network_mask) == 1)
		{
			/* Prepare the answer */
			nbytes = forge_icmp6_na(out_buffer, interface_mac, client_mac, target, client_ip, target, interface_mac);

			/* Send it */
			memset(&addr, 0, sizeof(struct sockaddr_ll));
			addr.sll_family = AF_PACKET;
			addr.sll_ifindex = interface_index;
			addr.sll_halen = ETH_ALEN; 
			memcpy(&addr.sll_addr, client_mac, ETH_ALEN);

			if (sendto(sock, out_buffer, nbytes, 0, (const struct sockaddr *)&addr, sizeof(struct sockaddr_ll)) < 0)
				err(1, "sendto");
			
			if (verbose) fprintf(stderr, " [Answered]");
		}
		
		if (verbose) fprintf(stderr, "\n");
	}
}


/* 
 * Functions
 */

#ifdef DEBUG
void print_hex(unsigned char *data, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
	{
		if (!(i % 8)) fprintf(stderr, "  ");
		if (!(i % 16)) fprintf(stderr, "\n");

		fprintf(stderr, "%02x ", data[i]);
	}

	fprintf(stderr, "\n");
}
#endif

uint16_t icmp6_cksum(unsigned char *icmp_packet, size_t len, struct in6_addr* src, struct in6_addr* dst)
{
	uint16_t *data;
	uint32_t cksum;
	int i;

	data = (uint16_t *)icmp_packet;
	cksum = 0;

	/* Sum fake header */
	for (i = 0; i < 8; i++)
	{
		cksum += src->s6_addr16[i];
		cksum += (cksum < src->s6_addr16[i]) ? 1 : 0;
		cksum += dst->s6_addr16[i];
		cksum += (cksum < dst->s6_addr16[i]) ? 1 : 0;
	}

	cksum += htonl((uint32_t) len);
	cksum += (cksum < len) ? 1 : 0;
	cksum += htonl((uint32_t) IPPROTO_ICMPV6);
	cksum += (cksum < IPPROTO_ICMPV6) ? 1 : 0;

	/* Sum data */
	while (len > 1)
	{
		cksum += *data;
		cksum += (cksum < *data) ? 1 : 0;

		data++;
		len -= sizeof(uint16_t);
	}

	if (len)
	{
		cksum += htonl((uint16_t)(*(uint8_t *)data) << 8);
		cksum += (cksum < ((*(uint8_t *)data) << 8)) ? 1 : 0;
	}

	/* Fold sum */
	cksum = (cksum & 0xffff) + (cksum >> 16);
	cksum = (cksum & 0xffff) + (cksum >> 16);

	return (uint16_t)(~cksum);
}

int forge_icmp6_na (unsigned char *buffer, unsigned char *srcmac, unsigned char *dstmac, struct in6_addr *srcip, struct in6_addr *dstip, struct in6_addr *target, unsigned char *lla)
{

	struct packet {
		struct ethhdr eth;
		struct ip6_hdr ip;
		struct nd_neighbor_advert na;
		struct nd_opt_hdr na_opt;
		unsigned char na_opt_lla[ETH_ALEN];
	} __attribute__((__packed__)) packet;

	/* lla */
	memcpy(&packet.na_opt_lla, lla, ETH_ALEN);

	/* Neighbor Advertisement Option (source link layer address) */
	packet.na_opt.nd_opt_type = 2;
	packet.na_opt.nd_opt_len = 1;

	/* Neighbor Advertisement */
	packet.na.nd_na_type = ND_NEIGHBOR_ADVERT;
	packet.na.nd_na_code = 0;
	packet.na.nd_na_cksum = 0;
	packet.na.nd_na_flags_reserved = ND_NA_FLAG_SOLICITED | ND_NA_FLAG_OVERRIDE | ND_NA_FLAG_ROUTER;
	memcpy(&packet.na.nd_na_target, target, sizeof(struct in6_addr));

	packet.na.nd_na_cksum = icmp6_cksum((unsigned char *)&packet.na, sizeof(struct packet) - sizeof(struct ethhdr) - sizeof(struct ip6_hdr), srcip, dstip);

	/* IPv6 */
	packet.ip.ip6_flow = htonl(0x60000000);
	packet.ip.ip6_plen = htons(sizeof(struct nd_neighbor_advert) + sizeof(struct nd_opt_hdr) + ETH_ALEN);
	packet.ip.ip6_nxt = IPPROTO_ICMPV6; 
	packet.ip.ip6_hlim = 0xFF;
	memcpy(&packet.ip.ip6_src, srcip, sizeof(struct in6_addr));
	memcpy(&packet.ip.ip6_dst, dstip, sizeof(struct in6_addr));
	
	/* Ethernet */
	memcpy(&packet.eth.h_dest, dstmac, ETH_ALEN);
	memcpy(&packet.eth.h_source, srcmac, ETH_ALEN);
	packet.eth.h_proto = htons(ETH_P_IPV6);

	memcpy(buffer, &packet, sizeof(struct packet));

	return sizeof(struct packet); 
}

int ipv6_match(struct in6_addr *a, struct in6_addr *b, int len)
{
	struct in6_addr mask;
	int i;

	/* Create a mask of the right length */
	memset(&mask, 0x00, sizeof(struct in6_addr));
	memset(&mask, 0xFF, len / 8);
	mask.s6_addr[len / 8] = 0xFF << (8 - len % 8);

	/* Compare addresses using mask */
	for (i = 0; i < 4; i++)
	{
		if ((a->s6_addr32[i] & mask.s6_addr32[i]) != (b->s6_addr32[i] & mask.s6_addr32[i])) return 0; 
	}

	return 1;
}


void daemonize(char *pidfile)
{
	FILE *pidfile_h;				/* PID File handle */
	pid_t pid;

	/* First fork */
	pid = fork();
	if (pid < 0) err(1, "first fork");
	if (pid > 0) exit(0);

	/* Get a clean environment */
	if (setsid() < 0) err(1, "setsid");
	if (chdir("/") < 0) err(1, "chdir");
	umask(0);

	/* Since we are not suppose to output anything, disable standard files */
	freopen( "/dev/null", "r", stdin);
	freopen( "/dev/null", "w", stdout);
	freopen( "/dev/null", "w", stderr);

	/* Second fork */
	pid = fork();
	if (pid < 0) err(1, "second fork");
	if (pid > 0) exit(0);

	/* Write PID in pidfile */
	pid = getpid();

	if ((pidfile_h = fopen(pidfile, "w+")) == NULL)
		err(1, "fopen");
	if (fprintf(pidfile_h, "%d", pid) < 0)
		err(1, "fprintf");
	if (fclose(pidfile_h) == EOF)
		err(1, "fclose");
}


void handle_signal(int signal)
{
	if (verbose)
		fprintf(stderr, "Signal %d received. Exiting.\n", signal);

	if (unlink(pidfile) < 0) 
		err(1, "unlink");

	exit(0);
}
