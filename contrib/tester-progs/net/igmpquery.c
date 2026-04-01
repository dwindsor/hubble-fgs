#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <linux/types.h>
#include <libnet.h>
#include <netinet/igmp.h>
#include <netinet/ip.h>

void usage()
{
	printf("igmpquery <version> <if>\n\n");
	printf("version = 1 | 2 | 3\n");
	printf("if = name of network interface\n");
	exit(1);
}

int main (int argc, char *argv[])
{
	uint8_t igmp_data[4] = {0, 1, 0, 0};
	uint8_t ip_opt[2] = {IPOPT_RA, 4};
	char err[LIBNET_ERRBUF_SIZE];
	uint32_t payload_size = 0;
	uint8_t *payload = NULL;
	libnet_ptag_t ptag;
	uint8_t code = 0;
	uint32_t saddr;
	libnet_t *ctx;
	int version;
	char *iface;

	if (argc != 3) usage();
	version = atoi(argv[1]);
	if (version < 1 || version > 3) usage();
	iface = argv[2];

	if (version > 1)
		code = 1;
	if (version == 3) {
		payload = igmp_data;
		payload_size = sizeof(igmp_data);
	}

	ctx = libnet_init(LIBNET_RAW4, iface, err);
	if (!ctx) {
		printf("libnet_init: %s\n", err);
		exit(2);
	}

	ptag = libnet_build_igmp(
			0x11,		// type
			code,		// code
			0,		// checksum
			0,		// group IP addr 0.0.0.0
			payload,	// ptr to packet data or NULL
			payload_size,	// payload length
			ctx,		// libnet context
			0);		// no existing ptag
	if (ptag < 0) {
		printf("libnet_build_igmp: %s\n", libnet_geterror(ctx));
		exit(2);
	}

	ptag = libnet_build_ipv4_options(
			ip_opt,		// options
			sizeof(ip_opt),	// size
			ctx,		// libnet context
			0);		// no existing ptag
	if (ptag < 0) {
		printf("libnet_build_ipv4_options: %s\n", libnet_geterror(ctx));
		exit(2);
	}

	saddr = libnet_get_ipaddr4(ctx);

	ptag = libnet_build_ipv4(
			LIBNET_IPV4_H + LIBNET_IGMP_H,	// length
			0,				// TOS
			getpid(),			// IP ID
			IP_DF,				// don't fragment
			1,				// TTL
			IPPROTO_IGMP,			// protocol
			0,				// checksum
			saddr,				// saddr
			htonl(0xE0000001),		// daddr
			0,				// raw packet payload
			0,				// raw packet payload length
			ctx,				// libnet context
			0);				// no existing ptag
	if (ptag < 0) {
		printf("libnet_build_ipv4: %s\n", libnet_geterror(ctx));
		exit(2);
	}

	if (libnet_write(ctx) < 0) {
		printf("libnet_write: %s\n", libnet_geterror(ctx));
		exit(2);
	}

	printf("Success\n");

	libnet_diag_dump_pblock(ctx);
	libnet_destroy(ctx);

	return 0;
}

