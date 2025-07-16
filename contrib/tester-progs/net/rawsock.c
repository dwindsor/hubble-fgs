#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/in.h>

#define PACKET_RAW_LOOP 1
#define PACKET_DGRAM_IP 2
#define INET_RAW_UDP 3
#define INET_RAW_RAW 4
#define PACKET_RAW_ALL 5
#define PACKET_DGRAM_ALL 6

int main(int argc, char *argv[])
{
	int testNum;
	int fd;

	if (argc < 2)
		return 1;
	testNum = atoi(argv[1]);

	switch(testNum) {
	case PACKET_RAW_LOOP:
		fd = socket(AF_PACKET, SOCK_RAW, ETH_P_LOOP);
		break;
	case PACKET_DGRAM_IP:
		fd = socket(AF_PACKET, SOCK_DGRAM, ETH_P_IP);
		break;
	case INET_RAW_UDP:
		fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
		break;
	case INET_RAW_RAW:
		fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
		break;
	case PACKET_RAW_ALL:
		fd = socket(AF_PACKET, SOCK_RAW, ETH_P_ALL);
		break;
	case PACKET_DGRAM_ALL:
		fd = socket(AF_PACKET, SOCK_DGRAM, ETH_P_ALL);
		break;
	default:
		return 2;
	}

	if (fd < 0)
		return 3;

	printf("FD: %d\n", fd);

	close(fd);
	sleep(1);

	return 0;
}

