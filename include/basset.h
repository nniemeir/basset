#ifndef BASSET_H
#define BASSET_H
#include <arpa/inet.h>
#include <errno.h>
#include <libnn.h>
#include <linux/if_packet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define BUFFER_SIZE 65536
#define SIGNAL_MAX 15
#define TCP_CODE 6
#define UDP_CODE 17

struct captured_packets {
  int tcp;
  int udp;
  int other;
};

void process_packet(unsigned char *buffer, const int buflen, FILE *capture_file,
                    struct captured_packets *captured_packets_count);
#endif