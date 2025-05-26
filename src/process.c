#include "../include/basset.h"

void print_ethernet_header(const unsigned char *buffer, FILE *capture_file) {
  struct ethhdr *eth = (struct ethhdr *)(buffer);
  fprintf(capture_file, "\nEthernet Header\n");
  fprintf(capture_file,
          "\t|-Source Address	: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",
          eth->h_source[0], eth->h_source[1], eth->h_source[2],
          eth->h_source[3], eth->h_source[4], eth->h_source[5]);
  fprintf(capture_file,
          "\t|-Destination Address	: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",
          eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3],
          eth->h_dest[4], eth->h_dest[5]);
  fprintf(capture_file, "\t|-Protocol		: 0x%.4X\n",
          ntohs(eth->h_proto));
}

void print_ip_header(const unsigned char *buffer, FILE *capture_file) {
  struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
  // iphdrlen = ip->ihl * 4;
  static struct sockaddr_in source;
  static struct sockaddr_in dest;
  memset(&source, 0, sizeof(source));
  source.sin_addr.s_addr = ip->saddr;
  memset(&dest, 0, sizeof(dest));
  dest.sin_addr.s_addr = ip->daddr;

  fprintf(capture_file, "\nIP Header\n");

  fprintf(capture_file, "\t|-Version              : %d\n",
          (unsigned int)ip->version);
  fprintf(capture_file, "\t|-Internet Header Length  : %d DWORDS or %d Bytes\n",
          (unsigned int)ip->ihl, ((unsigned int)(ip->ihl)) * 4);
  fprintf(capture_file, "\t|-Type Of Service   : %d\n", (unsigned int)ip->tos);
  fprintf(capture_file, "\t|-Total Length      : %d  Bytes\n",
          ntohs(ip->tot_len));
  fprintf(capture_file, "\t|-Identification    : %d\n", ntohs(ip->id));
  fprintf(capture_file, "\t|-Time To Live	    : %d\n",
          (unsigned int)ip->ttl);
  fprintf(capture_file, "\t|-Protocol 	    : %d\n",
          (unsigned int)ip->protocol);
  fprintf(capture_file, "\t|-Header Checksum   : %d\n", ntohs(ip->check));
  fprintf(capture_file, "\t|-Source IP         : %s\n",
          inet_ntoa(source.sin_addr));
  fprintf(capture_file, "\t|-Destination IP    : %s\n",
          inet_ntoa(dest.sin_addr));
}

void print_payload(const unsigned char *buffer, int buflen, int iphdrlen,
                   FILE *capture_file) {
  const unsigned char *data =
      (buffer + iphdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr));
  fprintf(capture_file, "\nData\n");
  int remaining_data =
      buflen - (iphdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr));
  for (int i = 0; i < remaining_data; i++) {
    fprintf(capture_file, " %.2X ", data[i]);
  }

  fprintf(capture_file, "\n");
}

void print_tcp_header(const unsigned char *buffer, int buflen, int iphdrlen,
                      FILE *capture_file) {
  fprintf(
      capture_file,
      "\n*************************TCP Packet******************************");
  print_ethernet_header(buffer, capture_file);
  print_ip_header(buffer, capture_file);

  struct tcphdr *tcp =
      (struct tcphdr *)(buffer + iphdrlen + sizeof(struct ethhdr));
  fprintf(capture_file, "\nTCP Header\n");
  fprintf(capture_file, "\t|-Source Port          : %u\n", ntohs(tcp->source));
  fprintf(capture_file, "\t|-Destination Port     : %u\n", ntohs(tcp->dest));
  // The server and client both choose a pseudo-random number called the Initial
  // Sequence Number, which is then increased by the number of bytes
  // transmitted in further packets to allow for reliable packet ordering.
  fprintf(capture_file, "\t|-Sequence Number      : %u\n", ntohl(tcp->seq));
  // The ACK number tells us the byte number of the last received data byte
  fprintf(capture_file, "\t|-Acknowledge Number   : %u\n", ntohl(tcp->ack_seq));
  // The minimum TCP header length is 5 DWORDS (20 bytes), with anything larger
  // being due to included options
  fprintf(capture_file, "\t|-Header Length        : %d DWORDS or %d BYTES\n",
          (unsigned int)tcp->doff, (unsigned int)tcp->doff * 4);
  fprintf(capture_file, "\t|----------Flags-----------\n");
  // The urgent flag indicates that the data being sent should be prioritized
  // over data without the flag. This flag is not often used
  fprintf(capture_file, "\t\t|-Urgent Flag          : %d\n",
          (unsigned int)tcp->urg);
  // The ACK flag dictates whether the other side of the connection should
  // concern itself with the ACK number (1) or ignore it (0)
  fprintf(capture_file, "\t\t|-Acknowledgement Flag : %d\n",
          (unsigned int)tcp->ack);
  // The PSH flag indicates that the data should be sent immediately rather
  // than adding it to a buffer
  fprintf(capture_file, "\t\t|-Push Flag            : %d\n",
          (unsigned int)tcp->psh);
  // The RST flag tells the other side to cleanup resources and close the
  // connection immediately, often used when errors occur.
  // Equivalent to telling someone to stop speaking mid-sentence
  fprintf(capture_file, "\t\t|-Reset Flag           : %d\n",
          (unsigned int)tcp->rst);
  // The SYN flag indicates that we are starting the handshake process
  fprintf(capture_file, "\t\t|-Synchronise Flag     : %d\n",
          (unsigned int)tcp->syn);
  // The FIN flag tells the receiver that all data has been sent and that the
  // connection may be closed
  // Equivalent to telling someone goodbye when a conversation has concluded
  // A proper connection shutdown will have a FIN-ACK-FIN handshake
  fprintf(capture_file, "\t\t|-Finish Flag          : %d\n",
          (unsigned int)tcp->fin);
  // The WND flag indicates the amount of data capable of being received at the time.
  // The window size changes throughout the connection to best optimize data transmission without overwhelming the receiver  
  fprintf(capture_file, "\t|-Window size          : %d\n", ntohs(tcp->window));
  fprintf(capture_file, "\t|-Checksum             : %d\n", ntohs(tcp->check));
  // The urgent pointer indicates where the urgent data ends
  fprintf(capture_file, "\t|-Urgent Pointer       : %d\n", tcp->urg_ptr);

  print_payload(buffer, buflen, iphdrlen, capture_file);

  fprintf(capture_file,
          "***********************************************************"
          "******\n\n\n");
}

void print_udp_header(const unsigned char *buffer, int buflen, int iphdrlen,
                      FILE *capture_file) {
  fprintf(
      capture_file,
      "\n*************************UDP Packet******************************");
  print_ethernet_header(buffer, capture_file);
  print_ip_header(buffer, capture_file);
  fprintf(capture_file, "\nUDP Header\n");

  struct udphdr *udp =
      (struct udphdr *)(buffer + iphdrlen + sizeof(struct ethhdr));
  fprintf(capture_file, "\t|-Source Port    	: %d\n", ntohs(udp->source));
  fprintf(capture_file, "\t|-Destination Port	: %d\n", ntohs(udp->dest));
  fprintf(capture_file, "\t|-UDP Length      	: %d\n", ntohs(udp->len));
  fprintf(capture_file, "\t|-UDP Checksum   	: %d\n", ntohs(udp->check));

  print_payload(buffer, buflen, iphdrlen, capture_file);

  fprintf(capture_file,
          "***********************************************************"
          "******\n\n\n");
}

void process_packet(unsigned char *buffer, const int buflen, FILE *capture_file,
                    struct captured_packets *captured_packets_count) {
  struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
  // Each protocol is associated with a number in /etc/protocols
  int iphdrlen = 0;
  switch (ip->protocol) {
  case TCP_CODE:
    ++captured_packets_count->tcp;
    print_tcp_header(buffer, buflen, iphdrlen, capture_file);
    break;
  case UDP_CODE:
    ++captured_packets_count->udp;
    print_udp_header(buffer, buflen, iphdrlen, capture_file);
    break;
  default:
    ++captured_packets_count->other;
  }
}
