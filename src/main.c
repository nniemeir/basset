#include "../include/basset.h"
#include <libnn.h>

const char *program_name = "basset";
int log_to_file = 0;
int filter_protocol = 0;
int packets_to_capture = -1;
static int sock_fd;
static char *interface = NULL;

void handler(int signal_num) {
  char signal_name[SIGNAL_MAX];
  switch (signal_num) {
  case SIGINT:
    snprintf(signal_name, SIGNAL_MAX, "SIGINT");
    break;
  case SIGTERM:
    snprintf(signal_name, SIGNAL_MAX, "SIGTERM");
    break;
  default:
    snprintf(signal_name, SIGNAL_MAX, "Unknown signal");
    break;
  };
  printf("\n");
  char signal_msg[LOG_MAX];
  snprintf(signal_msg, LOG_MAX, "%s given, closing socket", signal_name);
  log_event(program_name, INFO, signal_msg, log_to_file);
}

void process_args(int argc, char *argv[]) {
  char errmsg[LOG_MAX];
  int c;
  while ((c = getopt(argc, argv, "hi:ln:p:")) != -1) {
    switch (c) {
    case 'h':
      printf("Usage: basset [options]\n");
      printf("Options:\n");
      printf("  -h               Show this help message\n");
      printf("  -i               Specify interface to bind to\n");
      printf("  -l               Save logs to file\n");
      printf("  -n               Specify number of packets to capture\n");
      printf("  -p               Filter for a specific protocol\n");
      exit(EXIT_SUCCESS);
    case 'i':
      interface = optarg;
      break;
    case 'l':
      log_to_file = 1;
      break;
    case 'n':
      log_to_file = 1;
      packets_to_capture = atoi(optarg);
      break;
    case 'p':
      if (!strcmp(optarg, "tcp")) {
        filter_protocol = 1;
        break;
      }
      if (!strcmp(optarg, "udp")) {
        filter_protocol = 2;
        break;
      }
      log_event(program_name, ERROR, "Unknown protocol", log_to_file);
      break;
    case '?':
      snprintf(errmsg, LOG_MAX,
               "Unknown option '-%c'. Run with -h for options.", optopt);
      log_event(program_name, ERROR, errmsg, log_to_file);
      exit(EXIT_FAILURE);
    }
  }
}

int main(int argc, char *argv[]) {
  process_args(argc, argv);

  // Only the root user can open raw sockets
  if (geteuid() != 0) {
    log_event(program_name, FATAL, "Basset must be run as root", log_to_file);
    exit(EXIT_FAILURE);
  }

  // sigaction listens for SIGINT (sent by Ctrl+C) for the duration of the
  // process's lifetime
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handler;
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

  int saddr_len;
  int buflen;

  unsigned char *buffer = (unsigned char *)malloc(BUFFER_SIZE);
  if (!buffer) {
    log_event(program_name, FATAL, "Failed to allocate memory for buffer",
              log_to_file);
    exit(EXIT_FAILURE);
  }
  memset(buffer, 0, BUFFER_SIZE);

  sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (sock_fd == -1) {
    printf("Failed to initialize socket.\n");
    exit(EXIT_FAILURE);
  }
  char start_msg[LOG_MAX];
  snprintf(start_msg, LOG_MAX, "Starting capture");
  log_event(program_name, INFO, start_msg, log_to_file);
  struct sockaddr saddr;

  if (interface) {
    if (setsockopt(sock_fd, SOL_SOCKET, SO_BINDTODEVICE, interface,
                   sizeof(interface)) < 0) {
      log_event(program_name, FATAL, "Failed to bind to device", log_to_file);
      close(sock_fd);
      return EXIT_FAILURE;
    }
  }

  FILE *capture_file = fopen("capture", "a");
  if (!capture_file) {
    log_event(program_name, FATAL, "Failed to open capture file", log_to_file);
    exit(EXIT_FAILURE);
  }
  bool capturing = true;
  struct captured_packets captured_packets_count = {0, 0, 0};
  while (capturing) {
    if (packets_to_capture == 0) {
      capturing = false;
      break;
    }
    saddr_len = sizeof saddr;
    buflen = recvfrom(sock_fd, buffer, BUFFER_SIZE, 0, &saddr,
                      (socklen_t *)&saddr_len);

    if (buflen == -1) {
      if (errno == EINTR) {
        break;
      }
      log_event(program_name, FATAL, "Error in reading from socket",
                log_to_file);
      exit(EXIT_FAILURE);
    }
    if (fflush(capture_file) == EOF) {
      log_event(program_name, ERROR, "Failed to flush output stream",
                log_to_file);
    }

    process_packet(buffer, buflen, capture_file, &captured_packets_count);
  }
  close(sock_fd);
  char totals_msg[LOG_MAX];
  snprintf(totals_msg, LOG_MAX, "%d TCP, %d UDP, and %d other packets captured",
           captured_packets_count.tcp, captured_packets_count.udp,
           captured_packets_count.other);
  log_event(program_name, INFO, totals_msg, log_to_file);
  free(buffer);
  fclose(capture_file);
  exit(EXIT_SUCCESS);
}