/****************************************************************************
 * sping.cc
 *
 *   Copyright (c) 2017 Yoshinori Sugino
 *   This software is released under the MIT License.
 ****************************************************************************/
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in_systm.h>
#include <netinet/ip_icmp.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>

namespace {

/*
 * Header:  8 bytes
 *  0             7 8            15 16                           31
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |     Code      |           Checksum            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          Identifier           |        Sequence Number        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
constexpr const int kPingHeaderLength = ICMP_MINLEN;  /* 8 bytes */
constexpr const int kPingDataLength = 64 - kPingHeaderLength;

constexpr const int kIPHeaderMaxLengthIPv4 = 60;
constexpr const int kICMPTimestampLength = ICMP_TSLEN;

constexpr const int kICMPMessageLength = kPingHeaderLength + kPingDataLength;
constexpr const int kMessageLength = kIPHeaderMaxLengthIPv4 + kICMPTimestampLength + kPingDataLength;

enum class status_t : uint8_t {
  kSuccess,
  kPermissionFailure,
  kTimeOutFailure,
  kOtherFailure,
  kUnknown
};

struct PingData {
  int socket_fd;
  char *host_name;
  std::shared_ptr<char> official_name;
  struct sockaddr_in addr_to;
  struct sockaddr_in addr_from;
  std::unique_ptr<unsigned char[]> msg;
  size_t ip_hlen;
};

/*
 * RFC 1071
 * the 16-bit checksum calculated as the 1's complement of the 1's complement sum.
 */
unsigned short checksum(unsigned short *buf, unsigned int len) {
  unsigned long sum;

  for (sum = 0; len > 1; len -= 2) {
    sum += *(unsigned short *)buf++;
  }

  /*  Add left-over byte, if any */
  if (len == 1) {
    sum += *(unsigned char *)buf;
  }

  /*  Fold 32-bit sum to 16 bits */
  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  return ~sum;
}

status_t socket_init(int *fd) {
  struct protoent *proto;

  proto = getprotobyname("icmp");
  if (!proto) {
    return status_t::kOtherFailure;
  }

  *fd = socket(AF_INET, SOCK_RAW, proto->p_proto);
  if (*fd < 0) {
    if (errno == EPERM || errno == EACCES) {
      return status_t::kPermissionFailure;
    } else {
      return status_t::kOtherFailure;
    }
  }

  return  status_t::kSuccess;
}

std::shared_ptr<char> mystrdup(char *str) {
  /* Unlike std::unique_ptr, the deleter of std::shared_ptr is invoked even if the managed pointer is null. */
  return std::shared_ptr<char>(strdup(str), [](char *str) -> void {
    if (str) {
      std::free(str);
    }
  });
}

status_t dest_init(struct PingData *data) {
  int ret;
  struct addrinfo hints, *res;

  memset (&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_flags  = AI_CANONNAME;

  ret = getaddrinfo(data->host_name, nullptr, &hints, &res);
  if (ret) return status_t::kOtherFailure;

  memcpy(&data->addr_to, res->ai_addr, res->ai_addrlen);
  data->official_name = mystrdup(res->ai_canonname);

  freeaddrinfo(res);

  if (!data->official_name) return status_t::kOtherFailure;

  return status_t::kSuccess;
}

status_t msg_init(struct PingData *data) {
  data->msg = std::unique_ptr<unsigned char[]>(new unsigned char[kMessageLength * sizeof(unsigned char)]);
  if (!data->msg) {
    return status_t::kOtherFailure;
  }

  return status_t::kSuccess;
}

status_t init(struct PingData *data) {
  status_t st;

  st = socket_init(&data->socket_fd);
  if (st != status_t::kSuccess) return st;

  st = dest_init(data);
  if (st != status_t::kSuccess) return st;

  st = msg_init(data);
  if (st != status_t::kSuccess) return st;

  return status_t::kSuccess;
}

/* Note: consider strict aliasing rules */
void setup_msg(unsigned char *msg) {
  struct icmphdr hdr;
  struct timeval tv;

  hdr.type             = ICMP_ECHO;
  hdr.code             = 0;
  hdr.checksum         = 0;
  hdr.un.echo.id       = htons(getpid() & 0xFFFF);
  hdr.un.echo.sequence = htons(0);
  memcpy(msg, &hdr, sizeof(hdr));

  (void)gettimeofday(&tv, nullptr);
  memcpy((unsigned char *)msg + sizeof(hdr), &tv, sizeof(tv));

  hdr.checksum = checksum((unsigned short *)msg, kICMPMessageLength);
  memcpy(msg, &hdr, sizeof(hdr));
}

status_t send(struct PingData *data) {
  ssize_t length;

  setup_msg(data->msg.get());
  data->ip_hlen = 0;

  /* send an ICMP message: ICMP header + ICMP payload */
  length = sendto(data->socket_fd, (char *)data->msg.get(), kICMPMessageLength, 0, (struct sockaddr *)&data->addr_to, sizeof(struct sockaddr_in));
  if (length  < 0) {
    return status_t::kOtherFailure;
  }

  return status_t::kSuccess;
}

/* Note: consider strict aliasing rules */
status_t decode_msg(unsigned char *msg, size_t *hlen, unsigned int length) {
  struct iphdr ip_header;

  memcpy(&ip_header, msg, sizeof(ip_header));
  *hlen = ip_header.ihl * 4;

  if (checksum((unsigned short *)((unsigned char *)msg + *hlen), length - *hlen) != 0) return status_t::kOtherFailure;

  return status_t::kSuccess;
}

status_t recv(struct PingData *data) {
  int ret;
  fd_set fdset;
  struct timeval timeout;
  socklen_t fromlen;

retry:
  memset(&timeout, 0, sizeof(timeout));

  timeout.tv_sec  = 1;
  timeout.tv_usec = 0;

  FD_ZERO(&fdset);
  FD_SET(data->socket_fd, &fdset);

  ret = select(data->socket_fd + 1, &fdset, nullptr, nullptr, &timeout);
  if (ret < 0) {
    if (errno == EINTR) goto retry;
    return status_t::kOtherFailure;
  }

  if (ret != 1) {
    return status_t::kTimeOutFailure;
  }

  fromlen = sizeof(data->addr_from);
  ret = recvfrom(data->socket_fd, (char *)data->msg.get(), kMessageLength, 0, (struct sockaddr *)&data->addr_from, &fromlen);
  if (ret < 0) return status_t::kOtherFailure;

  if (decode_msg(data->msg.get(), &data->ip_hlen, ret) != status_t::kSuccess) return status_t::kOtherFailure;

  return status_t::kSuccess;
}

/* tv1 = tv1 - tv2 */
void sub_timeval(struct timeval *tv1, struct timeval *tv2) {
  if (tv1->tv_usec -= tv2->tv_usec < 0) {
    tv1->tv_usec += 1000000;
    tv1->tv_sec  -= 1;
  }

  tv1->tv_sec -= tv2->tv_sec;
}

inline double timeval2msec(const struct timeval &tv) {
  return (double)tv.tv_sec * 1000.0 + (double)tv.tv_usec / 1000.0;
}

void show_result (struct PingData *data) {
  struct timeval tv_now, tv_sent;

  (void)gettimeofday(&tv_now, nullptr);

  memcpy(&tv_sent, (unsigned char *)data->msg.get() + data->ip_hlen + sizeof(struct icmphdr), sizeof(struct timeval));

  sub_timeval(&tv_now, &tv_sent);

  printf("name: %s\n", data->official_name.get());
  printf("time=%.3f ms\n", timeval2msec(tv_now));
}

}  // namespace

int main(int argc, char *argv[]) {
  status_t st;
  struct PingData data;

  if (argc != 2) {
    printf("error\n");
  }

  data.host_name = argv[1];

  st = init(&data);
  if (st != status_t::kSuccess) goto error;

  st = send(&data);
  if (st != status_t::kSuccess) goto error;

  st = recv(&data);
  if (st != status_t::kSuccess) goto error;

  show_result(&data);

  return EXIT_SUCCESS;

error:
  printf("ERROR\n");
  return EXIT_FAILURE;
}

