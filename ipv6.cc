/**********************************/
/***** Martin Vaško xvasko12  *****/
/****  FIT VUTBR 3.BIT->3.BIB  ****/
/*******  ISA -> 1.project  *******/
/**** stats of packet loss RTT ****/
/** Date of creation = 28.9.2017 **/
/* Makefile usage = make,make all,*/
/***** make pack, make clean  *****/
/*   project- traffic monitoring  */
/* sends http requests to server  */
/**********           *************/
/*                                */
/**   Using BSD sockets, parse,  **/
/***    strftime, timestamps    ***/
/****    Parse_param class     ****/
/*****     Socket class       *****/
/**********************************/
#include "ipv6.hpp"

bool Socket_thread::fill_udp_ipv6(const char *addr, int type) {
  is_ipv6 = true;
  int status;
  // set peer 6 address
  peer_addr6 = (struct sockaddr_in6 *) &node_address;
  peer_addr_len = sizeof(node_address);
  memset(peer_addr6, 0, sizeof(*peer_addr6));
  if (type == 0) {
    if ((status = inet_pton (AF_INET6, addr, (void *)&peer_addr6->sin6_addr)) == -1) {
      std::cerr << "Failed to perform inet_pton on UDP datagram!\n";
      return false;
    }
  }
  peer_addr6->sin6_family = AF_INET6;
  peer_addr6->sin6_flowinfo = 0;

  if (this->udp_port != 0)
    peer_addr6->sin6_port = htons(udp_port);

  if (this->flags[0]) {
    if (type == 0) {
      client_socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
      if (client_socket == -1) {
        std::cerr << "Could not create socket!\n";
        return false;
      }
    }
  }
  return true;
}

bool Socket_thread::fill_icmp_ipv6(const char *addr, int type) {
  // fill peer 6 address with IPv6 address inet_pton
  is_ipv6 = true;
  int status;
  peer_addr6 = (struct sockaddr_in6 *) &node_address;
  peer_addr_len = sizeof(node_address);
  memset(peer_addr6, 0, sizeof(*peer_addr6));

  if ((status = inet_pton (AF_INET6, addr, &peer_addr6->sin6_addr)) == -1) {
    std::cerr << "Failed to perform inet_pton on ICMP packet!\n";
    return false;
  }
  // use SOCK_RAW for ICMP
  if (!this->flags[0]) {
    if (type == 0) {
      client_socket = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
      if (client_socket == -1) {
        std::cerr << "Could not create socket!\n";
        return false;
      }
    }
  }
  peer_addr6->sin6_family = AF_INET6;
  peer_addr6->sin6_flowinfo = 0;
  return true;
}

// Computing the internet checksum (RFC 1071).
// Note that the internet checksum does not preclude collisions.
/* checksum()
 * Calculating ICMP checksum.
 */
 //http://www.cs.cmu.edu/afs/cs/academic/class/15213-f00/unpv12e/libfree/in_cksum.c
unsigned short in_cksum(unsigned short *addr, int len)
{
  int       nleft = len;
  int       sum = 0;
  unsigned short  *w = addr;
  unsigned short  answer = 0;
  /*
   * Our algorithm is simple, using a 32 bit accumulator (sum), we add
   * sequential 16 bit words to it, and at the end, fold back all the
   * carry bits from the top 16 bits into the lower 16 bits.
   */
  while (nleft > 1)  {
    sum += *w++;
    nleft -= 2;
  }
    /* 4mop up an odd byte, if necessary */
  if (nleft == 1) {
    *(unsigned char *)(&answer) = *(unsigned char *)w ;
    sum += answer;
  }

    /* 4add back carry outs from top 16 bits to low 16 bits */
  sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
  sum += (sum >> 16);     /* add carry */
  answer = ~sum;        /* truncate to 16 bits */
  return(answer);
}