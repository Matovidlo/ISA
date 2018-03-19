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

#ifndef THREAD
#define THREAD
#include "testovac.hpp"
#include "service.hpp"
#include "ipv6.hpp"

class Socket_thread;

// struct which pass to service of ICMP messages
struct Send_struct {
  Socket_thread *node = NULL;
  pid_t pid;

  Send_struct(Socket_thread *, pid_t);
  ~Send_struct();
};

class Socket_thread final {
private:
  int packet_size;        // in Bytes -s param 56B ICMP or UDP 64B
  double loss_interval;   // in seconds -t param
  int send_interval;      // in ms -i param
  double wait_interval;   // in seconds -w param
  int udp_port;           // specification of UDP port
  int listen_port;        // specification of listening UDP port
  double round_value;        // specification of RTT -r param

  // save of value -w when no message recieved set value back to -w value
  // else is used value 2 times RTT value.
  double wait_interval_save;

  std::vector<std::string> node_options;
  unsigned current_option = 0;
  bool flags[3] = {false, false, false};
  bool is_ipv6 = false;
  // IPV4
  int client_socket = -1;
  int node;
  // for ICMP
  struct sockaddr_in peer_addr;
  struct hostent *peer;
  struct sockaddr_storage node_address;
  socklen_t peer_addr_len;

  // IPV6 ICMP and IPv4 ICMP
  struct icmpv6_hdr *icmp6_header;
  struct icmphdr icmp4_header;
  struct sockaddr_in6 *peer_addr6;
  const char *address;
  struct addrinfo *results = nullptr;

  // stats
  uint64_t number_packet_loss = 0;
  uint64_t all_packets = 0;
  uint64_t number_packet_exceeded = 0;

  /* methods */
  void set_size();
  // create socket based on addrinfo structure
  bool initialize_socket();
  bool fill_ipv4(struct addrinfo *);
  // based on getaddrinfo creates ipv6 or ipv4 connection, address.
  // Starts thread for service
  bool create_node_connection(struct addrinfo );

  /*****************************************/
  /* those two methods are in file ipv6.cc */
  /*****************************************/
  bool fill_udp_ipv6(const char *, int);
  bool fill_icmp_ipv6(const char *, int);
public:
  void show_attributes();
  // evaluate stastics after -t time
  void evaluate();
  // hour statistics with vector of all Round trip times
  void hour_stats(std::vector<uint64_t> *);

  // checks wether node has correct IPv4 or IPv6 address or is hostname
  bool add_node(std::string);
  // based on input parameters change value in attributes
  bool add_type(int, double);

  bool get_ipversion();
  bool get_verbose();
  bool get_icmp();
  double get_loss_interval();
  int get_packet_size();
  int get_send_interval();
  double get_wait_interval();
  double get_round_value();
  int get_socket(int);
  socklen_t get_addr_len();
  struct sockaddr_in get_addr();
  struct sockaddr_in6 *get_addr6();
  std::string get_node();
  struct icmphdr get_icmphdr();

  void increase_packet_loss();
  void increase_packet();
  void increase_packet_exceeded();
  // Round trip time was exceeded, increase packet exceeded when is true;
  bool RTT_check(uint64_t, double);
  void set_wait_rtt(uint64_t);
  void set_no_recieve_wait();

  bool start_thread(int);
  // -i timer
  void start_send_timer();
  /*  calls start_thread for all nodes and -l parameter, allocate resources
      dealocates all threads after finished work */
  int set_connections();
  // set timestamp for UDP datagram
  char *set_timestamp(int);
  Socket_thread();
  ~Socket_thread();
};


#endif