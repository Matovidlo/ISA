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
#include "service.hpp"

bool exiting = true;
extern pthread_mutex_t lock;
extern pthread_mutex_t evaluate_lock;
extern Socket_thread *main_thread;

/* attach to -l thread */
void *listen_on(void *arg) {
  // set all necessary for listen
  Socket_thread *node = (Socket_thread *)arg;
  int length = node->get_packet_size();
  int c_socket = node->get_socket(0);
  struct sockaddr_in6* peer = node->get_addr6();
  socklen_t sock_len = node->get_addr_len();
  double wait_seconds = node->get_wait_interval();
  char *recv = NULL;
  fd_set rd_flg;
  struct timeval timeout;

  int seconds = (int)wait_seconds;
  wait_seconds = (wait_seconds - seconds) * 1000.0;
  timeout.tv_sec = seconds;
  timeout.tv_usec = wait_seconds;

  while(_check_exiting()) {
    if (recv == NULL) {
      recv = new char[65];
      memset(recv, 0, 65);
    }
    /* set select read flag to recieve only state for c_socket in -l thread */
    fcntl(c_socket, F_GETFL, 0);
    FD_ZERO(&rd_flg);
    FD_SET(c_socket, &rd_flg);
    int ready = select(c_socket + 1, &rd_flg, NULL, (fd_set *)0, &timeout);
    if (ready){
      length = recvfrom(c_socket, recv, length, MSG_PEEK | MSG_TRUNC,
                        (struct sockaddr *)peer, &sock_len);
    } else if (ready == 0)
      continue;
    else {
      std::cerr << "Error listen select!" << std::endl;
    }
    recv[length] = '\0';
    if (length < 0) {
      std::cerr << "recvfrom fail!\n";
    }
    if (recv != NULL) {
      delete[]recv;
      recv = NULL;
    }
    recv = new char[length + 1];
    memset(recv, 0, length);
    length = recvfrom(c_socket, recv, length, 0,
                      (struct sockaddr *)peer, &sock_len);
    recv[length] = '\0';

    sendto(c_socket, recv, length, 0,
          (struct sockaddr *)peer, sock_len);
    if (recv != NULL) {
      delete []recv;
      recv = NULL;
    }
  }
  if (recv != NULL) {
    delete []recv;
    recv = NULL;
  }
  if (c_socket)
    close(c_socket);
  return arg;
}

/* service of node, send and receive packet and raise count */
void *node_service(void *arg) {
  // get all necessary information to send and recv packet
  Socket_thread *node = (Socket_thread *)arg;

  bool ipv6 = node->get_ipversion();
  std::chrono::high_resolution_clock::time_point start = std::chrono::high_resolution_clock::now();
  // get all intervals to evaluate
  std::vector<uint64_t> *times_stamps = new std::vector<uint64_t>;
  std::chrono::high_resolution_clock::time_point duration_loss;
  int loss_interval = node->get_loss_interval();
  bool is_icmp = node->get_icmp();
  double rtt_e_value = node->get_round_value();

  char *recv_buffer = NULL;
  unsigned p_size = node->get_packet_size();
  int saved_loss_time = loss_interval;
  uint64_t diff_time;

  if (!is_icmp) {
    // icmp threads 4, 6
    if (!ipv6) {
      if (!node->start_thread(3)) {
        std::cerr << "Couldn't create sender thread!" << std::endl;
        delete times_stamps;
        return arg;
      }
    } else {
      if (!node->start_thread(4)) {
        std::cerr << "Couldn't create sender thread!" << std::endl;
        delete times_stamps;
        return arg;
      }
    }
  } else {
    // udp threads 4, 6
    if (!ipv6) {
      if (!node->start_thread(5)) {
        std::cerr << "Couldn't create sender thread!" << std::endl;
        delete times_stamps;
        return arg;
      }
    } else {
      if (!node->start_thread(6)) {
        std::cerr << "Couldn't create sender thread!" << std::endl;
        delete times_stamps;
        return arg;
      }
    }
  }

  // loop for recieve messages, extract timestamp and verbose print/ statistics
  while (_check_exiting()){
    recv_buffer = NULL;
    duration_loss = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>( duration_loss - start ).count();
    // -t param
    if (duration >= loss_interval) {
      loss_interval += saved_loss_time;
      if (!node->start_thread(2)) {
        std::cerr << "Couldn't create -t thread!" << std::endl;
        delete times_stamps;
        return arg;
      }
    }
    // print hour statistics
    if (duration >= 3600) {
      loss_interval = saved_loss_time;
      start = std::chrono::high_resolution_clock::now();
      node->hour_stats(times_stamps);
      times_stamps->clear();
    }
    // recieve packet by options
    if (!is_icmp) {
      if (!ipv6) {
        int retval;
        if ((retval = recv_icmp4(node, &recv_buffer, &diff_time)) == 0) {
          pthread_mutex_lock(&lock);
          node->increase_packet_loss();
          pthread_mutex_unlock(&lock);
          if (recv_buffer != NULL){
            delete []recv_buffer;
            recv_buffer = NULL;
          }
          continue;
        } else if(retval == 2) {
          continue;
        }
      } else {
        int retval;
        if ((retval = recv_icmp6(node, &recv_buffer,&diff_time)) == 0) {
          if (recv_buffer != NULL){
            delete []recv_buffer;
            recv_buffer = NULL;
          }
          node->increase_packet_loss();
          continue;
        } else if (retval == 2) {
          continue;
        }
      }
    } else {

      if (ipv6) {
        if (!recv_udp6(node, &recv_buffer)) {
          if (recv_buffer != NULL){
            delete []recv_buffer;
            recv_buffer = NULL;
          }
          node->increase_packet_loss();
          continue;
        }
      } else {
        if (!recv_udp4(node, &recv_buffer)) {
          if (recv_buffer != NULL){
            delete []recv_buffer;
            recv_buffer = NULL;
          }
          node->increase_packet_loss();
          continue;
        }
      }
    }
    // not received well
    if (!_check_exiting()) {
      delete []recv_buffer;
      break;
    }
    // parse timestamp from UDP 4,6 Packet
    struct timeval time_st, timestamp;
    // UDP packet timeval
    if (is_icmp) {
      gettimeofday(&time_st, (struct timezone *) NULL);
      memcpy(&timestamp, &recv_buffer[0], sizeof(struct timeval));
      diff_time = (((time_st.tv_sec - timestamp.tv_sec) * 1000000) + time_st.tv_usec - timestamp.tv_usec);// 1000.0;
      if (node->RTT_check(diff_time, rtt_e_value)) {
        if (node->get_verbose()) {
          pthread_mutex_lock(&lock);
          std::cout << "Packet exceeded" << std::endl;
          pthread_mutex_unlock(&lock);
        }
        delete []recv_buffer;
        continue;
      }
    }
    // set new -w 2*rtt
    // push timestamp to dynamic alocated vector on heap
    times_stamps->push_back(diff_time);
    node->set_wait_rtt(diff_time);
    if (node->get_verbose()) {
      if (recv_buffer != NULL) {
        verbose_print(p_size, node, diff_time);
      }
    }
    if (recv_buffer != NULL){
      delete []recv_buffer;
      recv_buffer = NULL;
    }
  }
  delete times_stamps;
  int c_socket = node->get_socket(0);
  if (c_socket)
    close(c_socket);
  return arg;
}
/* Statistic -t thread */
void *node_stats(void *arg) {
  Socket_thread *node = (Socket_thread *) arg;
  pthread_mutex_lock(&evaluate_lock);
  node->evaluate();
  pthread_mutex_unlock(&evaluate_lock);
  delete node;
  pthread_exit(NULL);
}
/* ICMPv4 sender thread */
void *node_sendicmp4(void *arg) {

  struct Send_struct *node_struct = (struct Send_struct *)arg;
  Socket_thread *node = node_struct->node;
  int c_socket = node->get_socket(0);
  socklen_t length = node->get_addr_len();
  unsigned p_size = node->get_packet_size();
  char *buf_tmp = NULL;
  int seq = 0;


  while(_check_exiting()) {
    // -i interval of message IPv4
    struct sockaddr_in addr = node->get_addr();
    // set timestamp
    node->start_send_timer();
    buf_tmp = icmp_timestamp(node, p_size + 24, seq++, node_struct->pid);
    if (buf_tmp == NULL){
      std::cerr << "FAIL" << std::endl;
      return arg;
    }
    if (sendto(c_socket, buf_tmp, p_size + 16, 0,
        (struct sockaddr *) &addr, length) < 0) {
    }
    if (buf_tmp != NULL) {
      delete []buf_tmp;
      buf_tmp = NULL;
    }
  }
  if (buf_tmp != NULL) {
    delete []buf_tmp;
    buf_tmp = NULL;
  }
  close(c_socket);
  delete (node_struct);
  pthread_exit(NULL);
}
/* ICMPv6 sender thread */
void *node_sendicmp6(void *arg) {
  struct Send_struct *node_struct = (struct Send_struct *) arg;
  Socket_thread *node = node_struct->node;
  int c_socket = node->get_socket(0);
  socklen_t length = node->get_addr_len();
  unsigned p_size = node->get_packet_size();
  char *buf_tmp = NULL;
  // -i interval of message IPv6
  struct sockaddr_in6 *addr = node->get_addr6();
  int seq = 0;

  while (_check_exiting()) {
    // set ICMPv6 timestamp
    node->start_send_timer();
    buf_tmp = icmp6_timestamp(p_size + 24, seq++, node_struct->pid);
    if (buf_tmp == NULL){
      std::cerr << "FAIL" << std::endl;
      return arg;
    }
    send_ip6_packet(c_socket, buf_tmp, addr, length, p_size + 16);
    if (buf_tmp != NULL) {
      delete []buf_tmp;
      buf_tmp = NULL;
    }
  }

  if (buf_tmp != NULL) {
    delete []buf_tmp;
    buf_tmp = NULL;
  }
  close(c_socket);
  delete node_struct;
  pthread_exit(NULL);
}

void *node_sendudp6(void *arg) {
  struct Send_struct *node_struct = (struct Send_struct *) arg;

  Socket_thread *node = node_struct->node;
  int c_socket = node->get_socket(0);
  socklen_t length = node->get_addr_len();
  unsigned p_size = node->get_packet_size();
  char *buf_tmp = NULL;
  // -i interval of message IPv6
  struct sockaddr_in6 *addr = node->get_addr6();

  while (_check_exiting()) {
    // set UDP6 timestamp
    node->start_send_timer();
    buf_tmp = node->set_timestamp(p_size);
    if (buf_tmp == NULL){
      std::cerr << "FAIL" << std::endl;
      return arg;
    }
    send_ip6_packet(c_socket, buf_tmp, addr, length, p_size);
    if (buf_tmp != NULL) {
      delete []buf_tmp;
      buf_tmp = NULL;
    }
  }

  if (buf_tmp != NULL) {
    delete []buf_tmp;
    buf_tmp = NULL;
  }
  close(c_socket);
  delete node_struct;
  pthread_exit(NULL);
}

void *node_sendudp4(void *arg) {
  struct Send_struct *node_struct = (struct Send_struct *) arg;

  Socket_thread *node = node_struct->node;
  int c_socket = node->get_socket(0);
  socklen_t length = node->get_addr_len();
  unsigned p_size = node->get_packet_size();
  char *buf_tmp = NULL;
  // -i interval of message IPv4
  struct sockaddr_in addr = node->get_addr();

  while (_check_exiting()) {
    // set UDP4 timestamp
    node->start_send_timer();
    buf_tmp = node->set_timestamp(p_size);
    if (sendto(c_socket, buf_tmp, p_size, 0,
            (struct sockaddr *) &addr, length) < 0){
      //std::cerr << "Error sending packet IPv4!\n";
    }
    if (buf_tmp == NULL){
      std::cerr << "FAIL" << std::endl;
      return arg;
    }

    if (buf_tmp != NULL) {
      delete []buf_tmp;
      buf_tmp = NULL;
    }
  }

  if (buf_tmp != NULL) {
    delete []buf_tmp;
    buf_tmp = NULL;
  }
  close(c_socket);
  delete node_struct;
  pthread_exit(NULL);
}


struct addrinfo *get_ipaddr(std::string node) {
  int serv;
  struct addrinfo hints;
  struct addrinfo *results;
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
  hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
  hints.ai_flags = 0;
  hints.ai_protocol = 0;          /* Any protocol */

  /* IPv4 and IPv6 resolve */
  if ((serv = getaddrinfo (node.c_str(), NULL, &hints, &results)) != 0) {
    std::cerr << "getaddrinfo: " << gai_strerror(serv) << "\n";
    return NULL;
  }
  return results;
}
// -v parameter
void verbose_print(int size, Socket_thread *node, uint64_t timestamp) {
  /* initialize all necessary things*/
  time_t rawtime;
  struct tm * timeinfo;
  char buffer [256];
  timeval curTime;
  std::string ip_ad = node->get_node();
  struct addrinfo *results = get_ipaddr(ip_ad);

  // get date anad time
  gettimeofday(&curTime, NULL);
  time(&rawtime);
  timeinfo = localtime(&rawtime);
  int milli = curTime.tv_usec / 10000;
  strftime(buffer, 256, "%F %T", timeinfo);
  sprintf(buffer, "%s.%02d ", buffer, milli);

  // print packet
  pthread_mutex_lock(&lock);
  std::cout << buffer << size << " bytes from " << ip_ad << " (" << std::flush;
  print_ips(results);
  std::cout << ") " << "time=" << std::flush;
  printf("%.03f ms\n", timestamp / 1000.0);
  pthread_mutex_unlock(&lock);
  freeaddrinfo(results);
}

int check_timeout(int c_socket, int seconds, int msec) {
  fd_set rd_flg;
  struct timeval timeout;

  FD_ZERO(&rd_flg);
  FD_SET(c_socket, &rd_flg);
  timeout.tv_sec = seconds;
  timeout.tv_usec = msec;
  // wait -w timeout
  int ready = select(c_socket + 1, &rd_flg, NULL, NULL, &timeout);
  return ready;
}

void send_ip6_packet(int socket, char *buffer, struct sockaddr_in6 *addr, socklen_t length, unsigned p_size) {
  pthread_mutex_lock(&lock);
  if (sendto(socket, buffer, p_size, 0,
            (struct sockaddr *) addr, length) < 0){
    //std::cerr << "Error sending packet IPv6!\n";
  }
  pthread_mutex_unlock(&lock);
}
/*******************************************************/
/******** UDP6/4 ICMPv4/v6 reciever functions **********/
/*******************************************************/
bool recv_udp6(Socket_thread *node, char **recv_buffer) {
  int c_socket = node->get_socket(0);
  socklen_t length = node->get_addr_len();
  unsigned p_size = node->get_packet_size();
  char *buf_tmp = new char [p_size];
  int i_value = node->get_send_interval();
  // -i interval of message IPv6
  double wait_seconds = node->get_wait_interval();

  struct sockaddr_in6 *addr = node->get_addr6();
  struct in6_addr sent = addr->sin6_addr;

  node->increase_packet();
  // cut double value
  int seconds = wait_seconds + ((double)i_value / 1000.0);
  int milis = (((double)(i_value / 1000.0) + wait_seconds) - seconds) * 1000000;
  int ready = check_timeout(c_socket, seconds, milis);
  if (ready) {
    long long int recieved;
    if ((recieved = recvfrom (c_socket, buf_tmp, p_size, 0,
                          (struct sockaddr *) addr, &length)) < 0) {
      std::cerr << "Error recieving packet UDPv6!\n";
    }
    // size does not match, fail
    if (p_size != recieved) {
      delete []buf_tmp;
      return false;
    }
    // timeout expires
  } else if (ready != -1) {
    node->set_no_recieve_wait();
    delete []buf_tmp;
    return false;
  }
  /* IPv6 */
  char ipv6_sendip[INET6_ADDRSTRLEN];
  char ipv6_givenip[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, &addr->sin6_addr, ipv6_givenip, INET6_ADDRSTRLEN);
  inet_ntop(AF_INET6, &sent, ipv6_sendip, INET6_ADDRSTRLEN);
  if (strcmp(ipv6_sendip, ipv6_givenip)){
    delete []buf_tmp;
    return false;
  }

  *recv_buffer = buf_tmp;
  return true;
}

bool recv_udp4(Socket_thread *node, char **recv_buffer) {
  int c_socket = node->get_socket(0);
  socklen_t length = node->get_addr_len();
  unsigned p_size = node->get_packet_size();
  char *buf_tmp = new char[p_size];
  int i_value = node->get_send_interval();
  // -i interval of message IPv4
  double wait_seconds = node->get_wait_interval();
  struct sockaddr_in addr = node->get_addr();
  struct in_addr sent = addr.sin_addr;

  // set timestamp
  node->increase_packet();

  int seconds = wait_seconds + ((double)i_value / 1000.0);
  int milis = (((double)(i_value / 1000.0) + wait_seconds) - seconds) * 1000000;
  int ready = check_timeout(c_socket, seconds, milis);

  if (ready) {
    long long int recieved;
    if ((recieved = recvfrom (c_socket, buf_tmp, p_size, 0,
                          (struct sockaddr *) &addr, &length)) < 0) {
      std::cerr << "Error recieving packet UDPv4!\n";
    }
    if (p_size != recieved) {
      delete[] buf_tmp;
      return false;
    }
  }
  else if (ready != -1) {
    node->set_no_recieve_wait();
    delete []buf_tmp;
    return false;
  }
  if (sent.s_addr != addr.sin_addr.s_addr){
    delete []buf_tmp;
    return false;
  }

  *recv_buffer = buf_tmp;
  return true;
}

int recv_icmp4(Socket_thread *node, char **recv_buffer, uint64_t *diff_time) {
  int c_socket = node->get_socket(0);
  socklen_t length = node->get_addr_len();
  unsigned p_size = node->get_packet_size();
  char *buf_tmp = new char [p_size + 24];
  memset(buf_tmp, 0, p_size + 24);
  int i_value = node->get_send_interval();
  // -i interval of message IPv4
  double wait_seconds = node->get_wait_interval();
  double rtt_e_value = node->get_round_value();
  struct sockaddr_in addr = node->get_addr();
  struct sockaddr_in sent = node->get_addr();

  // receiver
  while(_check_exiting()) {
    *diff_time = 0;

    int seconds = wait_seconds + ((double)i_value / 1000.0);
    int milis = (((double)(i_value / 1000.0) + wait_seconds) - seconds) * 1000000;
    int ready = check_timeout(c_socket, seconds, milis);
    if (ready) {
      long long int recieved;
      if ((recieved = recvfrom (c_socket, buf_tmp, p_size + 16, 0,
                            (struct sockaddr *) &addr, &length)) < 0) {
        // std::cerr << "Error recieving packet ICMPv4!\n";
      }
      // size of message does not match recieved size
      if (p_size != (recieved - 16)) {
        continue;
      }
      struct timeval time_st, timestamp;
      struct ip *ip = (struct ip*) buf_tmp;
      size_t hdr_len = ip->ip_hl << 2;

      gettimeofday(&time_st, (struct timezone *) NULL);
      memcpy(&timestamp, &(buf_tmp + hdr_len + sizeof(struct icmphdr))[0], sizeof(struct timeval));
      *diff_time = (((time_st.tv_sec - timestamp.tv_sec) * 1000000) + time_st.tv_usec - timestamp.tv_usec);// 1000.0;

    } else if (ready == -1) {
      std::cerr << "Error select()"<< std::endl;
      delete []buf_tmp;
      return 10;
    } else {
      // set value back to -w
      node->set_no_recieve_wait();
      delete []buf_tmp;
      return 0;
    }
    if (sent.sin_addr.s_addr != addr.sin_addr.s_addr){
      continue;
    }
    if (parse_icmp4(buf_tmp, p_size + 16, syscall(SYS_gettid))) {
      // delete []buf_tmp;
      continue;
    } else {
      break;
    }
  }
  node->increase_packet();
  // check RTT value
  if (node->RTT_check(*diff_time, rtt_e_value)) {
    if (node->get_verbose()) {
      pthread_mutex_lock(&lock);
      std::cout << "Packet exceeded" << std::endl;
      pthread_mutex_unlock(&lock);
    }
    delete []buf_tmp;
    return 2;
  }
  *recv_buffer = buf_tmp;
  return 1;
}

int recv_icmp6(Socket_thread *node, char **recv_buffer, uint64_t *diff_time) {
  int c_socket = node->get_socket(0);
  socklen_t length = node->get_addr_len();
  unsigned p_size = node->get_packet_size();
  char *buf_tmp = new char [p_size + 24];
  int i_value = node->get_send_interval();
  // -i interval of message IPv6
  double wait_seconds = node->get_wait_interval();
  double rtt_e_value = node->get_round_value();
  struct sockaddr_in6 *addr = node->get_addr6();
  struct in6_addr sent = addr->sin6_addr;
  /* IPv6 */
  char ipv6_sendip[INET6_ADDRSTRLEN];
  char ipv6_givenip[INET6_ADDRSTRLEN];
  // receiver
  while(_check_exiting()) {
    *diff_time = 0;

    int seconds = wait_seconds + ((double)i_value / 1000.0);
    int milis = (((double)(i_value / 1000.0) + wait_seconds) - seconds) * 1000000;
    int ready = check_timeout(c_socket, seconds, milis);

    if (ready) {
      long long int recieved;
      pthread_mutex_lock(&lock);
      if ((recieved = recvfrom (c_socket, buf_tmp, p_size + 16, 0,
                              (struct sockaddr *) addr, &length)) < 0) {
        std::cerr << "Error recieving packet ICMPv6!\n";
      }
      pthread_mutex_unlock(&lock);
      // get addresses
      inet_ntop(AF_INET6, &addr->sin6_addr, ipv6_givenip, INET6_ADDRSTRLEN);
      inet_ntop(AF_INET6, &sent, ipv6_sendip, INET6_ADDRSTRLEN);
      if (p_size != (recieved - 16)) {
        continue;
      }
      struct timeval time_st, timestamp;

      gettimeofday(&time_st, (struct timezone *) NULL);
      memcpy(&timestamp, &(buf_tmp + sizeof(struct icmphdr))[0], sizeof(struct timeval));
      *diff_time = (((time_st.tv_sec - timestamp.tv_sec) * 1000000) + time_st.tv_usec - timestamp.tv_usec);// 1000.0;
    } else if (ready != -1) {
      node->set_no_recieve_wait();
      delete []buf_tmp;
      return false;
    }
    if (strcmp(ipv6_sendip, ipv6_givenip)){
      continue;
    }
    if (parse_icmp6(buf_tmp, p_size + 16, syscall(SYS_gettid))) {
      continue;
    } else {
      break;
    }
  }
  node->increase_packet();

  if (node->RTT_check(*diff_time, rtt_e_value)) {
    if (node->get_verbose()) {
      pthread_mutex_lock(&lock);
      std::cout << "Packet exceeded" << std::endl;
      pthread_mutex_unlock(&lock);
    }
    delete []buf_tmp;
    return 2;
  }

  *recv_buffer = buf_tmp;
  return true;
}

char *print_ips(struct addrinfo *lst) {
  /* IPv4 */
  char ipv4_ip[INET_ADDRSTRLEN];
  struct sockaddr_in *addr4;
  /* IPv6 */
  char ipv6_ip[INET6_ADDRSTRLEN];
  struct sockaddr_in6 *addr6;

  for (; lst != NULL; lst = lst->ai_next) {
    if (lst->ai_addr->sa_family == AF_INET) {
      addr4 = (struct sockaddr_in *) lst->ai_addr;
      inet_ntop(AF_INET, &addr4->sin_addr, ipv4_ip, INET_ADDRSTRLEN);
      std::cout << ipv4_ip << std::flush;
      break;
    }
    else if (lst->ai_addr->sa_family == AF_INET6) {
      addr6 = (struct sockaddr_in6 *) lst->ai_addr;
      inet_ntop(AF_INET6, &addr6->sin6_addr, ipv6_ip, INET6_ADDRSTRLEN);
      std::cout << ipv6_ip << std::flush;
      break;
    }
  }
  return NULL;
}

char *icmp_timestamp(Socket_thread *node, unsigned p_size, int seq, pid_t pid) {
  struct icmphdr header = node->get_icmphdr();
  memset(&header, 0, sizeof(struct icmphdr));
  char *data = new char[p_size];
  std::string buf = "\0";
  // fill header with timestamp
  header.type = ICMP_ECHO;
  header.code = 0;
  header.un.echo.id = htons(pid);
  header.un.echo.sequence = seq;

  memset(data, 0, p_size);
  memcpy(data, &header, sizeof(struct icmphdr));
  struct timeval originate;
  gettimeofday(&originate, (struct timezone *)NULL);

  memcpy(data + sizeof(struct icmphdr), &originate, sizeof (struct timeval));
  unsigned u = 0;
  for (; u < p_size - 32; ++u) {
    buf += u;
  }
  memcpy(data + sizeof(struct icmphdr) + sizeof(struct timeval), buf.data(), buf.length());
  ((struct icmphdr *) data)->checksum = in_cksum((unsigned short *)data, p_size);
  return data;
}

char *icmp6_timestamp(unsigned p_size, int seq, pid_t pid) {
  struct timeval originate;
  gettimeofday(&originate, (struct timezone *)NULL);
  struct icmp6_hdr header;
  memset(&header, 0, sizeof(struct icmphdr));
  char *data = new char[p_size];
  std::string buf = "\0";
  // fill header with timestamp
  header.icmp6_type = ICMP6_ECHO_REQUEST;
  header.icmp6_code = 0;
  header.icmp6_id = htons(pid);
  header.icmp6_seq = seq;

  memset(data, 0, p_size);
  memcpy(data, &header, sizeof(struct icmp6_hdr));
  memcpy(data + sizeof(struct icmp6_hdr), &originate, sizeof (struct timeval));
  unsigned u = 0;
  for (; u < p_size - 32; ++u) {
    buf += u;
  }
  memcpy(data + sizeof(struct icmp6_hdr) + sizeof(struct timeval), buf.data(), buf.length());
  ((struct icmp6_hdr *) data)->icmp6_cksum = in_cksum((unsigned short *)data, p_size);
  return data;
}

// returns wether ICMP packet is for our process
bool parse_icmp4(char *buffer, int size, pid_t pid) {
  (void)size;

  struct ip *ip = (struct ip*) buffer;
  size_t hlen = ip->ip_hl << 2;
  struct icmphdr *icmp = (struct icmphdr *)(buffer + hlen);

  if (icmp->type == ICMP_ECHOREPLY && ntohs(icmp->un.echo.id) == pid) {
    return false;
  }

  return true;
}
// returns wether ICMPv6 packet is for our process
bool parse_icmp6(char *buffer, int size, pid_t pid) {
  (void) size;

  struct icmp6_hdr *icmp = (struct icmp6_hdr *)(buffer);
  if (icmp->icmp6_type == ICMP6_ECHO_REPLY && ntohs(icmp->icmp6_id) == pid) {
    return false;
  }
  return true;
}

// signal handler
void signal_handler(int signum) {
  pthread_mutex_lock(&lock);
  exiting = false;
  pthread_mutex_unlock(&lock);
  (void)signum;
}
// check when signal SIGINT was recieved
bool _check_exiting() {
  bool tmp;
  pthread_mutex_lock(&lock);
  tmp = exiting;
  pthread_mutex_unlock(&lock);
  return tmp;
}