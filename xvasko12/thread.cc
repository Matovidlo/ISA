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
#include "thread.hpp"

// global variable
pthread_t thread_id[16384];
pthread_mutex_t lock;
pthread_mutex_t evaluate_lock;
int cnt_thread = 1;

Socket_thread::Socket_thread(): packet_size(-1),
                                loss_interval(300.0),  // seconds
                                send_interval(100), // ms
                                wait_interval(2.0),   // seconds
                                udp_port(0),
                                listen_port(0),
                                round_value(-1),
                                wait_interval_save(2.0),
                                number_packet_loss(0),
                                number_packet_exceeded(0){}

Socket_thread::~Socket_thread(){
}

void Socket_thread::show_attributes() {
  if (flags[0])
    std::cout << "*UDP packet*\n\n";
  else
    std::cout << "*ICMP packet*\n\n";
  std::cout << "packet_size: " << packet_size << "\n"
            << "loss_interval: " << loss_interval << "\n"
            << "send_interval: " << send_interval << "\n"
            << "wait_interval: " << wait_interval << "\n"
            << "udp_port: " << udp_port << "\n"
            << "listen_port: " << listen_port << "\n"
            << "round_value: " << round_value << "\n"
            << "address: " << address << "\n"
            << "nodes: \n" << std::endl
            << "<b>pid_t:</b> "<< syscall(SYS_gettid) << std::flush;
  for (unsigned i = 0; i < node_options.size(); ++i) {
    std::cout << node_options[i] << "\n";
  }
  std::cout << "flags: \n";
  for (unsigned i = 0; i < 2; ++i) {
    std::cout << flags[i] << "\n";
  }
  std::cout << "For stastistics: " << std::endl;
  std::cout << "packet loss: " << number_packet_loss << std::endl;
  std::cout << "all packets sent: " << all_packets << std::endl;
}

void Socket_thread::evaluate() {
  if (number_packet_loss == 0 && number_packet_exceeded == 0) {
    if (!flags[1])
      return;
  }
  time_t rawtime;
  struct tm * timeinfo;
  char buffer [256];
  timeval curTime;
  pthread_mutex_lock(&lock);
  std::string ip_ad = this->get_node();
  struct addrinfo *results = get_ipaddr(ip_ad);
  pthread_mutex_unlock(&lock);

  gettimeofday(&curTime, NULL);
  time(&rawtime);
  timeinfo = localtime(&rawtime);
  int milli = curTime.tv_usec / 10000;
  strftime(buffer, 256, "%F %T", timeinfo);
  sprintf(buffer, "%s.%02d ", buffer, milli);
  // when all exceeded dont print this stats
  if (number_packet_exceeded != all_packets) {
    if (number_packet_loss == all_packets) {
      pthread_mutex_lock(&lock);
      std::cout << buffer << ip_ad << ": status down" << std::endl;
      pthread_mutex_unlock(&lock);
    } else {
      double avarage = (double)number_packet_loss / (double)all_packets;
      pthread_mutex_lock(&lock);
      std::cout << buffer << ip_ad << ": " << std::flush;
      printf("%.03f%%", avarage);
      std::cout << " packet loss, " << number_packet_loss << " packet lost" << std::endl;
      pthread_mutex_unlock(&lock);
    }
  }
  if (number_packet_exceeded == 0){
    freeaddrinfo(results);
    return;
  }
  if (round_value >= 0) {
    double avarage = (double)number_packet_exceeded / (double)all_packets;
    pthread_mutex_lock(&lock);
    std::cout << buffer << ip_ad << ": " << std::flush;
    printf("%.03f%% (%ld)", avarage, number_packet_exceeded);
    std::cout << " packets exceeded RTT threshold " << round_value << "ms" << std::endl;
    pthread_mutex_unlock(&lock);
  }
  freeaddrinfo(results);
}

void Socket_thread::hour_stats(std::vector<uint64_t> *timestamps) {
  time_t rawtime;
  struct tm * timeinfo;
  char buffer [256];
  timeval curTime;
  std::string ip_ad = this->get_node();
  struct addrinfo *results = get_ipaddr(ip_ad);

  // Get actual time and print in cool format
  gettimeofday(&curTime, NULL);
  time(&rawtime);
  timeinfo = localtime(&rawtime);
  int milli = curTime.tv_usec / 10000;
  strftime(buffer, 256, "%F %T", timeinfo);
  sprintf(buffer, "%s.%02d ", buffer, milli);

  // min_rtt calculation inside vector
  std::vector<uint64_t>::iterator result = std::min_element(std::begin(*timestamps), std::end(*timestamps));
  auto dist = std::distance(std::begin(*timestamps), result);
  uint64_t rtt = (*timestamps)[dist];
  double min_rtt = (rtt/1000.0);

  // max_rtt calculation inside vector
  result = std::max_element(std::begin(*timestamps), std::end(*timestamps));
  dist = std::distance(std::begin(*timestamps), result);
  uint64_t max_rtt = (*timestamps)[dist];

  // avg_rtt calculation inside vector
  uint64_t sum = std::accumulate(timestamps->begin(), timestamps->end(), 0);
  uint64_t avg_rtt = sum/timestamps->size();

  // mdev_rtt calculation inside vector
  uint64_t sum_mdev = pow(sum / timestamps->size(), 2);
  uint64_t sum_pow_mdev = 0;
  for (unsigned loop = 0; loop < timestamps->size(); ++loop) {
    sum_pow_mdev += (*timestamps)[loop] * (*timestamps)[loop];
  }
  sum_pow_mdev /= timestamps->size();
  uint64_t mdev = sqrt((sum_pow_mdev - sum_mdev));
  if (number_packet_loss == all_packets) {
    pthread_mutex_lock(&lock);
    std::cout << buffer << ip_ad << ": status down" << std::endl;
    pthread_mutex_unlock(&lock);
  } else {
    double avarage = (double)number_packet_loss / (double)all_packets;
    pthread_mutex_lock(&lock);
    std::cout << buffer << ip_ad << ": " << std::flush;
    printf("%.03f%% packet_loss, rtt min/avg/max/mdev %.03f/", avarage, min_rtt);
    printf(" %.03f/%.03f/%.03f ms\n", avg_rtt/1000.0, (double)max_rtt/1000.0, (double)mdev/1000.0);
    pthread_mutex_unlock(&lock);
  }
  freeaddrinfo(results);
}


bool Socket_thread::add_node(std::string argument) {
  struct addrinfo hints;
  struct addrinfo *results;
  int serv;
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
  hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
  hints.ai_flags = 0;
  hints.ai_protocol = 0;          /* Any protocol */

  /* IPv4 and IPv6 resolve */
  if ((serv = getaddrinfo (argument.c_str(), NULL, &hints, &results)) != 0) {
    std::cerr << "Node was not recognised, please enter it corretly!" << std::endl;
    return false;
  }
  this->node_options.push_back(argument);
  freeaddrinfo(results);
  return true;
}
// add attribute by type of option
bool Socket_thread::add_type(int type, double value) {
  switch(type) {
    case 1:
      this->flags[0] = true;
      this->udp_port = value;
      break;
    case 2:
      this->packet_size = value;
      this->flags[2] = true;
      break;
    case 3:
      this->loss_interval = value;
      break;
    case 4:
      this->send_interval = value;
      break;
    case 5:
      this->wait_interval = value;
      this->wait_interval_save = value;
      break;
    case 6:
      break;
    case 7:
      this->listen_port = value;
      break;
    case 8:
      this->round_value = value;
      break;
    case 9:
      this->flags[1] = true;
      break;
    default:
      return false;
  }
  return true;
}

bool Socket_thread::get_ipversion() {
  return is_ipv6;
}

bool Socket_thread::get_verbose() {
  return flags[1];
}

bool Socket_thread::get_icmp() {
  return flags[0];
}

double Socket_thread::get_loss_interval() {
  return loss_interval;
}

int Socket_thread::get_packet_size() {
  return packet_size;
}

int Socket_thread::get_send_interval() {
  return send_interval;
}

double Socket_thread::get_wait_interval() {
  return wait_interval;
}

double Socket_thread::get_round_value() {
  return round_value;
}

int Socket_thread::get_socket(int type) {
  if (type == 0)
    return client_socket;
  else
    return -1;
}

socklen_t Socket_thread::get_addr_len(){
  return peer_addr_len;
}

std::string Socket_thread::get_node() {
  return node_options.back();
}

struct icmphdr Socket_thread::get_icmphdr() {
  return icmp4_header;
}

struct sockaddr_in Socket_thread::get_addr() {
  return peer_addr;
}

struct sockaddr_in6 *Socket_thread::get_addr6() {
  return peer_addr6;
}

void Socket_thread::increase_packet_loss() {
  number_packet_loss++;
}

void Socket_thread::increase_packet() {
  all_packets++;
}

void Socket_thread::increase_packet_exceeded() {
  number_packet_exceeded++;
}
// set -w back to start value, because of no recieved message
void Socket_thread::set_no_recieve_wait() {
  wait_interval = wait_interval_save;
}

void Socket_thread::set_wait_rtt(uint64_t rtt) {
  pthread_mutex_lock(&lock);
  double tmp_value = rtt / 1000.0;
  wait_interval = (2 * tmp_value) / 1000.0;
  pthread_mutex_unlock(&lock);
}
/*  thread composite method, creates thread by given type,
    type == 1, listen thread
    type == 2 statistics thread
    type == 3 ICMP v4 thread sender
    type == 4 ICMP v6 thread sender
    type == 5 UDP v4 thread sender
    type == 6 UDP v6 thread sender
    type == 7 service thread starts */
bool Socket_thread::start_thread(int type) {
  int retval;
  int tmp_cnt;
  // create mutex
  std::string arg;

  Socket_thread *node = new Socket_thread(*this);

  // thread for -l param
  if (type == 1){
    retval = pthread_create(&(thread_id[0]), NULL, listen_on, (void *)node);
    if (retval){
      delete node;
      return false;
    }
    // no nodes
    if (node_options.size() == 0) {
      int s;
      void *res;
      s = pthread_join(thread_id[0], &res);
      if (!s) {
        Socket_thread *node = (Socket_thread *)res;
        delete node;
      }
    }
    return true;
  }
  // thread for statistics
  else if (type == 2) {
    // lock thread creation
    pthread_mutex_lock(&lock);
    retval = pthread_create(&(thread_id[1]), NULL, node_stats, (void *) node);
    pthread_mutex_unlock(&lock);
    if (retval) {
      delete node;
      return false;
    }
    pthread_detach(thread_id[1]);
  }
  //thread for send ICMPv4 packet
  else if (type == 3) {
    struct Send_struct *send = new struct Send_struct(node, syscall(SYS_gettid));
    while(_check_exiting()) {
      pthread_mutex_lock(&lock);
      tmp_cnt = ++cnt_thread;
      retval = pthread_create(&(thread_id[tmp_cnt]), NULL, node_sendicmp4, (void *) send);
      pthread_mutex_unlock(&lock);
      break;
    }

    if (retval) {
      delete send;
      return false;
    }
  }
  //thread for ICMPv6 packet
  else if (type == 4) {
    struct Send_struct *send = new struct Send_struct(node, syscall(SYS_gettid));
    while(_check_exiting()) {
      pthread_mutex_lock(&lock);
      tmp_cnt = ++cnt_thread;
      retval = pthread_create(&(thread_id[tmp_cnt]), NULL, node_sendicmp6, (void *) send);
      pthread_mutex_unlock(&lock);
      break;
    }
    if (retval) {
      delete send;
      return false;
    }
  }
  // thread for service UDP4 datagram
  else if (type == 5) {
    struct Send_struct *send = new struct Send_struct(node, syscall(SYS_gettid));
    while(_check_exiting()) {
      pthread_mutex_lock(&lock);
      tmp_cnt = ++cnt_thread;
      retval = pthread_create(&(thread_id[tmp_cnt]), NULL, node_sendudp4, (void *) send);
      pthread_mutex_unlock(&lock);
      break;
    }
    if (retval) {
      delete send;
      return false;
    }
  }

  // thread for service UDP4 datagram
  else if (type == 6) {
    struct Send_struct *send = new struct Send_struct(node, syscall(SYS_gettid));
    while(_check_exiting()) {
      pthread_mutex_lock(&lock);
      tmp_cnt = ++cnt_thread;
      retval = pthread_create(&(thread_id[tmp_cnt]), NULL, node_sendudp6, (void *) send);
      pthread_mutex_unlock(&lock);
      break;
    }
    if (retval) {
      delete send;
      return false;
    }
  }
  // thread for service node
  else if (type == 7){
    while(_check_exiting()) {
      pthread_mutex_lock(&lock);
      tmp_cnt = ++cnt_thread;
      retval = pthread_create(&(thread_id[tmp_cnt]), NULL, node_service, (void *) node);
      pthread_mutex_unlock(&lock);
      break;
    }
    if (retval) {
      delete node;
      return false;
    }
  }

  return true;
}

void Socket_thread::set_size() {
  // default values when no param -s
  if (!flags[2]) {
    if (flags[0]) {
      packet_size = 64;
    } else {
      packet_size = 56;
    }
  } else {
    // when packet is less than 16, error size is given
    if (flags[0]) {
      if (packet_size <= -1){
        packet_size = -1;
      }
      if (packet_size <= 16)
        packet_size = 16;
    } else {
      if (packet_size <= -1)
        packet_size = -1;
      if (packet_size <= 24)
        packet_size = 24;
    }
  }
}

bool Socket_thread::fill_ipv4(struct addrinfo *rp) {
  is_ipv6 = false;
  bzero((char *) &peer_addr, sizeof(peer_addr));
  peer_addr.sin_family = rp->ai_family;

  bcopy((char *) this->peer->h_addr, (char *)&this->peer_addr.sin_addr.s_addr, this->peer->h_length);
  if (this->udp_port != 0) {
    peer_addr.sin_port = htons(this->udp_port);
  }
  else
    peer_addr.sin_port = htons(rand() % 8000 + 1234);
  return true;
}

bool Socket_thread::create_node_connection(struct addrinfo hints) {
  struct addrinfo *rp;

  address = node_options.back().c_str();
  this->node = getaddrinfo(address, NULL, &hints, &results);
  peer = gethostbyname(address);
  rp = results;
  for (; rp != NULL; rp = rp->ai_next) {
    if (rp->ai_family == AF_INET6) {
      if (this->flags[0]) {
        // UDPv6 datagram
        if (!this->fill_udp_ipv6(address, 0))
          return false;
      } else {
        // ICMPv6 message
        if (!this->fill_icmp_ipv6(address, 0))
          return false;
      }
    } else {
      client_socket = socket(AF_INET, rp->ai_socktype, rp->ai_protocol);
      if (client_socket == -1){
        std::cerr << "Could not create socket!\n";
        return false;
      }
      peer_addr_len = sizeof(peer_addr);
      this->fill_ipv4(rp);
    }
  }
  // start node thread
  if (!this->start_thread(7)) {
    std::cerr << "Could not start node thread!\n";
    return false;
  }
  freeaddrinfo(results);
  return true;
}

bool Socket_thread::initialize_socket() {
  struct addrinfo hints;
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
  hints.ai_flags = hints.ai_flags;
  if (this->flags[0]) {
    hints.ai_protocol = 0;          /* Any protocol */
    hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
  } else {
    hints.ai_socktype = SOCK_RAW; /* ICMP message */
    hints.ai_protocol = IPPROTO_ICMP;
  }
  // get address, get information about port and get hostname
  if (!node_options.empty()) {
    if (!this->create_node_connection(hints)) {
      std::cerr << "Could not assign connection to peer!\n";
      return false;
    }
  }
  return true;
}

void Socket_thread::start_send_timer() {
  int send_interval = this->get_send_interval();
  usleep(send_interval * 1000);
}

bool Socket_thread::RTT_check(uint64_t duration, double rtt_v) {
  if (rtt_v < 0.0)
    return false;
  double tmp = duration/1000.0;
  if (tmp <= rtt_v){
    return false;
  }
  number_packet_exceeded++;
  return true;
}

char *Socket_thread::set_timestamp(int p_size) {
  struct timeval timestamp;
  gettimeofday(&timestamp, NULL);
  char *buffer = new char[p_size];
  memset(buffer, 0, p_size);
  std::string tmp = "\0";
  int generator = p_size - sizeof(struct timeval);
  for (int i = 0; i < generator; ++i){
    tmp += i;
  }
  memcpy(buffer, &timestamp, sizeof(struct timeval));
  memcpy(buffer + sizeof(struct timeval), tmp.data(), generator);

  return buffer;
}


int Socket_thread::set_connections() {
  // set -s size
  this->set_size();
  // 5 means for problem with -s (size) param
  if (packet_size == -1) {
    std::cerr << "Wrong size of UDP or ICMP packet\n";
    return 5;
  }
  signal(SIGINT,signal_handler);
  if (pthread_mutex_init(&lock, NULL) != 0) {
    std::cerr << "mutex failed to initiate!\n";
    return false;
  }
  if (pthread_mutex_init(&evaluate_lock, NULL) != 0) {
    std::cerr << "mutex failed to initiate!\n";
    return false;
  }

  if (listen_port != 0) {
    client_socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    int optval = 0;
    setsockopt(client_socket, SOL_IPV6, IPV6_V6ONLY,  &optval, sizeof(int));

    peer_addr6 = (struct sockaddr_in6 *) &node_address;
    bzero((char *) peer_addr6, sizeof(*peer_addr6));
    peer_addr6->sin6_family = AF_INET6;
    peer_addr6->sin6_addr = in6addr_any;
    peer_addr6->sin6_port = htons(listen_port);
    peer_addr_len = sizeof(*peer_addr6);
    if (bind (client_socket, (struct sockaddr *) peer_addr6, peer_addr_len) < 0) {
      std::cerr << "Could not bind socket to listen!\n";
      return 3;
    }
    // type 1 is for listen function
    if (!this->start_thread(1)) {
      std::cerr << "Could not create -l thread!\n";
      return 4;
    }
  }

  while (!node_options.empty()) {
    if (!this->initialize_socket()) {
      std::cerr << "Could not initialize socket!\n";
      return 2;
    }
    node_options.pop_back();
    if (node_options.empty()) {
      void *res;
      int s;
      // services dealoc of ICMP
      pthread_mutex_lock(&lock);
      int tmp_cnt_thread = cnt_thread;
      pthread_mutex_unlock(&lock);
      if (!flags[0]) {
        for (int j = 2; j <= tmp_cnt_thread; ++j) {
          s = pthread_join(thread_id[j], &res);
          if (!s) {
            Socket_thread *node = (Socket_thread *)res;
            delete node;
          }
        }
      } else {
        // service dealoc of UDP

        for (int j = 2; j <= tmp_cnt_thread; ++j) {
          s = pthread_join(thread_id[j], &res);
          if (!s) {
            Socket_thread *node = (Socket_thread *)res;
            delete node;
          }
        }
      }

      // -l thread dealoc
      if (listen_port != 0){
        s = pthread_join(thread_id[0], &res);
        if (!s) {
          Socket_thread *node = (Socket_thread *)res;
          delete node;
        }
      }
    }
  }
  pthread_mutex_destroy(&lock);
  pthread_mutex_destroy(&evaluate_lock);

  return 0;
}

Send_struct::Send_struct(Socket_thread *node_o, pid_t pid_o): node(node_o), pid(pid_o){}

Send_struct::~Send_struct() {
  if (node != NULL)
    delete node;
}