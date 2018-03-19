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
#ifndef SERVICE
#define SERVICE

#include "testovac.hpp"
#include "thread.hpp"

class Socket_thread;
void *listen_on(void *);
void *node_service(void *);
void *node_stats(void *);
void *node_sendicmp4(void *);
void *node_sendicmp6(void *);
void *node_sendudp6(void *);
void *node_sendudp4(void *);

struct addrinfo *get_ipaddr(std::string);
void verbose_print(int, Socket_thread *, uint64_t);
int check_timeout(int, int, int);
char *print_ips(struct addrinfo *);

void send_ip6_packet(int, char *, struct sockaddr_in6 *, socklen_t, int);
bool recv_udp6(Socket_thread *, char **);
bool recv_udp4(Socket_thread *, char **);
int recv_icmp4(Socket_thread *, char **, uint64_t *);
int recv_icmp6(Socket_thread *, char **, uint64_t *);
char *icmp_timestamp(Socket_thread *, unsigned, int, pid_t);
char *icmp6_timestamp(unsigned, int, pid_t);
bool parse_icmp4(char *, int, pid_t);
bool parse_icmp6(char *, int, pid_t);

void signal_handler(int);
bool _check_exiting();

#endif
