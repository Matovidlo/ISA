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
#ifndef TESTOVAC
#define TESTOVAC

#include <fcntl.h>
#include <algorithm>
#include <cmath>
#include <sys/socket.h>
#include <numeric>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/icmp6.h>
#include <chrono>
#include <netdb.h>
#include <unistd.h>
#include <pthread.h>
#include <string>
#include <vector>
#include <csignal>
#include <sys/stat.h>
#include <sys/wait.h>
#include <iostream>
#include <ctime>
#include <sched.h>
#include <iomanip>
#include <cstdio>
#include <netinet/ip_icmp.h>

#endif