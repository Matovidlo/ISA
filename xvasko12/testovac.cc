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
#include "parsearg.hpp"

int main(int argc, char *argv[]) {
  Socket_thread *Current_socket = new Socket_thread;

  Parse_param *Parser = new Parse_param(argc, argv);

  if (!Parser->parse_options(Current_socket)) {
    delete Parser;
    delete Current_socket;
    return 1;
  }
  Parser->resolve_options(Current_socket);
  delete Parser;

  int error_num = 0;
  if ((error_num = Current_socket->set_connections()) != 0) {
    delete Current_socket;
    return error_num;
  }
  delete Current_socket;

  return 0;
}