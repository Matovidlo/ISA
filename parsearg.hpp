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

#ifndef ARG_PARSE
#define ARG_PARSE

#include "testovac.hpp"
#include "thread.hpp"

class Parse_param final {
private:
  int param_number;
  char **all_options = NULL;
  int current_option;
  std::vector<int>not_evaluated_options;

  const std::string option_shortcuts[10] = {"-h", "-u", "-s", "-t", "-i", "-w", "-p", "-l", "-r", "-v"};
  bool flags[10] = {false};
  double option_required_values[10] = {-1, 0, 0, 0, 0, 0, 0, 0, -1};

  bool check_option_value(int, int);
  bool add_option();
public:
  void show_help();
  void show_variables();

  bool parse_options(Socket_thread *);
  int get_param_number();
  void resolve_options(Socket_thread *);

  Parse_param();
  Parse_param(int, char **);
  ~Parse_param();
};

#endif
