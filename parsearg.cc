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
#include "parsearg.hpp"

Parse_param::Parse_param(): param_number(0),
                            all_options(NULL),
                            current_option(0){}

Parse_param::Parse_param(int number, char **options): param_number(number),
                                                      all_options(options),
                                                      current_option(0){}

Parse_param::~Parse_param() {
}

void Parse_param::show_help() {
  std::cout << "Options: '-h' - Shows this help message \n"
  << "\t '-u' - For testing application will use UDP protocol\n"
  << "\t '-s <size>' - Size of data to send, default value is 56B\n"
  << "\t '-t <interval>' - Interval in secods in which packet loss is evaluated, in default setup 300s\n"
  << "\t '-i <interval>' - Interval in milliseconds how often is sent test reports, in default setup 100ms\n"
  << "\t '-w <timeout>' - How long application waits for response, only when no response is received, default value is 2s otherwise 2 times value of counted RTT\n"
  << "\t '-p <port>' - Specification of UDP port\n"
  << "\t '-l <port>' - Specification of listening UDP port\n"
  << "\t '-r <value>' - Specification of RTT value, when RTT is exceeding given value, application is reporting\n"
  << "\t '-v' - verbose mode, program is listing on stdout sent packets\n"
  << "\t '<node>' - IPv4/IPv6/hostname address of node\n";
}

void Parse_param::show_variables() {
  std::cout << "Param number: "<< this->param_number << "\n" << "Options: \n";
  for (int i = 1; i < this->param_number; i++)
    std::cout << this->all_options[i] << "\n";

  std::cout << "Flags: \n";
  for (int i = 0; i < 10; i++)
    std::cout << this->flags[i] << "\n";

  std::cout << "Stored values: \n";
  for (int i = 0; i < 9; i++){
    std::cout << this->option_shortcuts[i + 1] << " - ";
    std::cout << this->option_required_values[i] << "\n";
  }
}

bool Parse_param::add_option() {

  for (int j = 1; j < this->param_number; j++) {
    std::string param_option (this->all_options[j]);
    this->current_option = 0;

    for (int i = 0; i < 10; i++) {
      // fill flag array set current option, option is valid
      if (param_option == this->option_shortcuts[i]) {
        if (this->flags[i]){
          std::cerr << "Bad parameter given!\n";
          return false;
        }
        this->flags[i] = true;
        this->current_option = i;
      }
    }
    // not evaluated option
    if (!this->flags[this->current_option]) {
      this->not_evaluated_options.push_back(j);
    }

    if (param_option == "-u") {
      if (++j < this->param_number) {
        param_option = this->all_options[j];
        if (param_option == "-p"){
          if (++j < this->param_number) {
            if (! this->check_option_value(j, 5)){
              return false;
            }
          } else {
            std::cerr << "Required port value is missing!\n";
            return false;
          }
        } else {
          std::cerr << "Required parameter -p is missing!\n";
          return false;
        }
      } else {
        std::cerr << "Required parameter -p is missing!\n";
        return false;
      }
    }

    if (param_option == "-t" || param_option == "-i" ||
        param_option == "-w" || param_option == "-l" ||
        param_option == "-r" || param_option == "-s" ) {
      // next option is required for those types of option
      if (++j < this->param_number) {
        if (! this->check_option_value(j, this->current_option - 1)) {
          return false;
        }
      } else {
        std::cerr << "Required parameter is missing!\n";
        return false;
      }
    }
  }
  return true;
}

bool Parse_param::check_option_value(int position, int position_index){
  std::string convert_number (this->all_options[position]);
  double value;
  try {
    value = std::stod(convert_number);
  } catch (const std::invalid_argument& invalid_argument) {
    std::cerr << "No number given as required value parameter!\n";
    return false;
  }
  if (value < 0) {
    std::cerr << "Wrong input number for given parameter!" << std::endl;
    return false;
  }
  this->option_required_values[position_index] = value;
  return true;
}

void Parse_param::resolve_options(Socket_thread *thread) {
  for(int i = 1; i < 10; i++) {
    bool flag = this->flags[i];
    if (i == 1) {
      if (flag && thread->add_type(i, this->option_required_values[5])) {
        // std::cout << "Success!\n";
        ;
      }
    } else {
      if (flag && thread->add_type(i, this->option_required_values[i - 1])) {
        // std::cout << "Success!\n";
        ;
      }
    }
  }
}

bool Parse_param::parse_options(Socket_thread *thread) {
  bool success = this->add_option();
  if (this->flags[0] && this->param_number == 2 && success)
    this->show_help();
  else if (!success || (this->flags[0] && this->param_number != 2)){
    return false;
  }
  for (unsigned i = 0; i < this->not_evaluated_options.size(); ++i) {
    // FIXME debug
    // std::cout << all_options[this->not_evaluated_options[i]] << "\n";
    if (! thread->add_node(all_options[this->not_evaluated_options[i]])){
      return false;
    }
  }
  return true;
}

int Parse_param::get_param_number() {
  return this->param_number;
}


