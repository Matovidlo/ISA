#### Martin Vaško xvasko12
###  FIT VUTBR 3.BIT->3.BIB
#####  ISA -> 1.project
### stats of packet loss RTT
#  Date of creation = 28.9.2017
# Makefile usage = make,make all,
###  make pack, make clean
#   project- traffic monitoring
# sends http requests to server
##   Using BSD sockets, parse,
###    strftime, timestamps
####    Parse_param class
########   Socket class

CC=g++
CPPFLAGS=-std=c++11 -pedantic -Wall -Wextra -pthread
LDFLAGS=-L.

LIBOBJ=parsearg.o thread.o ipv6.o service.o testovac.o
APP=testovac

.PHONY: all test clean

all: $(APP)

$(APP): $(LIBOBJ)
	$(CC) $(CPPFLAGS) $^ -o $@

clean:
	$(RM) $(APP) xvasko12.tgz $(LIBOBJ) manual.dvi manual.log manual.ps manual.toc

xvasko12.tar: $(wildcard *.cc) $(wildcard *.hpp) Makefile manual.pdf README
	tar cvf $@ $^

manual.pdf:
	latex manual.tex
	latex manual.tex
	dvips -t a4 manual.dvi
	ps2pdf manual.ps

vagrant:
	make xvasko12.tar
	# cd ISA/projects/vagrant
	# cp xvasko12.tgz ISA/projects/vagrant
	vagrant scp xvasko12.tar default:~/
	vagrant ssh
	tar -xvf xvasko12.tar
