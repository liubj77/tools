CC = gcc
CXX = g++
CFLAGS = -Wall -g

RANLIB= ranlib

OBJS = dns_query.o dns_util.o  

BIN = main

all : $(BIN) out

main: libdnsquery.a
	$(CXX)  -o $@ main.cpp $< -lresolv $(CFLAGS) -I../../

out: libdnsquery.a
	@rm -rf output
	@mkdir -p output/include
	@mkdir -p output/lib
	@cp libdnsquery.a output/lib
	@cp dns.h dns_query.h dns_util.h output/include
	@rm -fr $< $(OBJS)

libdnsquery.a: $(OBJS)
	$(AR) rc $@ $(OBJS)
	$(RANLIB) $@

%.o : %.cpp
	$(CXX) -c $< -o $@ -I../../

.PHONY:clean rebuild
clean:
	@rm -rf output $(BIN)
rebuild:
	make clean; make
