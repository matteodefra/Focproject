CPPFLAGS=-g -pthread -Wall
LDFLAGS=-L. -g
LDLIBS=-lcrypto
AR=ar
ARFLAGS=rvs

TARGETS 			=	server_example \
						client_example


OBJECTSSERVER	=	tcp_server.o \
					client.o 
					 

OBJECTSCLIENT = tcp_client.o  	


INCLUDE_SERVER=	include/util.h \
				include/tcp_server.h \
				include/server_observer.h \
				include/pipe_ret_t.h \
				include/client.h


INCLUDE_CLIENT= include/util.h \
				include/tcp_client.h \
				include/client_observer.h \
				include/pipe_ret_t.h


.PHONY: all clean test

.SUFFIXES: .cpp .h

%: src/%.cpp 
	g++ $(CPPFLAGS) $(INCLUDES) $(LDFLAGS) -o $@ $< $(LDLIBS)

%: src/%.cpp 
	g++ $(CPPFLAGS) $(INCLUDES) $(LDFLAGS) -o $@ $< $(LDLIBS)

%.o: %.cpp 
	g++ $(CFLAGS) $(INCLUDES) $(LDFLAGS) -c -o $@ $< $(LDLIBS) 

%.o: src/%.cpp 
	g++ $(CFLAGS) $(INCLUDES) $(LDFLAGS) -c -o $@ $< $(LDLIBS) 


all: $(TARGETS)


server_example: server_example.o libserver.a $(INCLUDE_SERVER)
	g++ $(CPPFLAGS) $(INCLUDES) $(LDFLAGS) -o $@ $^ $(LDLIBS)


client_example: client_example.o libclient.a $(INCLUDE_CLIENT)
	g++ $(CPPFLAGS) $(INCLUDES) $(LDFLAGS) -o $@ $^ $(LDLIBS)


libserver.a: $(OBJECTSSERVER)
	$(AR) $(ARFLAGS) $@ $^ $(LDLIBS)


libclient.a: $(OBJECTSCLIENT)
	$(AR) $(ARFLAGS) $@ $^ $(LDLIBS)

# tool: tool.o support.o
#     g++ $(LDFLAGS) -o tool tool.o support.o $(LDLIBS)

# tool.o: tool.cc support.hh
#     g++ $(CPPFLAGS) -c tool.cc

# support.o: support.hh support.cc
#     g++ $(CPPFLAGS) -c support.cc