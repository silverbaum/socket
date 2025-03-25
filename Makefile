
OBJDIR=src

all: server

server: server.o sock.o
	cc -o server server.o sock.o
server.o: 
	cc -c -o server.o $(OBJDIR)/server.c 
sock.o: 
	cc -c -o sock.o $(OBJDIR)/sock.c
clean:
	rm *.o



