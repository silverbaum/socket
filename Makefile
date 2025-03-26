
CC=gcc
CFLAGS= -Wall
OBJDIR=src

OBJS= server.o sock.o util.o

all: server

server: $(OBJS)
	$(CC) $(CFLAGS) -o server server.o sock.o util.o
server.o: 
	$(CC) $(CFLAGS) -c $(OBJDIR)/server.c 
sock.o: 
	$(CC) $(CFLAGS) -c $(OBJDIR)/sock.c
util.o: 
	$(CC) $(CFLAGS) -c $(OBJDIR)/util.c
clean:
	rm *.o



