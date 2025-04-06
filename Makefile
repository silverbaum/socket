
CC=cc
CFLAGS= -Wall -std=gnu99
OBJDIR=src
OBJS= server.o util.o sock.o

all: server

server: $(OBJS)
	$(CC) $(CFLAGS) -o server $(OBJS)
server.o:
	$(CC) $(CFLAGS) -c $(OBJDIR)/server.c
util.o:
	$(CC) $(CFLAGS) -c $(OBJDIR)/util.c
sock.o:
	$(CC) $(CFLAGS) -c $(OBJDIR)/sock.c
clean:
	rm *.o
