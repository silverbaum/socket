
OBJDIR=src

all: server client

client: client.o
	cc -o client client.o

server: server.o
	cc -o server server.o

server.o:
	cc -c -o server.o $(OBJDIR)/server.c

client.o:
	cc -c -o client.o $(OBJDIR)/client.c
clean:
	rm *.o



