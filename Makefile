
CC=cc
CFLAGS= -Wall -std=gnu99
OBJDIR=src

all: server

server:
	$(CC) $(CFLAGS) -o server $(OBJDIR)/main.c
clean:
	rm *.o



