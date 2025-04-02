/* Copyright 2025 Topias Silfverhuth
 * SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#define _FORTIFY_SOURCE 1
#define __linux__ 1

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <aio.h>
#include <getopt.h>

#include "sock.h"
#include "util.h"

#define MAXMSG 2048
#define MAX_EVENTS 1024
#define DEFAULT_BUFSIZE 4096


#ifdef DEBUG
#define dfprintf fprintf
#endif
#ifndef DEBUG
static void dfprintf(FILE *restrict stream, const char *restrict format, ...) {return;}
#endif

struct route {
	char *name;
	char *type;
	char *buf;
	size_t docsz;
	size_t bufsize;
};

static void load_file(const char *file, struct route *route);
static inline int get_response(const int fd, const struct route *route);
static inline int serve(const char *restrict path, const int fd);
static inline int process_request(int filedes, char *buffer);
static inline int read_from_client(const int filedes);

/* Add routes here */
static struct route routes[] ={
{.name="/", .type="text/html"},
{.name="/index.js", .type="text/javascript"}
};
/* TODO: adding routes that arent filenames requires manual loading,
 * separation between file and route name (add struct field?) */

static const size_t routelen = sizeof(routes) / sizeof(struct route);

/*
 * Load HTML files into memory for a particular route
 * file: the name of the html file to be loaded,
 * route: pointer to the route struct to which the file should be connected
 */
void
load_file(const char *file, struct route *route)
{
	ssize_t i;
	char *buf;
	char *linebuf;
	size_t lbsz;
	FILE *ws;

	route->docsz = 0;
	route->buf = (char *)xmalloc(DEFAULT_BUFSIZE);
	route->bufsize = DEFAULT_BUFSIZE;
	
	buf = route->buf; // pointer for stpcpy
	linebuf = (char*)xmalloc(256);
	lbsz = 256;

	
	ws = fopen(file, "r");
	if (!ws) {
		fprintf(stderr, "Failed to open %s\n", file);
		perror(" fopen");
		return;
	}

	while ((i = getline(&linebuf, &lbsz, ws)) != -1) {
		dfprintf(stderr, "docsz: %lu\n", route->docsz);
		if (route->docsz+i >= route->bufsize){
			dfprintf(stderr, "reallocating, docsz: %lu, i: %lu\n", route->docsz, i);
			route->buf = xrealloc(route->buf, (route->bufsize*2));
			route->bufsize *= 2;

			dfprintf(stderr, "setting buf = to buf[%lu]\n", route->docsz);
			buf = &route->buf[route->docsz]; //for stpcpy, set pointer to the end of the read bytes
		}
		route->docsz += i;
		buf = stpcpy(buf, linebuf);
	}
	free(linebuf);
	if (fclose(ws) == EOF)
		perror("fclose");
}

/* Route function definitions */
int
get_response(const int fd, const struct route *restrict route)
{
	dfprintf(stderr, "in root\n");
	char *ok = (char *)xmalloc(route->docsz + 100);

	dfprintf(stderr, "\nroute name: %s, htbuf type: %s htbuf size: %lu, route docsz: %lu\n",
			 route->name, route->type, route->bufsize, route->docsz);

	snprintf(
		ok, route->docsz + 100,
		"HTTP/1.1 200 OK\nContent-Length: %lu\nContent-Type: %s\nCache-Control: no-store\n\n%s",
		route->docsz, route->type ?: "none", route->buf);

	dfprintf(stderr, "\nserving client:\n%s\n", ok);

	//change to htbuf->size+60 as length is known beforehand, no need to count it again
	if ((write(fd, ok, strlen(ok))) < 0) {
		perror("root: write");
		return -1;
	}
	free(ok);
	return 0;
}

/**  SERVER  **/

/* Matches the HTTP request path with a function to serve said path;
 * return values: 1 for no matches, 0 for success, -1 for failure */
int
serve(const char *restrict path, const int filedes)
{
	size_t i;
	int retval = 1;
	for (i = 0; i < routelen; i++) {
		dfprintf(stderr, "path: %s; routes[%lu].name = %s\n", path, i, routes[i].name);
		if (!strcmp(path, routes[i].name)) {
			retval = get_response(filedes, &routes[i]);
			break;
		}
	}

	return retval;
}

int
process_request(const int filedes, char *buffer)
{
	char *token;
	char *method;
	char *path;

	const char *delim = " ";
	const char *br = "HTTP/1.1 400 Bad Request";


	token = strtok(buffer, delim);
	method = token;

	token = strtok(NULL, delim);
	dfprintf(stderr, "second token: '%s'\n", token);
	path = token; //second token of start line should contain request path

	token = strtok(NULL, delim);
	dfprintf(stderr, "third token: '%s'\n", token);
	if (strncmp(token, "HTTP", 4))
			write(filedes, br, 25);

	if (!strncmp(method, "GET", 3)) {
		serve(path, filedes);
	} else if(!strncmp(method, "POST", 4)){
		serve(path, filedes);
	} else {
		if (write(filedes, br, strlen(br)) < 0)
			perror("in process_request -> else -> write");
		return -1;
	}

	return 0;
}

int
read_from_client(const int filedes)
{
	char *buffer = (char *)xmalloc(MAXMSG);
	long nbytes;

	nbytes = read(filedes, buffer, MAXMSG);
	if (nbytes < 0) {
		/* Read error. */
		perror("read");
		exit(EXIT_FAILURE);

	} else if (nbytes == 0) {
		/* End-of-file. */
		free(buffer);
		return -1;
	} else {
		if (nbytes + 1 < MAXMSG)
			buffer[nbytes + 1] = '\0';
		fprintf(stderr, "Server: got message: `%s'\n", buffer);
		if (process_request(filedes, buffer) < 0) {
			free(buffer);
			return 1;
		}
	}

	return 0;
}

/* epoll instance, an in-kernel data structure */
int
main(int argc, char *argv[])
{
	int sock, conn, nfds, epollfd;
	struct epoll_event ev, events[MAX_EVENTS];

	int i, c;
	size_t j;

	struct sockaddr_in clientname;
	socklen_t addrsize;

	char *html;
    unsigned short PORT;

	PORT = 8000;
	html = "index.html";

	while ((c = getopt(argc, argv, "p:f:")) != -1)
		switch (c) {
		case 'f':
			html = optarg;
			break;
		case 'p':
			PORT = (unsigned short)strtoul(optarg, NULL, 10);
			break;
		case '?':
			puts("Unknown argument");
			//help();
			exit(EXIT_FAILURE);
		}


	/* Read files to memory */
	char *rn;
	load_file(html, &routes[0]);
	for(j=1; j<routelen; j++){
		rn = &routes[j].name[1];
		load_file(rn, &routes[j]);
	}


	/* Create the socket and set it up to accept connections. */
	sock = make_socket(PORT);
	if (listen(sock, 1) < 0) {
		perror("listen");
		exit(EXIT_FAILURE);
	}


	if ((epollfd = epoll_create1(0)) < 0) {
		perror("epoll_create1");
		exit(EXIT_FAILURE);
	}

	/* events struct is a bit mask to the set "event types"/settings on the socket
	 * EPOLLIN: The fd(sock) is available for read operations.*/
	ev.events = EPOLLIN;
	/* connect the created ipv4 socket to the epoll event object */
	ev.data.fd = sock;
	/* Add the socket to the "interest list" of the epoll file descriptor
	 * according to the settings in the ev epoll_event struct */
	if(epoll_ctl(epollfd, EPOLL_CTL_ADD, sock, &ev) == -1){
		perror("epoll_ctl: sock");
		exit(EXIT_FAILURE);
	}


	while (1) {
		/* Block until input arrives on one or more active sockets,
		 * similar to select */
		if ((nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1)) < 0){
			perror("epoll_wait");
			exit(EXIT_FAILURE);
		}

		/* Service all the sockets with input pending. */
		for (i = 0; i < nfds; ++i){
			if (events[i].data.fd == sock){
					addrsize = sizeof(clientname);
					conn = accept(
						sock,
						(struct sockaddr *)&clientname,
						&addrsize);
					if (conn < 0) {
						perror("accept");
						exit(EXIT_FAILURE);
					}
					/* set nonblocking IO on the connected socket which
					 * is necessary for edge-triggered mode (EPOLLET) which
					 * delivers events only when changes occur on the monitored file descriptor */
					fcntl(conn, F_SETFL, O_NONBLOCK);
					ev.events = EPOLLIN | EPOLLET;
					ev.data.fd = conn;
					if(epoll_ctl(epollfd, EPOLL_CTL_ADD, conn, &ev) == -1){
						perror("epoll_ctl: conn");
						exit(EXIT_FAILURE);
					}

					fprintf(stderr,
						"Server: connect from host %s, port %hd.\n",
						inet_ntoa(clientname.sin_addr),
						ntohs(clientname.sin_port));
				} else {
					/* Data arriving on an already-connected socket. */
					if (read_from_client(events[i].data.fd) < 0) {
						close(events[i].data.fd);
						epoll_ctl(epollfd, EPOLL_CTL_DEL, events[i].data.fd, &ev);
					}
				}
			}
	}
}
