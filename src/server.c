/* Copyright 2025 Topias Silfverhuth
 * SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
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
static void dfprintf(FILE *restrict stream, const char *restrict format, ...) {NULL;}
#endif

struct route {
	char *name;
	char *mime;
	char *buf;
	size_t bufsize;
	size_t docsize;
};

struct request {
	char *method;
	char *path;
	char *protocol;
};

static void load_file(const char *file, struct route *route);
static inline int get_response(const int fd, const struct route *route);
static inline int serve(struct request req, const int fd);
static inline int process_request(int filedes, char *buffer);
static inline int read_from_client(const int filedes);

/* Add accepted routes here */
static struct route routes[] ={
{.name="/", .mime="text/html"},
{.name="/index.js", .mime="text/javascript"},
{.name="/img.png", .mime="image/png"}
};
/* TODO: adding routes that arent filenames requires manual loading,
 * separation between filename and route name (add struct field?) 
 * + loading files in runtime*/

static const size_t routelen = sizeof(routes) / sizeof(struct route);

/*
 * Load HTML files into memory for a particular route
 * file: the name of the html file to be loaded,
 * route: pointer to the route struct to which the file should be connected
 */

void
load_file(const char *file, struct route *route)
{
	/* add dynamic file loading runtime? */
	int fd;
	ssize_t i;
	char *file_type;

	route->docsize = 0;
	route->buf = (char *)xmalloc(DEFAULT_BUFSIZE);
	route->bufsize = DEFAULT_BUFSIZE;

	if (!route->mime)
		asprintf(&route->mime, "None");
		

	fd = open(file, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Failed to open %s\n", file);
		perror(" open");
		return;
	}

	file_type = strchr(file, '.');
	dfprintf(stderr, "extension: %s\n", file_type);
	
	for(i=0; (read(fd, &route->buf[i], 1)) > 0; i++, route->docsize++)
		if(route->docsize+1 >= route->bufsize){
				dfprintf(stderr, "reallocating, docsz: %lu, i: %lu\n", route->docsize, i);
				route->buf = xrealloc(route->buf, route->bufsize*=2);
		}

	close(fd) < 0 ? perror("close") : 0;
}

/* Route function definitions */
int
get_response(const int fd, const struct route *restrict route)
{
	char *response;
	
	dfprintf(stderr, "\nroute name: %s, route type: %s route size: %lu, route docsz: %lu\n",
			 route->name, route->mime, route->bufsize, route->docsize);


	if (!strncmp(route->mime, "image", 5)) {
		response = xmalloc(75);
		snprintf(response, 75, "HTTP/1.1 200 OK\nContent-Length: %lu\nContent-Type: %s\n\n",
				 route->docsize, route->mime);

		dfprintf(stderr, "serving client image,\n%s\n\n", response);

		if ((write(fd, response, strlen(response))) < 0 ||
			(write(fd, route->buf, route->docsize)) < 0){
			perror("get_response: write");
			return -1;
		}

	} else {


		response = (char *)xmalloc(route->docsize + 80);

		snprintf(
			response, route->docsize + 80,
			"HTTP/1.1 200 OK\nContent-Length: %lu\nContent-Type: %s\n\n%s",
			route->docsize, route->mime, route->buf);
		
		dfprintf(stderr, "\nserving client:\n%s\n", response);

		if ((write(fd, response, route->docsize+80) < 0)) {
			perror("get_response: write");
			return -1;
		}

	}


	free(response);
	return 0;
}

/**  SERVER  **/

/* Matches the HTTP request path with a function to serve said path;
 * return values: 1 for no matches, 0 for success, -1 for failure */
int
serve(struct request req, const int filedes)
{
	size_t i;
	int retval = 1;
	for (i = 0; i < routelen; i++) {
		dfprintf(stderr, "path: %s; routes[%lu].name = %s\n", req.path, i, routes[i].name);
		if (!strcmp(req.path, routes[i].name)) {
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

	struct request req;

	const char *delim = " \r\n";
	const char *br = "HTTP/1.1 400 Bad Request";


	token = strtok(buffer, delim);
	req.method = token;
	dfprintf(stderr,"first token: '%s'\n", token);

	token = strtok(NULL, delim);
	dfprintf(stderr, "second token: '%s'\n", token);
	req.path = token;

	token = strtok(NULL, delim);
	req.protocol = token;
	dfprintf(stderr, "third token: '%s'\n", token);
	if (!strncmp(token, "HTTP", 4)){
		serve(req, filedes);
	} else {
		write(filedes, br, 25) < 0 ? perror("process_request: write") : 0;
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

static inline void help(const char* arg){
printf("Usage: %s [OPTION] [argument]..\noptions:\n\
-f, --file		choose root file\n\
-p, --port		choose the port to which the socket is bound\n\
-h, --help		display this help information and exit\n", arg);
}

int
main(int argc, char *argv[])
{
	int sock, conn, nfds, epollfd;
	struct epoll_event ev, events[MAX_EVENTS];

	struct sockaddr_in clientname;
	socklen_t addrsize;

	int i, c;
	size_t j;
	int optindex;

	char *html;
   	unsigned short PORT;

	PORT = 8000;
	html = "index.html";
	
	static const struct option longopts[] = {
		{"help", no_argument, 0, 'h'},
		{"file", required_argument, 0, 'f'},
		{"port", required_argument, 0, 'p'},
	};
	optindex = 0;
	while ((c = getopt_long(argc, argv, "p:f:", longopts, &optindex)) != -1)
		switch (c) {
		case 'f':
			html = optarg;
			break;
		case 'p':
			PORT = (unsigned short)strtoul(optarg, NULL, 10);
			break;
		case 'h':
			help(argv[0]);
			return 0;
		case '?':
			puts("Unknown argument");
			help(argv[0]);
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
