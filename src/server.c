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
#include <dirent.h>

#include "sock.h"
#include "util.h"

#define MAXMSG 2048
#define MAX_EVENTS 1024
#define DEFAULT_BUFSIZE 4096

#define route(routename, mimetype) {.name=routename, .mime=mimetype}

#ifdef DEBUG
#define dfprintf fprintf
#endif
#ifndef DEBUG
#define dfprintf(x, y, ...)
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

static inline int process_request(int filedes, char *buffer);
static inline int read_from_client(const int filedes);

/* Add accepted routes here */
static struct route routes[] = {
    {.name = "/", .mime = "text/html"},
    {.name = "/index.js", .mime = "text/javascript"},
    {.name = "/img.png", .mime = "image/png"},
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

int
get_response(const int fd, const char *path)
{
	dfprintf(stderr, "get_response\npath: %s\n\n", &path[1]);
	DIR *cwd = 0;
	struct dirent *entry;
	int content;

	size_t docsize;
	size_t bufsize;
	size_t i;
	char *buf;
	char *mime;
	char response[100];
	char *file_name;

	if(!strncmp(path, "/", strlen(path))){
		dfprintf(stderr, "index\n");
		content = open("index.html", O_RDONLY);
		file_name = "index.html";
	} else {
	cwd = opendir(".");
	while((entry = readdir(cwd)) != NULL)
		if ((strstr(entry->d_name, &path[1])) != NULL) {
			dfprintf(stderr, "entry: %s, path: %s", entry->d_name, &path[1]);
			content = open(entry->d_name, O_RDONLY);
			break;
			}

	file_name = strchr(&path[1], '.');
	if(!content){
		perror("readdir");
		return -1;
	}
	}




	dfprintf(stderr, "extension: %s\n", file_name);

	if(strstr(file_name, ".html"))
		asprintf(&mime, "text/html");
	else if(strstr(file_name, ".png"))
		asprintf(&mime, "image/png");
	else if(strstr(file_name, ".js"))
		asprintf(&mime, "text/javascript");
	else{
		asprintf(&mime, "None");
	}



	docsize = 0;
	bufsize = DEFAULT_BUFSIZE;
	buf = (char *)xmalloc(DEFAULT_BUFSIZE);

	for(i=0; (read(content, &buf[i], 1)) > 0; i++, docsize++)
		if(docsize+1 >= bufsize){
			dfprintf(stderr, "reallocating, docsz: %lu, i: %lu\n", docsize, i);
			buf = xrealloc(buf, bufsize*=2);
		}

	snprintf(response, 80, "HTTP/1.1 200 OK\nContent-Length: %lu\nContent-Type: %s\n\n",
			 docsize, mime);

	dfprintf(stderr, "serving client,\n%s\n\n", response);
	write(1, buf, docsize);

	if ((write(fd, response, strlen(response))) < 0 ||
		(write(fd, buf, docsize)) < 0){
		perror("get_response: write");
		return -1;
	}


	free(buf);
	close(content);
	if(cwd)
		if(closedir(cwd) < 0)
			perror("closedir");
	return 0;
}

/**  SERVER  **/

/* Matches the HTTP request path with a function to serve said path;
 * return values: 1 for no matches, 0 for success, -1 for failure */

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

	/* Here add strstr and strtok to find the accepted types */

	if (!strncmp(req.protocol, "HTTP", 4)){
		!strncmp(req.method, "GET", 3) ? get_response(filedes, req.path) : 0;

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
		die("read");

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
	int optindex;

   	unsigned short PORT;

	PORT = 8000;

	static const struct option longopts[] = {
		{"help", no_argument, 0, 'h'},
		{"file", required_argument, 0, 'f'},
		{"port", required_argument, 0, 'p'},
	};
	optindex = 0;
	while ((c = getopt_long(argc, argv, "p:f:", longopts, &optindex)) != -1)
		switch (c) {
		case 'f':
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
