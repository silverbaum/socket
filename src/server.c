
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <aio.h>

#include "sock.h"
#include "util.h"

#define MAXMSG 512

#ifdef DEBUG
#define dfprintf fprintf
#endif
#ifndef DEBUG
static void dfprintf(FILE *restrict stream, const char *restrict format, ...) {return;}
#endif

struct ht_buf {
	char *buf;
	size_t size;
};

struct route {
	char *name;
	int (*func)(int);
	struct ht_buf htbuf;
	size_t docsz;
};

static void load_file(const char *file, struct route *route);
/* Route function prototypes */
static int root(const int fd);
static int js(const int fd);
/*                               */
static int serve(const char *restrict path, const int fd);
static int process_request(int filedes, char *buffer);
static int read_from_client(const int filedes);

static unsigned short PORT = 8000;
/* Add routes here */
static struct route routes[] = { {"/", &root, { NULL, 0 }, 0}, {"/index.js", &js, {NULL, 0}, 0} };
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
	route->htbuf.buf = (char *)xmalloc(4096);
	if (!route->htbuf.buf) {
		perror("Out of memory");
		return;
	}

	route->htbuf.size = 4096;
	
	buf = route->htbuf.buf;
	linebuf = (char*)xmalloc(256);
	lbsz = 256;

	
	ws = fopen(file, "r");
	if (!ws) {
		fprintf(stderr, "Failed to open %s", file);
		perror(" file");
		return;
	}

	while ((i = getline(&linebuf, &lbsz, ws)) != -1) {

		dfprintf(stderr, "docsz: %lu\n", route->docsz);
		if(route->docsz+i >= route->htbuf.size){
			dfprintf(stderr, "reallocating, docsz: %lu, i: %lu\n", route->docsz, i);
			route->htbuf.buf = xrealloc(route->htbuf.buf, (route->htbuf.size*2));
			route->htbuf.size *= 2;

			dfprintf(stderr, "setting buf = to buf[%lu]", route->docsz);
			buf = &route->htbuf.buf[route->docsz];
		}
		route->docsz += i;
		buf = stpcpy(buf, linebuf);
	}
	free(linebuf);
	if(fclose(ws) == EOF)
		perror("fclose");
}

/* ROUTES */
int
root(const int fd)
{
	dfprintf(stderr, "in root\n");
	struct ht_buf *htbuf = &routes[0].htbuf;
	char *ok = (char *)xmalloc(htbuf->size + 60);

	dfprintf(stderr, "htbuf size: %lu, route docsz: %lu, routes[0].htbuf.buf: %s\n",
		htbuf->size, routes[0].docsz, routes[0].htbuf.buf);

	snprintf(
		ok, htbuf->size + 60,
		"HTTP/1.1 200 OK\nContent-Length: %lu\nContent-Type: text/html\nCache-Control: no-store\n\n\
%s",
		routes[0].docsz, htbuf->buf);

	dfprintf(stderr, "serving client %s", ok); //debug print

	if ((write(fd, ok, strlen(ok))) < 0) {
		perror("root: Failed to send response");
		return -1;
	}
	free(ok);
	return 0;
}

int
js(const int fd)
{
	struct ht_buf *htbuf = &routes[1].htbuf;
	char *ok = (char *)xmalloc(htbuf->size + 100);

	dfprintf(stderr, "htbuf size: %lu, route docsz: %lu, routes[0].htbuf.buf: %s\n",
		htbuf->size, routes[1].docsz, routes[1].htbuf.buf);

	snprintf(
		ok, htbuf->size + 100,
		"HTTP/1.1 200 OK\nContent-Length: %lu\nContent-Type: text/javascript\nCache-Control: no-store\n\n\
%s",
		routes[1].docsz, htbuf->buf);

	dfprintf(stderr, "serving client %s", ok);

	if ((write(fd, ok, strlen(ok))) < 0) {
		perror("root: Failed to send response");
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
		dfprintf(stderr, "path: %s; routes[%lu].name = %s", path, i, routes[i].name);
		if (!strcmp(path, routes[i].name)) {
			retval = routes[i].func(filedes);
		}
	}

	return retval;
}

int
process_request(const int filedes, char *buffer)
{
	char *path;
	char *token;
	const char *delim = " ";
	const char *br = "HTTP/1.1 400 Bad Request";

	token = strtok(buffer, delim);
	if (!strncmp(buffer, "GET", 3)) {
		token = strtok(NULL, delim);
		//fprintf(stderr, "second token: '%s'\n", token);
		path = token; //second token of start line should contain request path

		token = strtok(NULL, delim);
		//fprintf(stderr, "third token: '%s'\n", token);
		if (!strncmp(token, "HTTP", 4))
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

int
main(int argc, char *argv[])
{
	int sock;
	fd_set active_fd_set, read_fd_set;
	int i;
	struct sockaddr_in clientname;
	socklen_t size;

	
	int c;
	char *html = "index.html";
	while ((c = getopt(argc, argv, "p:f:")) != -1)
		switch (c) {
		case 'f':
			html = optarg;
			break;
		case 'p':
			PORT = (unsigned short)atoi(optarg);
			break;
		case '?':
			puts("Unknown argument");
			//help();
			exit(EXIT_FAILURE);
		}

	/* Read files to memory */
	char *rn;
	load_file(html, &routes[0]);
	for(i=1; i<routelen; i++){
		rn = &routes[i].name[i];
		load_file(rn, &routes[i]);
	}


	/* Create the socket and set it up to accept connections. */
	sock = make_socket(PORT);
	if (listen(sock, 1) < 0) {
		perror("listen");
		exit(EXIT_FAILURE);
	}

	/* Initialize the set of active sockets. */
	FD_ZERO(&active_fd_set);
	FD_SET(sock, &active_fd_set);

	while (1) {
		/* Block until input arrives on one or more active sockets. */
		read_fd_set = active_fd_set;
		if (select(FD_SETSIZE, &read_fd_set, NULL, NULL, NULL) < 0) {
			perror("select");
			exit(EXIT_FAILURE);
		}

		/* Service all the sockets with input pending. */
		for (i = 0; i < FD_SETSIZE; ++i)
			if (FD_ISSET(i, &read_fd_set)) {
				if (i == sock) {
					/* Connection request on original socket. */
					int new;
					size = sizeof(clientname);
					new = accept(
						sock,
						(struct sockaddr *)&clientname,
						&size);
					if (new < 0) {
						perror("accept");
						exit(EXIT_FAILURE);
					}
					fprintf(stderr,
						"Server: connect from host %s, port %hd.\n",
						inet_ntoa(clientname.sin_addr),
						ntohs(clientname.sin_port));
					FD_SET(new, &active_fd_set);
				} else {
					/* Data arriving on an already-connected socket. */
					if (read_from_client(i) < 0) {
						close(i);
						FD_CLR(i, &active_fd_set);
					}
				}
			}
	}
}
