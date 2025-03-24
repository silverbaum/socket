
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
#include "sock.c"

#define PORT    8000
#define MAXMSG  512

static int serve(const char *restrict, int);
static int process_request(int, char*);
static int root(int);

struct ht_buf{
char *buf;
size_t size;
};

struct route{
    char *name;
    int (*func)(int);
    struct ht_buf htbuf;
    size_t docsz;
};


struct route routes[] = { {"/", &root, {0, 0}, 0} };
const size_t routelen = 1;

/* TODO: make more robust, error handling, noexcept, threads?
 * more dynamic content serving? (instead of malloc and reading into heap buffer) */

void init_html(const char *file, struct route *route)
{
    // consider iteration

    route->docsz = 0;
    int i;

    route->htbuf.buf = (char*)malloc(4096);
    if(!route->htbuf.buf){
        perror("Out of memory");
        exit(EXIT_FAILURE);
    }

    route->htbuf.size = 4096;

    unsigned int c = 0;

    char *linebuf = (char*)malloc(256);
    size_t lbsz = 256;

    FILE* ws = fopen(file, "r");
    if(!ws){
        perror("Failed to open html file");
        exit(EXIT_FAILURE);
    }

    while((i = getline(&linebuf, &lbsz, ws)) != -1){
        c++;
        if(c == route->htbuf.size){
            route->htbuf.buf = realloc(route->htbuf.buf, route->htbuf.size*2);
            route->htbuf.size *= 2;
        }

        route->docsz += i;
        strcat(route->htbuf.buf, linebuf);
    };
    //return htbuf;

}

/* ROUTES */
int root(const int fd)
{
    fprintf(stderr, "in root\n");
    struct ht_buf *htbuf = &routes[0].htbuf;
/* EDIT CONTENT LENGTH TO MATCH */
    char* ok = (char*)malloc(htbuf->size+60);

    fprintf(stderr, "htbuf size: %lu, route docsz: %lu, htbuf->buf: %s", htbuf->size, routes[0].docsz, htbuf->buf);

    snprintf(ok, htbuf->size+60,"HTTP/1.1 200 OK\nContent-Length: %lu\nContent-Type: text/html\nCache-Control: no-store\n\n\
%s", routes[0].docsz, htbuf->buf);

    fprintf(stderr, "serving client %s", ok); //debug print

    if((write(fd, ok, strlen(ok))) < 0){
        perror("root: Failed to send response");
        return -1;
    }

    return 0;
}

/**  SERVER  **/

/* Matches the HTTP request path with a function to serve said path;
 * return values: 1 for no matches, 0 for success, -1 for failure */
int
serve(const char *restrict path, const int filedes)
{
    size_t i;
    int retval=1;
    for(i=0; i<routelen; i++){
        if(!strcmp(path, routes[i].name)){
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
    if(!strncmp(buffer, "GET", 3)){
               token = strtok(NULL, delim);
               //fprintf(stderr, "second token: '%s'\n", token);
               path = token; //second token of start line should contain request path

               token = strtok(NULL, delim);
               //fprintf(stderr, "third token: '%s'\n", token);
               if(!strncmp(token, "HTTP", 4))
                   serve(path, filedes);
    }
    else {
        if(write(filedes, br, strlen(br)) < 0)
            perror("in process_request -> else -> write");
        return -1;
    }

    return 0;
}

int
read_from_client (const int filedes)
{
       char *buffer = (char*)malloc(MAXMSG);
       int nbytes;

       nbytes = read (filedes, buffer, MAXMSG);
       if (nbytes < 0){
           /* Read error. */
           perror ("read");
           exit (EXIT_FAILURE);
         }
       else if (nbytes == 0)
           /* End-of-file. */
           return -1;
       else {
           fprintf (stderr, "Server: got message: `%s'\n", buffer);
           if(process_request(filedes, buffer) < 0)
               return 1;
         }

       return 0;
}

int
main (int argc, char *argv[])
{
       extern int make_socket (uint16_t port);
       int sock;
       fd_set active_fd_set, read_fd_set;
       int i;
       struct sockaddr_in clientname;
       socklen_t size;

       /* Initialize HTML file by reading it into buffer */
       int c;
       char *html = "index.html";
       while((c = getopt(argc, argv, "f:") ) != -1)
           switch(c){
           case 'f':
               html = optarg;
               break;
            case '?':
                puts("Unknown argument");
                exit(EXIT_FAILURE);
                break;
           }
       init_html(html, &routes[0]);

       /* Create the socket and set it up to accept connections. */
       sock = make_socket (PORT);
       if (listen (sock, 1) < 0)
         {
           perror ("listen");
           exit (EXIT_FAILURE);
         }

       /* Initialize the set of active sockets. */
       FD_ZERO (&active_fd_set);
       FD_SET (sock, &active_fd_set);

       while (1)
         {
           /* Block until input arrives on one or more active sockets. */
           read_fd_set = active_fd_set;
           if (select (FD_SETSIZE, &read_fd_set, NULL, NULL, NULL) < 0)
             {
               perror ("select");
               exit (EXIT_FAILURE);
             }

           /* Service all the sockets with input pending. */
           for (i = 0; i < FD_SETSIZE; ++i)
             if (FD_ISSET (i, &read_fd_set))
               {
                 if (i == sock)
                   {
                     /* Connection request on original socket. */
                     int new;
                     size = sizeof (clientname);
                     new = accept (sock,
                                   (struct sockaddr *) &clientname,
                                   &size);
                     if (new < 0)
                       {
                         perror ("accept");
                         exit (EXIT_FAILURE);
                       }
                     fprintf (stderr,
                              "Server: connect from host %s, port %hd.\n",
                              inet_ntoa (clientname.sin_addr),
                              ntohs (clientname.sin_port));
                     FD_SET (new, &active_fd_set);
                   }
                 else
                   {
                     /* Data arriving on an already-connected socket. */
                     if (read_from_client (i) < 0)
                       {
                         close (i);
                         FD_CLR (i, &active_fd_set);
                       }
                   }
              }
         }
     }

