
#include <complex.h>
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
#include "sock.c"
#include <aio.h>

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
    void *func;
};

struct ht_buf htbuf;
const struct route routes[] = { {"/", &root} };
size_t routelen = 1;

/* TODO: make more robust, error handling, noexcept, threads?
 * more dynamic content serving? (instead of malloc and reading into heap buffer) */

void init_html()
{
    htbuf.buf = (char*)malloc(4096);
    htbuf.size = 4096;

    char *linebuf = (char*)malloc(256);
    size_t lbsz = 256;

    FILE* ws = fopen("index.html", "r");
    if(!ws){
        perror("Failed to open index.html");
        exit(EXIT_FAILURE);
    }
    while(getline(&linebuf, &lbsz, ws) != -1){
        strcat(htbuf.buf, linebuf);
    };
    //return htbuf;

}
/* ROUTES */
int root(int fd){

/* EDIT CONTENT LENGTH TO MATCH */
    char* ok = (char*)malloc(htbuf.size+60);
    snprintf(ok, htbuf.size+60,"HTTP/1.1 200 OK\nContent-Length: 1178\nContent-Type: text/html\nCache-Control: no-store\n\n\
%s", htbuf.buf);

    fprintf(stderr, "serving client: %s", ok); //debug print

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
serve(const char *restrict path, int filedes)
{
/* TODO: Add function pointers with an allowed routes struct, see code/play for implementation */

    size_t i;
    int(* funcptr)(int);
    int retval=1;
    for(i=0; i<routelen; i++){
        funcptr = routes[i].func;
        if(!strcmp(path, routes[i].name)){
            retval = funcptr(filedes);
        }
    }

    return retval;
}

int
process_request(int filedes, char *buffer)
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
               if(!strncmp(token, "HTTP/1.1", 8))
                   serve(path, filedes);
    }
    else {
        if(write(filedes, br, strlen(br)) < 0)
            perror("in process_request -> else -> write");
    }

return 0;
}

int
read_from_client (int filedes)
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
           /* Data read. PARSE HTTP HERE */
           /* tokenize (strtok?)  */
           fprintf (stderr, "Server: got message: `%s'\n", buffer);

           process_request(filedes, buffer);
           /* GET /path HTTP/1.1 */
           return 0;
         }
     }

int
main (void)
{
       extern int make_socket (uint16_t port);
       int sock;
       fd_set active_fd_set, read_fd_set;
       int i;
       struct sockaddr_in clientname;
       socklen_t size;

       /* Initialize HTML file by reading it into buffer */
       init_html();

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

