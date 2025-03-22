
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

struct ht_buf{
char *buf;
size_t size;
};
struct ht_buf htbuf;


void init_html()
{
    htbuf.buf = (char*)malloc(2048);
    htbuf.size = 2048;

    char *linebuf = (char*)malloc(128);
    size_t lbsz = 128;

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

int
serve(const char *restrict path, int filedes)
{

char* ok = (char*)malloc(htbuf.size+60);
snprintf(ok, htbuf.size+60,"HTTP/1.1 200 OK\nContent-Length: 900\nContent-Type: text/html\n\n \
%s", htbuf.buf);

   /* const char *ok = "HTTP/1.1 200 OK\nContent-Length: 70\nContent-Type: text/html\n\n\
<!DOCTYPE html>\n<html lang=en>\n<body>\n<h1> Hello there </h1>\n</body>\n</html>";
*/

    if(!strncmp(path, "/", 1)){
        fprintf(stderr, "serving ok: %s", ok);
        if((write(filedes, ok, strlen(ok))) < 0){
            perror("Failed to send response");
            return -1;
        }
    }

    return 0;
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

