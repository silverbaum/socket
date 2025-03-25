#include <asm-generic/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

extern void init_sockaddr(struct sockaddr_in *, const char *, unsigned int );
extern int make_socket(unsigned short int);

void
init_sockaddr(struct sockaddr_in *name,
	      const char *hostname,
	      unsigned int port)
{
  struct hostent *hostinfo;

  name->sin_family = AF_INET; //IPv4
  name->sin_port = htons(port); //convert network byte order
  hostinfo = gethostbyname(hostname);
  if(hostinfo == NULL)
    {
      fprintf (stderr, "Unknown host %s.\n", hostname);
      exit(EXIT_FAILURE);
    }
  name->sin_addr = *(struct in_addr *) hostinfo->h_addr;
}


int
make_socket (short unsigned int port)
{
  int sock;
  struct sockaddr_in name;

  sock=socket(PF_INET, SOCK_STREAM, 0);
  if(sock<0){
    perror("socket");
    exit(EXIT_FAILURE);
  }

  int sad = 1;
  setsockopt((sock), 0, SO_REUSEADDR, &sad, 1);

  name.sin_family = AF_INET;
  name.sin_port = htons(port);
  name.sin_addr.s_addr = htonl(INADDR_ANY);
  if(bind(sock, (struct sockaddr *) &name, sizeof(name)) < 0){
    perror("bind");
    exit(EXIT_FAILURE);
  }
  return sock;
}
