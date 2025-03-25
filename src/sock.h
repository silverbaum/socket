#ifndef SERVER_H_
#define SERVER_H_

extern void init_sockaddr(struct sockaddr_in *name, const char *hostname, unsigned int port);
extern int make_socket(unsigned short int port);

#endif // SERVER_H_
