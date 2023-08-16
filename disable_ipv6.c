#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>

int socket_hurr(int domain, int type, int protocol)
{
  // Load the original socket function
  int (*original_socket)(int, int, int);
  original_socket = dlsym(RTLD_NEXT, "socket");

  // If the address family is AF_INET6, change it to AF_INET
  if (domain == AF_INET6) {
    domain = AF_INET;
#ifdef VERBOSE
    fprintf(stderr, "Intercepted an AF_INET6 socket call and changed it to AF_INET\n");
#endif
  }

  // Call the original socket function with modified parameters
  return original_socket(domain, type, protocol);
}

int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res)
{
  int (*original_getaddrinfo)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
  original_getaddrinfo = dlsym(RTLD_NEXT, "getaddrinfo");

  struct addrinfo new_hints = {0};

  if (hints)
    new_hints = *hints;

  // Set hints to request IPv4 addresses only
  if (new_hints.ai_family == AF_UNSPEC || hints->ai_family == AF_INET6) {
    new_hints.ai_family = AF_INET;
#ifdef VERBOSE
    fprintf(stderr, "Intercepted an AF_INET6/AF_UNSPEC getaddrinfo call and changed it to AF_INET\n");
#endif
  }

  return original_getaddrinfo(node, service, &new_hints, res);
}
