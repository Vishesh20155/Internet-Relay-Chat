#ifndef COMMON_H3
#define COMMON_H3

#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "kdc.h"
#include "chat.h"

#define MAX_CLIENTS 5

void *start_server(void *thread_args)
{
  int retval;

  pthread_t thread;
  int server_fd, new_socket;
  struct sockaddr_in address;
  int opt = 1;
  int addrlen = sizeof(address);

  struct server_args *s_opts = (struct server_args *)thread_args;

  printf("@@@ Started server on port: %d\n", s_opts->port);

  server_fd = socket(AF_INET, SOCK_STREAM, 0);
  retval = setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
  if (retval < 0)
  {
    perror("Error in setsockopt");
    exit(EXIT_FAILURE);
  }

  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(s_opts->port);

  retval = bind(server_fd, (struct sockaddr *)&address, sizeof(address));
  if (retval < 0)
  {
    perror("Error in using bind");
    exit(EXIT_FAILURE);
  }

  retval = listen(server_fd, MAX_CLIENTS);
  if (retval < 0)
  {
    perror("Error in using listen");
    exit(EXIT_FAILURE);
  }

  while (1)
  {
    new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen);

    if (s_opts->server_type == CHAT_SERVER)
    {
      pthread_create(&thread, NULL, chat_functionality, (void *)&new_socket);
    }
    else if (s_opts->server_type == KDC_SERVER)
    {
      pthread_create(&thread, NULL, kdc_functionality, (void *)&new_socket);
    }
    else
    {
      perror("Invalid arguments in create_server");
    }

    pthread_detach(thread);
  }

  close(server_fd);
}

#endif