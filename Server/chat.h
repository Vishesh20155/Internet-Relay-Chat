#include "../common_structures.h"

void *chat_functionality(void *socket)
{
  int sock = *(int *)socket;
  char buffer[BUFFER_SIZE] = {0};
  int retval;

  // Receive message 1 of NS authentication
  receive_data(sock, buffer, BUFFER_SIZE);
  printf("Data Received on Chat Server: %s\n", buffer);

  // Send message 2 of NS authentication
  send_data(sock, "ChatResp", 8);

  retval = close(sock);
  if(retval < 0) {
    perror("Unable to close the socket");
    exit(EXIT_FAILURE);
  }
  return NULL;
}