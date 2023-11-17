#ifndef COMMON_H1
#define COMMON_H1

#include "common_data.h"

void *chat_functionality(void *socket)
{
  int sock = *(int *)socket;

  int retval;

  // Receive ticket
  char cipherticket[ENCRYPTED_TICKET_LEN];
  size_t recv_ticket_len = receive_data(sock, cipherticket, ENCRYPTED_TICKET_LEN);
  printf("Length of ticket received at chat server: %ld\n", recv_ticket_len);
  print_byte_data("\nReceived encrypted ticket at CHAT server", cipherticket, recv_ticket_len);
  struct ticket t1;
  decrypt_data(cipherticket, recv_ticket_len, all_keys[0], NULL, (unsigned char*)&t1);

  printf("\t## Decrypted ticket at CHAT server: %s\n", t1.uname);
  print_byte_data("Decrypted SESSION KEY at chat server", t1.session_key, SESSION_KEY_LEN);

  // Receive message 3 of NS authentication

  // Send message 4 of NS authentication

  // Receive message 5 of NS authentication

  retval = close(sock);
  if (retval < 0)
  {
    perror("Unable to close the socket");
    exit(EXIT_FAILURE);
  }

  printf("-----------------\n");
  return NULL;
}

#endif