#include "../common_structures.h"

void *chat_functionality(void *socket)
{
  int sock = *(int *)socket;
  char buffer[BUFFER_SIZE];
  memset(buffer, '\0', BUFFER_SIZE);
  int retval;

  // Receive message 3 of NS authentication
  receive_data(sock, (void *)buffer, BUFFER_SIZE);
  printf("Data Received on Chat Server: %s\n", buffer);

  // Send message 4 of NS authentication
  char plaintext[BUFFER_SIZE], ciphertext[BUFFER_SIZE];
  memset(plaintext, '\0', BUFFER_SIZE);
  memset(ciphertext, '\0', BUFFER_SIZE);

  strcpy(plaintext, "Hello Rahul Bhai. Mera code chal rha hai!!");
  
  printf("Server sending plain text (%ld): %s\n", strlen(plaintext), plaintext);
  int encryption_len = encrypt_data(plaintext, strlen(plaintext), random_key, NULL, ciphertext);

  send_data(sock, ciphertext, encryption_len);

  // Receive message 5 of NS authentication

  retval = close(sock);
  if (retval < 0)
  {
    perror("Unable to close the socket");
    exit(EXIT_FAILURE);
  }
  return NULL;
}