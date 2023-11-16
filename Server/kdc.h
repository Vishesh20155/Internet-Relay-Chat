#include "../common_structures.h"

void *kdc_functionality(void *socket)
{
  int sock = *(int *)socket;
  struct NS_msg_1 msg1;
  struct NS_msg_2 msg2;
  int retval;

  // Receive message 1 of NS authentication
  receive_data(sock, (void *)&msg1, sizeof(msg1));
  printf("Data Received on KDC Server: %s | %d\n", msg1.uname, msg1.nonce);

  // Send message 2 of NS authentication
  msg2.nonce = msg1.nonce;
  strcpy(msg2.session_key, "Fake session key");
  // msg2->t.uname = msg1.uname;
  // strcpy(msg2->t.session_key, "1234567890");

  // Encrypt with K(ab) and K(bs)
  char ciphertext[BUFFER_SIZE];
  memset(ciphertext, '\0', BUFFER_SIZE);
  int encryption_len = encrypt_data((unsigned char *)&msg2, sizeof(msg2), random_key, NULL, ciphertext);

  printf("Length of cipher text in KDC server: %d\n", encryption_len);

  // Send encrypted data
  send_data(sock, (void *)ciphertext, encryption_len);

  retval = close(sock);
  if(retval < 0) {
    perror("Unable to close the socket");
    exit(EXIT_FAILURE);
  }
  return NULL;
}