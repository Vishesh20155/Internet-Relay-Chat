#ifndef COMMON_H4
#define COMMON_H4

#include <openssl/rand.h>
#include "common_data.h"

void generate_session_key(unsigned char *key)
{
  // Generate key using OpenSSL's CSPRNG
  // Maybe an error here
  if (RAND_bytes(key, SESSION_KEY_LEN/2) != 1)
  {
    perror("Error generating session key");
    exit(EXIT_FAILURE);
  }
}

void *kdc_functionality(void *socket)
{
  int sock = *(int *)socket;
  struct NS_msg_1 msg1;
  struct NS_msg_2 msg2;
  int retval;


  // Receive message 1 of NS authentication
  receive_data(sock, (void *)&msg1, sizeof(msg1));
  printf("**** Data Received on KDC Server: %s | %d\n", msg1.uname, msg1.nonce);

  // Generate the session key
  unsigned char session_key[SESSION_KEY_LEN];
  memset(session_key, '\0', SESSION_KEY_LEN);
  generate_session_key(session_key);

  // Send message 2 of NS authentication
  msg2.nonce = msg1.nonce;
  strcpy(msg2.session_key, session_key);

  // Create a ticket here and encrypt it using Server's long term key
  struct ticket t1;
  strcpy(t1.session_key, session_key);
  strcpy(t1.uname, msg1.uname);

  int encrypted_ticket_len = encrypt_data((unsigned char *)&t1, sizeof(t1), all_users_details[0].key, NULL, msg2.encrypted_t);
  print_byte_data("\t** Encrypted Ticket", msg2.encrypted_t, encrypted_ticket_len);
  msg2.encrypted_t_len = encrypted_ticket_len;
  // strcpy(msg2.encrypted_t, "Encrypted Ticket!");

  // Encrypt with K(ab) and K(bs)
  char ciphertext[BUFFER_SIZE];
  memset(ciphertext, '\0', BUFFER_SIZE);
  int encryption_len = encrypt_data((unsigned char *)&msg2, sizeof(msg2), random_key, NULL, ciphertext);

  // Send encrypted data
  send_data(sock, (void *)ciphertext, encryption_len);

  retval = close(sock);
  if (retval < 0)
  {
    perror("Unable to close the socket");
    exit(EXIT_FAILURE);
  }

  return NULL;
}

#endif