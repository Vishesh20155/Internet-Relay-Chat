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
  struct ticket t1;
  decrypt_data(cipherticket, recv_ticket_len, all_keys[0], NULL, (unsigned char*)&t1);

  printf("Decrypted ticket at CHAT server: %s\n", t1.uname);
  print_byte_data("Decrypted SESSION KEY at chat server", t1.session_key, SESSION_KEY_LEN);

  // Send acknowledgement:
  send_data(sock, "1", 1);

  // Receive encrypted nonce2
  char ciphernonce2[BUFFER_SIZE];
  memset(ciphernonce2, '\0', BUFFER_SIZE);
  int recv_nonce2_len = receive_data(sock, ciphernonce2, BUFFER_SIZE);

  // Decrypt nonce2
  char nonce2_str[BUFFER_SIZE];
  memset(nonce2_str, '\0', BUFFER_SIZE);
  decrypt_data(ciphernonce2, recv_nonce2_len, t1.session_key, NULL, nonce2_str);
  int nonce2 = atoi(nonce2_str);
  printf("Nonce2 received at CHAT server: %d\n", nonce2);

  // Encrypt Nonce2-1, Nonce3
  int nonce3 = generate_nonce();
  printf("Generated Nonce3 @ Chat server: %d\n", nonce3);
  struct NS_msg_3 msg3 = {nonce2-1, nonce3};
  char ciphermsg3[BUFFER_SIZE];
  memset(ciphermsg3, '\0', BUFFER_SIZE);
  int enc_msg3_len = encrypt_data((unsigned char *)&msg3, sizeof(msg3), t1.session_key, NULL, ciphermsg3);

  // Send Nonce2-1, Nonce3
  send_data(sock, ciphermsg3, enc_msg3_len);

  // Receive Nonce3-1
  char ciphernonce3_resp[BUFFER_SIZE];
  memset(ciphernonce3_resp, '\0', BUFFER_SIZE);
  int recv_nonce3_resp_len = receive_data(sock, ciphernonce3_resp, BUFFER_SIZE);

  // Decrypt Nonce3-1
  char nonce3_resp_str[NONCE_LEN];
  memset(nonce3_resp_str, '\0', NONCE_LEN);
  decrypt_data(ciphernonce3_resp, recv_nonce3_resp_len, t1.session_key, NULL, nonce3_resp_str);

  int nonce3_resp = atoi(nonce3_resp_str);
  printf("Nonce 3 response received on Chat server: %d\n", nonce3_resp);

  retval = close(sock);
  if (retval < 0)
  {
    perror("Unable to close the CHAT socket");
    exit(EXIT_FAILURE);
  }

  printf("-----------------\n");
  return NULL;
}

#endif