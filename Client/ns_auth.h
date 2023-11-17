#include "../common_structures.h"

bool ns_part_1(int sock, struct NS_msg_2 *msg2, char *username) {
  // Send message 1
  struct NS_msg_1 msg1;
  msg1.nonce = generate_nonce();
  strcpy(msg1.uname, username);
  send_data(sock, (void *)&msg1, sizeof(msg1));
  
  // Receive message 2
  char ciphertext[BUFFER_SIZE];
  memset(ciphertext, '\0', BUFFER_SIZE);

  size_t recv_len = receive_data(sock, (void *)ciphertext, BUFFER_SIZE);

  // Decrypt message 2:
  decrypt_data(ciphertext, recv_len, random_key, NULL, (unsigned char *)msg2);
  printf("\tReceived Nonce: %d, encrypted ticket length: %d\n", msg2->nonce, msg2->encrypted_t_len);
  print_byte_data("\tReceived Session Key", msg2->session_key, SESSION_KEY_LEN);
  print_byte_data("\tReceived Encrypted ticket", msg2->encrypted_t, msg2->encrypted_t_len);

  // TODO: return false in case decryption fails
  return true;
}

bool ns_part_2(int sock, struct NS_msg_2 msg2) {
  // Send the encrypted ticket
  send_data(sock, msg2.encrypted_t, msg2.encrypted_t_len);
  printf("Sent encrypted ticket\n");

  // Receive acknowledgement to ensure the 2 sends dont mess up
  char ack_buffer[10];
  memset(ack_buffer, '\0', 10);
  receive_data(sock, ack_buffer, 1);

  // Send Encrypted Nonce2
  int nonce2 = generate_nonce();
  printf("Generated nonce @ Client: %d\n", nonce2);
  char nonce2_str[NONCE_LEN];
  sprintf(nonce2_str, "%d", nonce2);
  char ciphernonce2[BUFFER_SIZE];
  memset(ciphernonce2, '\0', BUFFER_SIZE);
  int enc_nonce2_len = encrypt_data(nonce2_str, strlen(nonce2_str), msg2.session_key, NULL, ciphernonce2);
  send_data(sock, ciphernonce2, enc_nonce2_len);

  // Receive Encrypted (Nonce2-1, Nonce3)
  char ciphermsg3[BUFFER_SIZE];
  memset(ciphermsg3, '\0', BUFFER_SIZE);
  int recv_msg3_len = receive_data(sock, ciphermsg3, BUFFER_SIZE);

  // Decrypt (Nonce2-1, Nonce3)
  struct NS_msg_3 msg3;
  decrypt_data(ciphermsg3, recv_msg3_len, msg2.session_key, NULL, (unsigned char*)&msg3);
  printf("Response of Nonce2: %d | Nonce3: %d\n", msg3.nonce2_resp, msg3.nonce3);
  int nonce3 = msg3.nonce3;

  // Encrypt Nonce3-1
  int nonce3_resp = nonce3-1;
  char ciphernonce3_resp[BUFFER_SIZE];
  memset(ciphernonce3_resp, '\0', BUFFER_SIZE);
  char nonce3_resp_str[NONCE_LEN];
  memset(nonce3_resp_str, '\0', NONCE_LEN);
  sprintf(nonce3_resp_str, "%d", nonce3_resp);
  int enc_nonce3_resp = encrypt_data(nonce3_resp_str, NONCE_LEN, msg2.session_key, NULL, ciphernonce3_resp);

  // Send Nonce3-1
  send_data(sock, ciphernonce3_resp, enc_nonce3_resp);
  
  // TODO: Return false in case of invalid response
  return true;
}