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
  print_byte_data("Sending Encrypted ticket", msg2.encrypted_t, msg2.encrypted_t_len);
  send_data(sock, msg2.encrypted_t, msg2.encrypted_t_len);

  // Send Encrypted Nonce2

  // Receive Encrypted (Nonce2-1, Nonce3)

  // Send Nonce3-1
  
  // TODO: Return false in case of invalid response
  return true;
}