#include "../common_structures.h"

bool ns_part_1(int sock) {
  // Send message 1
  struct NS_msg_1 msg1 = {"username", generate_nonce()};
  send_data(sock, (void *)&msg1, sizeof(msg1));
  
  // Receive message 2
  struct NS_msg_2 msg2;
  char ciphertext[BUFFER_SIZE];
  memset(ciphertext, '\0', BUFFER_SIZE);

  size_t recv_len = receive_data(sock, (void *)ciphertext, BUFFER_SIZE);

  // Decrypt message 2:
  decrypt_data(ciphertext, recv_len, random_key, NULL, (unsigned char *)&msg2);
  printf("Received: %d | %s\n", msg2.nonce, msg2.session_key);
}