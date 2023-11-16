#include "../common_structures.h"

bool ns_part_1(int sock) {
  struct NS_msg_1 msg1 = {"username", generate_nonce()};
  send_data(sock, (void *)&msg1, sizeof(msg1));
  
  struct NS_msg_2 msg2;
  receive_data(sock, (void *)&msg2, sizeof(msg2));
  // Decrypt here:
  printf("Received: %d | %s\n", msg2.nonce, msg2.session_key);
}