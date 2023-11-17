#ifndef COMMON_H1
#define COMMON_H1

#include "service.h"

void remove_logged_in_user(char *username) {
  int found = 0;
  for(int i=0; i<num_logged_in_users; ++i) {
    if(found) {
      memset(logged_in_user_list[i-1].username, '\0', UNAME_LEN);
      strcpy(logged_in_user_list[i-1].username, logged_in_user_list[i].username);
      logged_in_user_list[i-1].user_id = logged_in_user_list[i].user_id;
    }
    if(strcmp(username, logged_in_user_list[i].username) == 0) {
      found = 1;
    }
  }

  memset(logged_in_user_list[num_logged_in_users-1].username, '\0', UNAME_LEN);
  logged_in_user_list[num_logged_in_users-1].user_id = -1;
}

void *chat_functionality(void *socket)
{
  int sock = *(int *)socket;

  int retval;
  srand(time(0));

  // Receive ticket
  char cipherticket[ENCRYPTED_TICKET_LEN];
  size_t recv_ticket_len = receive_data(sock, cipherticket, ENCRYPTED_TICKET_LEN);
  struct ticket t1;
  decrypt_data(cipherticket, recv_ticket_len, all_users_details[0].key, NULL, (unsigned char*)&t1);

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

  // TODO: handle the failure case:
  if(nonce3-1 != nonce3_resp) {
    
  }
  
  printf("User %s authenticated to chat!!\n", t1.uname);
  // update the loggedin users list and number under mutex
  pthread_mutex_lock(&mutex_log_in);
  if(num_logged_in_users < MAX_LOGGED_IN_USERS) {
    memset(logged_in_user_list[num_logged_in_users].username, '\0', UNAME_LEN);
    strcpy(logged_in_user_list[num_logged_in_users].username, t1.uname);
    logged_in_user_list[num_logged_in_users].user_id = get_id_from_uname(t1.uname);
    num_logged_in_users++;
    pthread_mutex_unlock(&mutex_log_in);

    serve_client(sock);

    printf("It was a pleasure serving client: %s\n", t1.uname);

    pthread_mutex_lock(&mutex_log_in);
    // Remove element from list
    remove_logged_in_user(t1.uname);
    num_logged_in_users--;
    pthread_mutex_unlock(&mutex_log_in);
  }
  else {
    pthread_mutex_unlock(&mutex_log_in);
    printf("Can't serve Reached capacity of %d concurrent users\n", MAX_LOGGED_IN_USERS);
  }

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