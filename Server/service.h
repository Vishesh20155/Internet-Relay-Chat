#ifndef COMMON_H5
#define COMMON_H5

#include "common_data.h"

void get_logged_in_users(int sock) {
  char num_users_str[10];
  memset(num_users_str, '\0', 10);

  pthread_mutex_lock(&mutex_log_in);
  sprintf(num_users_str, "%d", num_logged_in_users);
  pthread_mutex_unlock(&mutex_log_in);

  send_data(sock, num_users_str, 10);
  // Just to ensure no clash of send_data
  char random_buffer[5];
  receive_data(sock, random_buffer, 5);

  pthread_mutex_lock(&mutex_log_in);
  send_data(sock, (void *)logged_in_user_list, num_logged_in_users*sizeof(struct logged_in_user_struct));
  pthread_mutex_unlock(&mutex_log_in);
}

int handle_cmd(int sock, char *inp) {
  if(strcmp(inp, "/exit") == 0) {
    return -1;
  }
  else if(strcmp(inp, "/who") == 0) {
    get_logged_in_users(sock);
  }
  else if(strcmp(inp, "/write_all") == 0) {
    
  }
  else if(strcmp(inp, "/create_group") == 0) {
    
  }
  else if(strcmp(inp, "/group_invite") == 0) {
    
  }
  else if(strcmp(inp, "/group_invite_accept") == 0) {
    
  }
  else if(strcmp(inp, "/request_public_key") == 0) {
    
  }
  else if(strcmp(inp, "/send_public_key") == 0) {
    
  }
  else {
    // In case of invalid command
    return 0;
  }

  return 1;
}

void serve_client(int sock) {
  while(1) {
    char command[CMD_LEN];
    memset(command, '\0', CMD_LEN);
    receive_data(sock, command, CMD_LEN);
    int retval = handle_cmd(sock, command);

    if(retval == -1) {
      return;
    }
  }
}

#endif