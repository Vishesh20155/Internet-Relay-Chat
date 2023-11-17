#include "../common_structures.h"

/*Function to show the list of commands available to the users*/
void show_menu() {
  /*
  * /exit
  */
}

void show_logged_in_users(int sock) {
  char num_users_str[10];
  memset(num_users_str, '\0', 10);
  receive_data(sock, num_users_str, 10);

  int num_users = atoi(num_users_str);
  printf("Number of logged in users: %d\n", num_users);

  // Send ACK
  send_data(sock, "ACKNO", 3);

  // Receive list
  struct logged_in_user_struct *user_list;
  int data_len = num_users * sizeof(struct logged_in_user_struct);
  user_list = (struct logged_in_user_struct*)malloc(data_len);
  receive_data(sock, (void *)user_list, data_len);

  // Print list:
  for(int i=0; i<num_users; ++i) {
    printf("%d\t---\t%s\n", user_list[i].user_id, user_list[i].username);
  }
}

int evaluate_inp_cmd(int sock, char *inp) {
  if(strcmp(inp, "/exit") == 0) {
    return -1;
  }
  else if(strcmp(inp, "/who") == 0) {
    show_logged_in_users(sock);
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
    printf("Invalid command. Try Again!\n\n");
    return 0;
  }

  printf("\n--------------\n");
  printf("Executed command successfully\n");
  printf("\n--------------\n");
  return 1;
}

void input_command(int sock) {
  char inp_cmd[CMD_LEN];
  while(1) {
    memset(inp_cmd, '\0', CMD_LEN);
    printf("Command: ");
    scanf("%s", inp_cmd);

    send_data(sock, inp_cmd, strlen(inp_cmd));

    int retval = evaluate_inp_cmd(sock, inp_cmd);
    if(retval == -1) {
      return;
    }
  }
}