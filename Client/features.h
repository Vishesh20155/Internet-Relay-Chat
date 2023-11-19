#include "../common_structures.h"

/*Function to show the list of commands available to the users*/
void show_menu()
{
  /*
   * /exit
   */
}

void show_logged_in_users(int sock)
{
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
  user_list = (struct logged_in_user_struct *)malloc(data_len);
  receive_data(sock, (void *)user_list, data_len);

  // Print list:
  for (int i = 0; i < num_users; ++i)
  {
    printf("%d\t---\t%s\n", user_list[i].user_id, user_list[i].username);
  }
}

void broadcast_message(int sock)
{
  receive_ACK(sock);

  printf("\tMessage: ");
  char inp_message[BUFFER_SIZE];
  getchar();
  memset(inp_message, '\0', BUFFER_SIZE);
  if (fgets(inp_message, BUFFER_SIZE, stdin) != NULL)
  {
    printf("\tInput message: %s", inp_message);
  }
  else
  {
    printf("\tError reading input.\n");
  }

  send_data(sock, inp_message, strlen(inp_message));

  receive_ACK(sock);
}

void show_messages(int sock)
{
  char num_msgs_str[10];
  memset(num_msgs_str, '\0', 10);
  receive_data(sock, num_msgs_str, 10);

  int num_msgs = atoi(num_msgs_str);
  printf("Number of Pending messages for you: %d\n", num_msgs);

  if (num_msgs <= 0)
    return;

  // Send ACK
  send_ACK(sock);

  // Form a dynamic array
  struct message_struct *pending_msgs;
  int data_len = num_msgs * sizeof(struct message_struct);
  pending_msgs = (struct message_struct *)malloc(data_len);

  // Receive the messages
  receive_data(sock, pending_msgs, data_len);

  // Print received messages
  for (int i = 0; i < num_msgs; ++i)
  {
    printf("\tMessage from %s : %s\n", pending_msgs[i].sender_name, pending_msgs[i].content);
  }
}

void request_public_key(int sock)
{
  printf("UNIMPLEMENTED\n");
  // printf("Enter the user ID of the user: ");
  // int req_user_id;
  // scanf("%d", &req_user_id);
  // char req_uid_str[10];
  // memset(req_uid_str, '\0', 10);
  // sprintf(req_uid_str, "%d", req_user_id);

  // send_data(sock, req_uid_str, strlen(req_uid_str));

  // char resp[10];
  // memset(resp, '\0', 10);
  // receive_data(sock, resp, 10);

  // if(strcmp(resp, "NACK") == 0) {
  //   printf("Couldn't request the user as it does not exist\n");
  // }
}

void create_group(int sock)
{
  receive_ACK(sock);
  char grp_name[GRP_NAME_LEN];
  memset(grp_name, '\0', GRP_NAME_LEN);
  printf("\tGroup Name: ");
  scanf("%s", grp_name);
  send_data(sock, grp_name, strlen(grp_name));

  char grp_id_str[10];
  memset(grp_id_str, '\0', sizeof(grp_id_str));
  receive_data(sock, grp_id_str, sizeof(grp_id_str));

  int new_grp_id = atoi(grp_id_str);
  if(new_grp_id < 0) {
    printf("Unable to create group. Check server logs\n");
    return;
  }
  printf("Created group with Group ID: %d", new_grp_id);
}

void group_invite(int sock)
{
  receive_ACK(sock);

  printf("\tGroup ID: ");
  int gid;
  scanf("%d", &gid);

  int invitee_uid;
  printf("\tUser ID: ");
  scanf("%d", &invitee_uid);

  struct group_invite inv = {gid, invitee_uid};
  send_data(sock, (void *)&inv, sizeof(inv));

  char resp[BUFFER_SIZE];
  memset(resp, '\0', BUFFER_SIZE);

  receive_data(sock, (void *)resp, BUFFER_SIZE);

  printf("%s\n", resp);
}

void show_invites(int sock)
{
  // Receive number of pending invites
  char num_pending_invites_str[10];
  memset(num_pending_invites_str, '\0', sizeof(num_pending_invites_str));

  receive_data(sock, num_pending_invites_str, sizeof(num_pending_invites_str));
  int num_pending_invites = atoi(num_pending_invites_str);

  printf("\tYou have %d pending invites\n", num_pending_invites);

  // Check num_pending_invites > 0
  if(num_pending_invites <= 0) return;

  // Send ack
  send_ACK(sock);

  // Receive all pending invites
  struct group_struct *grp_invites;
  int datalen = num_pending_invites * sizeof(struct group_struct);
  grp_invites = (struct group_struct *)malloc(datalen);

  receive_data(sock, (void *)grp_invites, datalen);

  for(int i=0; i<num_pending_invites; ++i) {
    printf("Pending invite for Group ID: %d | Group name: %s\n", grp_invites[i].group_id, grp_invites[i].name);
  }
}

void group_invite_accept(int sock)
{
  receive_ACK(sock);

  printf("\tGroup ID: ");
  int gid;
  scanf("%d", &gid);

  char gid_str[10];
  memset(gid_str, '\0', 10);
  sprintf(gid_str, "%d", gid);

  send_data(sock, gid_str, strlen(gid_str));

  // Receive and print the response:
  char resp[BUFFER_SIZE];
  memset(resp, '\0', sizeof(resp));

  receive_data(sock, resp, sizeof(resp));
  printf("\t%s\n", resp);
}

int evaluate_inp_cmd(int sock, char *inp)
{
  if (strcmp(inp, "/exit") == 0)
  {
    return -1;
  }
  else if (strcmp(inp, "/who") == 0)
  {
    show_logged_in_users(sock);
  }
  else if (strcmp(inp, "/write_all") == 0)
  {
    broadcast_message(sock);
  }
  else if (strcmp(inp, "/show_messages") == 0)
  {
    show_messages(sock);
  }
  else if (strcmp(inp, "/create_group") == 0)
  {
    create_group(sock);
  }
  else if (strcmp(inp, "/group_invite") == 0)
  {
    group_invite(sock);
  }
  else if (strcmp(inp, "/show_invites") == 0)
  {
    show_invites(sock);
  }
  else if (strcmp(inp, "/group_invite_accept") == 0)
  {
    group_invite_accept(sock);
  }
  else if (strcmp(inp, "/request_public_key") == 0)
  {
    request_public_key(sock);
  }
  else if (strcmp(inp, "/send_public_key") == 0)
  {
  }
  else
  {
    printf("Invalid command. Try Again!\n\n");
    return 0;
  }

  printf("\n--------------\n");
  printf("Executed command successfully\n");
  printf("--------------\n");
  return 1;
}

void input_command(int sock)
{
  char inp_cmd[CMD_LEN];
  while (1)
  {
    memset(inp_cmd, '\0', CMD_LEN);
    printf("Command: ");
    scanf("%s", inp_cmd);

    send_data(sock, inp_cmd, strlen(inp_cmd));

    int retval = evaluate_inp_cmd(sock, inp_cmd);
    if (retval == -1)
    {
      return;
    }
  }
}