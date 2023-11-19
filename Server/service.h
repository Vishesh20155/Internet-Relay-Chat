#ifndef COMMON_H5
#define COMMON_H5

#include "common_data.h"

// Helper mfunction to show details of all the groups created
void show_all_groups()
{
  printf("Details of all the groups:\n");
  pthread_mutex_lock(&mutex_grp);

  for (int i = 0; i < num_grps_created; ++i)
  {
    printf("Group ID: %d | Name: %s\n", all_groups[i].group_id, all_groups[i].name);
    printf("\tUsers (%d): ", all_groups[i].num_members);
    for (int j = 0; j < all_groups[i].num_members; ++j)
    {
      printf("%d ", all_groups[i].users[j]);
    }
    printf("\n\n");
  }

  pthread_mutex_unlock(&mutex_grp);
}

void get_logged_in_users(int sock)
{
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
  send_data(sock, (void *)logged_in_user_list, num_logged_in_users * sizeof(struct logged_in_user_struct));
  pthread_mutex_unlock(&mutex_log_in);
}

void broadcast_message_to_logged_in(int sock, char *curr_username, int curr_user_id)
{
  send_ACK(sock);

  struct message_struct message;
  memset(message.sender_name, '\0', sizeof(message.sender_name));
  memset(message.content, '\0', sizeof(message.content));

  receive_data(sock, message.content, sizeof(message.sender_name));
  strcpy(message.sender_name, curr_username);

  send_ACK(sock);

  // Add the message to all the users pending messages list
  pthread_mutex_lock(&mutex_log_in);
  for (int i = 0; i < num_logged_in_users; ++i)
  {
    if (logged_in_user_list[i].user_id == curr_user_id)
    {
      continue;
    }

    int receiver_uid = logged_in_user_list[i].user_id;
    int q_len = num_pending_msgs[receiver_uid];
    if (q_len >= MAX_MSG_QUEUE_LEN)
    {
      printf("Pending message queue length full for client: %s\n", logged_in_user_list[i].username);
      continue;
    }
    memset(pending_msgs[receiver_uid][q_len].sender_name, '\0', sizeof(pending_msgs[receiver_uid][q_len].sender_name));
    memset(pending_msgs[receiver_uid][q_len].content, '\0', sizeof(pending_msgs[receiver_uid][q_len].content));

    strcpy(pending_msgs[receiver_uid][q_len].sender_name, curr_username);
    strcpy(pending_msgs[receiver_uid][q_len].content, message.content);
    num_pending_msgs[receiver_uid]++;
  }
  pthread_mutex_unlock(&mutex_log_in);
}

void send_pending_messages(int sock, char *curr_username, int curr_user_id)
{
  char num_msgs_str[10];
  memset(num_msgs_str, '\0', 10);

  pthread_mutex_lock(&mutex_log_in);
  sprintf(num_msgs_str, "%d", num_pending_msgs[curr_user_id]);
  pthread_mutex_unlock(&mutex_log_in);

  send_data(sock, num_msgs_str, 10);

  int num_msgs = atoi(num_msgs_str);
  if (num_msgs <= 0)
    return;

  // Receive ACK
  receive_ACK(sock);

  int data_len = num_msgs * sizeof(struct message_struct);

  pthread_mutex_lock(&mutex_log_in);

  send_data(sock, pending_msgs[curr_user_id], data_len);
  for (int i = 0; i < num_msgs; ++i)
  {
    memset(pending_msgs[curr_user_id][i].content, '\0', sizeof(pending_msgs[curr_user_id][i].content));
    memset(pending_msgs[curr_user_id][i].sender_name, '\0', sizeof(pending_msgs[curr_user_id][i].sender_name));
  }
  num_pending_msgs[curr_user_id] = 0;

  pthread_mutex_unlock(&mutex_log_in);
}

void create_new_group(int sock, int user_id)
{
  send_ACK(sock);
  char grp_name[GRP_NAME_LEN];
  memset(grp_name, '\0', GRP_NAME_LEN);

  int new_grp_id = -1;

  receive_data(sock, grp_name, GRP_NAME_LEN);

  pthread_mutex_lock(&mutex_grp);
  if (num_grps_created < MAX_NUM_GRPS)
  {
    all_groups[num_grps_created].group_id = num_grps_created;
    all_groups[num_grps_created].users[0] = user_id;
    all_groups[num_grps_created].num_members = 1;
    memset(all_groups[num_grps_created].name, '\0', sizeof(all_groups[num_grps_created].name));
    strcpy(all_groups[num_grps_created].name, grp_name);
    group_user_status[num_grps_created][user_id] = 2;
    new_grp_id = num_grps_created;
    num_grps_created++;
  }
  else
  {
    printf("Number of groups limit reached!!\n");
  }

  pthread_mutex_unlock(&mutex_grp);

  char grp_id_str[10];
  memset(grp_id_str, '\0', sizeof(grp_id_str));
  sprintf(grp_id_str, "%d", new_grp_id);
  send_data(sock, grp_id_str, strlen(grp_id_str));

  show_all_groups();
}

void send_grp_invite(int sock, int uid)
{
  send_ACK(sock);

  struct group_invite inv;
  receive_data(sock, (void *)&inv, sizeof(inv));

  char resp[BUFFER_SIZE];
  memset(resp, '\0', BUFFER_SIZE);

  pthread_mutex_lock(&mutex_grp);
  if(inv.gid >= num_grps_created)
  {
    strcpy(resp, "Invalid group ID");
  }
  else if(inv.invitee_uid >= NUM_USERS)
  {
    strcpy(resp, "Invalid User ID");
  }
  else if(all_groups[inv.gid].users[0] != uid)
  {
    // Not group creator
    strcpy(resp, "You are not the creator of this group");
  }
  else if(group_user_status[inv.gid][inv.invitee_uid] == 2) {
    // User already a part of the group
    strcpy(resp, "User already part of this group");
  }
  else {
    // User invited
    group_user_status[inv.gid][inv.invitee_uid] = 1;
    strcpy(resp, "Invitation sent");
  }
  pthread_mutex_unlock(&mutex_grp);

  send_data(sock, resp, strlen(resp));
}

void check_pending_invites(int sock, int uid)
{
  // Find num_pending_invites
  int num_pending_invites = 0;
  pthread_mutex_lock(&mutex_grp);
  for(int i=0; i<num_grps_created; ++i) {
    if(group_user_status[i][uid] == 1)
    {
      num_pending_invites++;
    }
  }
  pthread_mutex_unlock(&mutex_grp);

  char num_pending_invites_str[10];
  memset(num_pending_invites_str, '\0', sizeof(num_pending_invites_str));
  sprintf(num_pending_invites_str, "%d", num_pending_invites);
  send_data(sock, num_pending_invites_str, sizeof(num_pending_invites_str));

  // Check num_pending_invites > 0
  if(num_pending_invites <= 0) return;

  // Receive ACK
  receive_ACK(sock);

  // Send all pending invites
  struct group_struct *grp_invites;
  int datalen = num_pending_invites * sizeof(struct group_struct);
  grp_invites = (struct group_struct *)malloc(datalen);
  int added_grps = 0;
  pthread_mutex_lock(&mutex_grp);
  for(int i=0; i<num_grps_created; ++i) {
    if(group_user_status[i][uid] == 1)
    {
      memcpy((void *)&(grp_invites[added_grps]), (void *)&(all_groups[i]), sizeof(struct group_struct));
      added_grps++;
    }
  }
  pthread_mutex_unlock(&mutex_grp);

  send_data(sock, (void *)grp_invites, datalen);
}

void accept_invitation(int sock, int uid)
{
  send_ACK(sock);
  
  // Receive the group ID
  char gid_str[10];
  memset(gid_str, '\0', 10);
  receive_data(sock, gid_str, sizeof(gid_str));

  int gid = atoi(gid_str);

  char resp[BUFFER_SIZE];
  memset(resp, '\0', sizeof(resp));
  
  pthread_mutex_lock(&mutex_grp);
  
  if(gid >= num_grps_created) // check validity of group id
  {
    strcpy(resp, "Invalid Group ID entered");
  }
  else if(group_user_status[gid][uid] != 1) // check if invited
  {
    strcpy(resp, "You were not invited to this group");
  }
  else  // Invite accepted
  {
    strcpy(resp, "Invitation Accepted!");
    // Update the status and the member to group
    group_user_status[gid][uid] = 2;
    int curr_num = all_groups[gid].num_members;
    all_groups[gid].users[curr_num] = uid;
    all_groups[gid].num_members++;
  }

  pthread_mutex_unlock(&mutex_grp);

  send_data(sock, resp, strlen(resp));

  show_all_groups();
}

void initiate_DHKE(int sock, int uid, DH *dh)
{
  // Receive the group ID
  // char gid_str[10];
  // memset(gid_str, '\0', 10);
  // receive_data(sock, gid_str, sizeof(gid_str));

  // int gid = atoi(gid_str);

  // pthread_mutex_lock(&mutex_grp);
  
  // if(gid >= num_grps_created) // check validity of group id
  // {
  //   strcpy(resp, "Invalid Group ID entered");
  // }
  // else if(all_groups[gid].users[0] != uid) // check if owner of group or not
  // {
  //   strcpy(resp, "You not the creator of this group");
  // }

  // pthread_mutex_unlock(&mutex_grp);
}

void create_public_key_request(int sock, int uid)
{
  send_ACK(sock);
  char inp_uname[UNAME_LEN];
  memset(inp_uname, '\0', UNAME_LEN);
  receive_data(sock, inp_uname, sizeof(inp_uname));

  pthread_mutex_lock(&mutex_log_in);
  int found = 0;
  for(int i=0; i<num_logged_in_users; ++i) {
    if(strcmp(inp_uname, logged_in_user_list[i].username) == 0) {
      found = 1;
      break;
    }
  }
  pthread_mutex_unlock(&mutex_log_in);

  char resp[BUFFER_SIZE];
  memset(resp, '\0', sizeof(resp));

  if(found == 0) {
    strcpy(resp, "User is not logged in!");
  }
  else {
    strcpy(resp, "Requested the user for public key");
  }
  send_data(sock, resp, strlen(resp));
}

void supply_public_key(int sock, int uid, char *pub_key)
{
  // send_ACK(sock);
  // char inp_uname[UNAME_LEN];
  // memset(inp_uname, '\0', UNAME_LEN);

  // receive_data(sock, inp_uname, sizeof(inp_uname));
  // // No error handling done
  // int dest_sock = -1, target_uid = -1;
  // pthread_mutex_lock(&mutex_log_in);
  // for(int i=0; i<num_logged_in_users; ++i) {
  //   if(strcmp(inp_uname, logged_in_user_list[i].username) == 0) {
  //     dest_sock = logged_in_user_list[i].sock_fd;
  //     target_uid = logged_in_user_list[i].user_id;
  //     break;
  //   }
  // }
  // pthread_mutex_unlock(&mutex_log_in);

  // char resp[BUFFER_SIZE];
  // memset(resp, '\0', sizeof(resp));
  // sprintf(resp, "Public Key: %s", all_public_keys_hex[target_uid]);

  // send_data(dest_sock, resp, strlen(resp));
  
  // memset(resp, '\0', sizeof(resp));

  char resp[BUFFER_SIZE];
  memset(resp, '\0', sizeof(resp));
  pthread_mutex_lock(&mutex_dh);
  strcpy(all_public_keys_hex[uid], pub_key);
  pthread_mutex_unlock(&mutex_dh);
  strcpy(resp, "Sent public key successfully");
}

int handle_cmd(int sock, char *inp, char *curr_username, int curr_user_id, char *public_key)
{
  if (strcmp(inp, "/exit") == 0)
  {
    return -1;
  }
  else if (strcmp(inp, "/who") == 0)
  {
    get_logged_in_users(sock);
  }
  else if (strcmp(inp, "/write_all") == 0)
  {
    broadcast_message_to_logged_in(sock, curr_username, curr_user_id);
  }
  else if (strcmp(inp, "/show_messages") == 0)
  {
    send_pending_messages(sock, curr_username, curr_user_id);
  }
  else if (strcmp(inp, "/create_group") == 0)
  {
    create_new_group(sock, curr_user_id);
  }
  else if (strcmp(inp, "/group_invite") == 0)
  {
    send_grp_invite(sock, curr_user_id);
  }
  else if (strcmp(inp, "/show_invites") == 0)
  {
    check_pending_invites(sock, curr_user_id);
  }
  else if (strcmp(inp, "/group_invite_accept") == 0)
  {
    accept_invitation(sock, curr_user_id);
  }
  else if (strcmp(inp, "/request_public_key") == 0)
  {
    create_public_key_request(sock, curr_user_id);
  }
  else if (strcmp(inp, "/send_public_key") == 0)
  {
    supply_public_key(sock, curr_user_id, public_key);
  }
  else if (strcmp(inp, "/init_group_dhxchg") == 0)
  {
    // initiate_DHKE(sock, curr_user_id, dh);
  }
  else
  {
    // In case of invalid command
    return 0;
  }

  return 1;
}

void serve_client(int sock, int userid, char *username)
{
  char hex_pub_key[DH_PUB_KEY_LEN+1];
  memset(hex_pub_key, '\0', sizeof(hex_pub_key));
  receive_data(sock, hex_pub_key, DH_PUB_KEY_LEN);

  pthread_mutex_lock(&mutex_dh);
  memset(all_public_keys_hex[userid], '\0', sizeof(all_public_keys_hex[userid]));
  strcpy(all_public_keys_hex[userid], hex_pub_key);
  pthread_mutex_unlock(&mutex_dh);

  while (1)
  {
    char command[CMD_LEN];
    memset(command, '\0', CMD_LEN);
    receive_data(sock, command, CMD_LEN);
    int retval = handle_cmd(sock, command, username, userid, hex_pub_key);

    if (retval == -1)
    {
      return;
    }
  }
}

#endif