#ifndef COMMON_H5
#define COMMON_H5

#include "common_data.h"

// Helper mfunction to show details of all the groups created
void show_all_groups()
{
  printf("Details of all the groups:\n");
  pthread_mutex_lock(&mutex_grp);

  for(int i=0; i<num_grps_created; ++i)
  {
    printf("Group ID: %d | Name: %s\n", all_groups[i].group_id, all_groups[i].name);
    printf("\tUsers (%d): ", all_groups[i].num_members);
    for(int j=0; j<all_groups[i].num_members; ++j)
    {
      printf("%d ", all_groups[i].users[j]);
    }
    printf("\n\n");
  }

  pthread_mutex_unlock(&mutex_grp);
}

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
  for(int i=0; i<num_logged_in_users; ++i) {
    if(logged_in_user_list[i].user_id == curr_user_id) {
      continue;
    }

    int receiver_uid = logged_in_user_list[i].user_id;
    int q_len = num_pending_msgs[receiver_uid];
    if(q_len >= MAX_MSG_QUEUE_LEN) {
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

void send_pending_messages(int sock, char *curr_username, int curr_user_id) {
  char num_msgs_str[10];
  memset(num_msgs_str, '\0', 10);
  
  pthread_mutex_lock(&mutex_log_in);
  sprintf(num_msgs_str, "%d", num_pending_msgs[curr_user_id]);
  pthread_mutex_unlock(&mutex_log_in);

  send_data(sock, num_msgs_str, 10);

  int num_msgs = atoi(num_msgs_str);
  if(num_msgs <= 0) return;

  // Receive ACK
  receive_ACK(sock);

  int data_len = num_msgs * sizeof(struct message_struct);

  pthread_mutex_lock(&mutex_log_in);

  send_data(sock, pending_msgs[curr_user_id], data_len);
  for(int i=0; i<num_msgs; ++i) {
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

  receive_data(sock, grp_name, GRP_NAME_LEN);

  pthread_mutex_lock(&mutex_grp);
  if(num_grps_created < MAX_NUM_GRPS){
    all_groups[num_grps_created].group_id = num_grps_created;
    all_groups[num_grps_created].users[0] = user_id;
    all_groups[num_grps_created].num_members = 1;
    memset(all_groups[num_grps_created].name, '\0', sizeof(all_groups[num_grps_created].name));
    strcpy(all_groups[num_grps_created].name, grp_name);
    num_grps_created++;
  } 
  else {
    print("Number of groups limit reached!!\n");
  }

  pthread_mutex_unlock(&mutex_grp);

  send_ACK(sock);

  show_all_groups();
}

int handle_cmd(int sock, char *inp, char *curr_username, int curr_user_id) {
  if(strcmp(inp, "/exit") == 0) {
    return -1;
  }
  else if(strcmp(inp, "/who") == 0) {
    get_logged_in_users(sock);
  }
  else if(strcmp(inp, "/write_all") == 0) {
    broadcast_message_to_logged_in(sock, curr_username, curr_user_id);
  }
  else if(strcmp(inp, "/show_messages") == 0) {
    send_pending_messages(sock, curr_username, curr_user_id);
  }
  else if(strcmp(inp, "/create_group") == 0) {
    create_new_group(sock, curr_user_id);
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

void serve_client(int sock, int userid, char *username) {

  while(1) {
    char command[CMD_LEN];
    memset(command, '\0', CMD_LEN);
    receive_data(sock, command, CMD_LEN);
    int retval = handle_cmd(sock, command, username, userid);

    if(retval == -1) {
      return;
    }
  }
}

#endif