#ifndef COMMON_H2
#define COMMON_H2

#include "../common_structures.h"

// Append new users to the end of the list and change the macro NUM_USERS
char all_unames[NUM_USERS][UNAME_LEN] = {"chat server", "vishesh", "larry", "bob", "harry", "joe", "alpha", "beta", "gamma", "delta"};
char all_pwds[NUM_USERS][PASSWORD_LEN] = {"chat server", "vishesh", "larry", "bob", "harry", "joe", "alpha", "beta", "gamma", "delta"};
unsigned char all_ssnkeys[NUM_USERS][SESSION_KEY_LEN];
int all_u_ids[NUM_USERS];

struct user_details all_users_details[NUM_USERS];

pthread_mutex_t mutex_log_in = PTHREAD_MUTEX_INITIALIZER;
int num_logged_in_users = 0;
// char logged_in_usernames[MAX_LOGGED_IN_USERS][UNAME_LEN];
struct logged_in_user_struct logged_in_user_list[MAX_LOGGED_IN_USERS];

// For messages
int num_pending_msgs[MAX_LOGGED_IN_USERS] = {0};
struct message_struct pending_msgs[MAX_LOGGED_IN_USERS][MAX_MSG_QUEUE_LEN];

// For groups
struct group_struct all_groups[MAX_NUM_GRPS];
int num_grps_created = 0;
pthread_mutex_t mutex_grp = PTHREAD_MUTEX_INITIALIZER;
/*
* Maintain the status of each user:
* * 0 - Not Invited
* * 1 - Invited
* * 2 - Accepted
*/
int group_user_status[MAX_NUM_GRPS][NUM_USERS];

// For Diffie Hellman
pthread_mutex_t mutex_dh = PTHREAD_MUTEX_INITIALIZER;
char all_public_keys_hex[NUM_USERS][DH_PUB_KEY_LEN];

void derive_all_keys()
{
  printf("^^^^^^Deriving all keys\n");
  for (int i = 0; i < NUM_USERS; ++i)
  {
    all_users_details[i].user_id = i;
    strcpy(all_users_details[i].username, all_unames[i]);
    strcpy(all_users_details[i].password, all_pwds[i]);
    password_to_key(all_users_details[i].password, all_users_details[i].key);
  }
}

void set_group_status(){
  for(int i=0; i<MAX_NUM_GRPS; ++i) {
    for(int j=0; j<NUM_USERS; ++j) {
      group_user_status[i][j] = 0;
    }
  }
}

int get_id_from_uname(char *username) {
  for(int i=0; i<NUM_USERS; ++i) {
    if(strcmp(all_users_details[i].username, username) == 0) return all_users_details[i].user_id;
  }
}

#endif