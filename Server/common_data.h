#ifndef COMMON_H2
#define COMMON_H2

#include "../common_structures.h"

// Append new users to the end of the list and change the macro NUM_USERS
char all_unames[NUM_USERS][UNAME_LEN] = {"chat server", "vishesh", "larry", "bob", "harry", "joe", "alpha", "beta", "gamma", "delta"};
char all_pwds[NUM_USERS][PASSWORD_LEN] = {"chat server", "vishesh", "larry", "bob", "harry", "joe", "alpha", "beta", "gamma", "delta"};
unsigned char all_ssnkeys[NUM_USERS][SESSION_KEY_LEN];
int all_u_ids[NUM_USERS];

struct user_details all_users_details[NUM_USERS];



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

#endif