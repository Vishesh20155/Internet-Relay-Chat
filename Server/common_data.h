#ifndef COMMON_H2
#define COMMON_H2

#include "../common_structures.h"

char all_usernames[NUM_USERS][UNAME_LEN] = {"chat server", "vishesh"};
char all_passwords[NUM_USERS][PASSWORD_LEN] = {"chat server", "vishesh"};
unsigned char all_keys[NUM_USERS][SESSION_KEY_LEN];

void derive_all_keys()
{
  printf("^^^^^^Deriving all keys\n");
  for (int i = 0; i < NUM_USERS; ++i)
  {
    password_to_key(all_passwords[i], all_keys[i]);
    // strcpy((char *)all_keys[i], all_passwords[i]);
  }
}

#endif