#include "../common_structures.h"

int socket_fd;
char client_pvt_key[DH_PRIV_KEY_LEN + 1];
DH *curr_dh;

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
  printf("\n\tNumber of Pending messages for you: %d\n", num_msgs);

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
    if (pending_msgs[i].grp_id == -1)
    {
      printf("\tMessage from %s : %s\n", pending_msgs[i].sender_name, pending_msgs[i].content);
    }
    else
    {
      send_ACK(sock);
      struct group_struct grp_details;
      receive_data(sock, (void *)&grp_details, sizeof(grp_details));
      // printf("@@@ %d ki AES key length for decryption: %ld\n", grp_details.group_id, strlen(grp_details.shared_aes_key));
      if (strlen(grp_details.shared_aes_key) != 32)
      {
        printf("\tMessage in group %d from %s : %s\n", pending_msgs[i].grp_id, pending_msgs[i].sender_name, pending_msgs[i].content);
      }
      else
      {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        unsigned char iv[16] = {0}; // Fixed IV for simplicity
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, grp_details.shared_aes_key, iv);

        int len, plaintext_len;
        unsigned char decrypted_message[BUFFER_SIZE];
        EVP_DecryptUpdate(ctx, decrypted_message, &len, pending_msgs[i].content, strlen(pending_msgs[i].content));
        plaintext_len = len;

        EVP_DecryptFinal_ex(ctx, decrypted_message + len, &len);
        plaintext_len += len;

        decrypted_message[plaintext_len] = '\0';
        printf("\tDecrypted Message in group %d from %s : %s\n", pending_msgs[i].grp_id, pending_msgs[i].sender_name, decrypted_message);
      }
    }
  }
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
  if (new_grp_id < 0)
  {
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

  printf("\n\tYou have %d pending invites\n", num_pending_invites);

  // Check num_pending_invites > 0
  if (num_pending_invites <= 0)
    return;

  // Send ack
  send_ACK(sock);

  // Receive all pending invites
  struct group_struct *grp_invites;
  int datalen = num_pending_invites * sizeof(struct group_struct);
  grp_invites = (struct group_struct *)malloc(datalen);

  receive_data(sock, (void *)grp_invites, datalen);

  for (int i = 0; i < num_pending_invites; ++i)
  {
    printf("\tPending invite for Group ID: %d | Group name: %s\n", grp_invites[i].group_id, grp_invites[i].name);
  }
}

void encrypt_dh_1(char *key, char *content, char *ciphertext) {
  strcpy(ciphertext, "Encrypted text");
}

void send_to(int target_uid, char *ciphertext) {
  int target_sock_fd = target_uid;

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

void encrypt_and_send(struct group_struct grp_details, char pub_keys[NUM_USERS][DH_PUB_KEY_LEN + 1])
{
  int owner_id = grp_details.users[0];
  char cipher_text[BUFFER_SIZE];
  for(int i=1; i<grp_details.num_members; ++i)
  {
    int target_uid = grp_details.users[i];
    char *encryption_key = pub_keys[target_uid];
    
    memset(cipher_text, '\0', BUFFER_SIZE);
    encrypt_dh_1(encryption_key, pub_keys[owner_id], cipher_text);
    send_to(target_uid, cipher_text);
  }
}

// compute_DH_key(sock, shared_secret, curr_uid, pub_keys, grp_details);
void compute_DH_key(int sock, int uid, unsigned char shared_key[SHARED_SECRET_LEN + 1], char pub_keys[NUM_USERS][DH_PUB_KEY_LEN + 1], struct group_struct grp_details)
{
  memset(shared_key, '\0', SHARED_SECRET_LEN + 1);
  int grp_mem_uid = grp_details.users[1];

  BIGNUM *server_pub_key = NULL;
  BN_hex2bn(&server_pub_key, pub_keys[grp_mem_uid]);
  DH_compute_key(shared_key, server_pub_key, curr_dh);

  // Hash the shared secret to derive an AES key
  unsigned char aes_key[32]; // AES-256 key
  EVP_Digest(shared_key, SHARED_SECRET_LEN, aes_key, NULL, EVP_sha256(), NULL);
  printf("### Length of AES key: %ld\n", strlen(aes_key));
  send_data(sock, aes_key, 32);

  printf("\tDerived and communicated the shared key to everyone in the group\n");

  receive_ACK(sock);
}

void init_group_dhxchg(int sock)
{
  printf("Client private key (%ld): %s\n", strlen(client_pvt_key), client_pvt_key);

  receive_ACK(sock);

  char gid_str[10];
  memset(gid_str, '\0', 10);
  int gid;

  printf("\tGroup ID: ");
  scanf("%d", &gid);

  sprintf(gid_str, "%d", gid);
  send_data(sock, gid_str, sizeof(gid_str));

  // Get the group details
  char resp[BUFFER_SIZE];
  memset(resp, '\0', strlen(resp));
  receive_data(sock, resp, sizeof(resp));

  if (strcmp(resp, "Success") != 0)
  {
    printf("%s\n", resp);
    return;
  }

  send_ACK(sock);
  struct group_struct grp_details;
  receive_data(sock, (void *)(&grp_details), sizeof(grp_details));

  // printf("\tNumber of members in the group: %d\n", grp_details.num_members);

  if (grp_details.num_members <= 1)
  {
    printf("\tThere should be atleast 2 members in the group!\n");
    return;
  }

  // Get public keys of all the users
  send_ACK(sock);
  char pub_keys[NUM_USERS][DH_PUB_KEY_LEN + 1];
  for (int i = 0; i < NUM_USERS; ++i)
  {
    memset(pub_keys[i], '\0', sizeof(pub_keys[i]));
  }

  receive_data(sock, pub_keys, sizeof(pub_keys));

  // Call this function to send encrypted g^A
  // to all the group members for
  // Diffie Hellman process to take place
  encrypt_and_send(grp_details, pub_keys);

  unsigned char shared_secret[SHARED_SECRET_LEN]; // Contains the key that will actually be used for encryption

  int curr_uid = grp_details.users[0];
  // Get the key from all the members
  // Decrypt that
  // Check the HMAC hash
  // char prev_shared_key[SHARED_SECRET_LEN];  // This is the key that will be used for HMAC key
  // strcpy(prev_shared_key, pub_keys[curr_uid]);
  // for(all group members){
  //   verify_and_decrypt(pub_keys, prev_shared_key, shared_secret);
  //   strcpy(prev_shared_key, shared_secret);
  // }

  // Function to compute the final key
  compute_DH_key(sock, curr_uid, shared_secret, pub_keys, grp_details);
}

void request_public_key(int sock)
{
  receive_ACK(sock);
  char inp_uname[UNAME_LEN];
  memset(inp_uname, '\0', UNAME_LEN);
  printf("Username: ");
  scanf("%s", inp_uname);

  send_data(sock, inp_uname, strlen(inp_uname));

  char resp[BUFFER_SIZE];
  memset(resp, '\0', BUFFER_SIZE);

  receive_data(sock, (void *)resp, BUFFER_SIZE);

  printf("%s\n", resp);
}

void send_public_key(int sock)
{
  // receive_ACK(sock);
  // char inp_uname[UNAME_LEN];
  // memset(inp_uname, '\0', UNAME_LEN);
  // printf("Username: ");
  // scanf("%s", inp_uname);

  // send_data(sock, inp_uname, strlen(inp_uname));

  char resp[BUFFER_SIZE];
  memset(resp, '\0', BUFFER_SIZE);

  receive_data(sock, (void *)resp, BUFFER_SIZE);

  printf("%s\n", resp);
}

void write_group(int sock)
{
  receive_ACK(sock);

  printf("\tGroup ID: ");
  int gid;
  scanf("%d", &gid);

  unsigned char *encryption_key = NULL;
  struct message_struct empty_msg;
  empty_msg.grp_id = gid;
  send_data(sock, (void *)&empty_msg, sizeof(empty_msg));
  struct group_struct grp_details;
  receive_data(sock, (void *)&grp_details, sizeof(grp_details));

  if (strlen(grp_details.shared_aes_key) == 32)
  {
    encryption_key = grp_details.shared_aes_key;
  }

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

  struct message_struct msg;
  msg.grp_id = gid;
  memset(msg.content, '\0', sizeof(msg.content));
  // encrypt the message here
  if (encryption_key == NULL)
  {
    printf("\n\t!! Encryption key not yet set, sending message in plain text !!\n");
    strcpy(msg.content, inp_message);
  }
  else
  {
    // printf("Length of encryption key: %ld\n", strlen(encryption_key));
    unsigned char iv[16] = {0};
    unsigned char encrypted_message[BUFFER_SIZE];
    memset(encrypted_message, '\0', BUFFER_SIZE);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, encryption_key, iv);

    int len, ciphertext_len;
    EVP_EncryptUpdate(ctx, encrypted_message, &len, (unsigned char *)inp_message, strlen(inp_message));
    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, encrypted_message + len, &len);
    ciphertext_len += len;

    strcpy(msg.content, encrypted_message);
  }
  memset(msg.sender_name, '\0', sizeof(msg.sender_name));

  send_data(sock, (void *)&msg, sizeof(msg));

  receive_ACK(sock);
}

void show_messages_signal_handler(int signal_number)
{
  char inp[25];
  memset(inp, '\0', sizeof(inp));

  receive_data(socket_fd, inp, sizeof(inp));

  if (strcmp(inp, "/show_messages") == 0)
  {
    send_data(socket_fd, "/show_messages", strlen("/show_messages"));
    show_messages(socket_fd);
  }
  else if (strcmp(inp, "/show_invites") == 0)
  {
    send_data(socket_fd, inp, strlen(inp));
    show_invites(socket_fd);
  }
  else if (strcmp(inp, "/request_public_key") == 0)
  {
    printf("Requested public key\n");
  }
  printf("--------------\n");
  printf("Command: ");
  fflush(stdout);
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
    send_public_key(sock);
  }
  else if (strcmp(inp, "/init_group_dhxchg") == 0)
  {
    init_group_dhxchg(sock);
  }
  else if (strcmp(inp, "/write_group") == 0)
  {
    write_group(sock);
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
  DH *dh = DH_get_2048_256();
  if (1 != DH_generate_key(dh))
    handleError();
  const BIGNUM *pub_key = NULL;
  DH_get0_key(dh, &pub_key, NULL);

  char *hex_pub_key = BN_bn2hex(pub_key);
  char *hex_pub_key_copy = (char *)malloc(strlen(hex_pub_key));

  memcpy(hex_pub_key_copy, hex_pub_key, strlen(hex_pub_key));

  send_data(sock, hex_pub_key_copy, strlen(hex_pub_key_copy));

  const BIGNUM *pvt_key = DH_get0_priv_key(dh);
  char *hex_pvt_key = BN_bn2hex(pvt_key);

  printf("Client private key (%ld): %s\n", strlen(hex_pvt_key), hex_pvt_key);

  memset(client_pvt_key, '\0', sizeof(client_pvt_key));
  strcpy(client_pvt_key, hex_pvt_key);
  curr_dh = dh;
  receive_ACK(sock);

  // Send the PID as well
  char client_pid_str[10];
  memset(client_pid_str, '\0', sizeof(client_pid_str));

  sprintf(client_pid_str, "%d", getpid());
  send_data(sock, client_pid_str, strlen(client_pid_str));

  socket_fd = sock;

  // Setup signal handler:
  if (signal(SIGUSR1, show_messages_signal_handler) == SIG_ERR)
  {
    perror("Error setting up signal handler");
  }

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