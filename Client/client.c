#include <arpa/inet.h>

#include "ns_auth.h"

int connect_server(struct server_args s_opts)
{
  int sock = 0, valread, server_port;
  struct sockaddr_in serv_addr;

  // Create socket
  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
  {
    printf("\n Socket creation error \n");
    return -1;
  }

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(s_opts.port);

  // Convert IPv4 address from text to binary form
  if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0)
  {
    printf("\nInvalid address/ Address not supported \n");
    return -1;
  }

  // Connect to the server
  if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
  {
    printf("\nConnection Failed \n");
    return -1;
  }

  return sock;
}

int main(int argc, char const *argv[])
{
  int retval;
  char *message = "Hello from client";

  struct server_args kdc_server = {KDC_PORT, KDC_SERVER}, chat_server = {CHAT_PORT, CHAT_SERVER};

  char username[UNAME_LEN], password[PASSWORD_LEN];
  
  printf("Username: ");
  scanf("%s", username);

  printf("Password: ");
  scanf("%s", password);

  // Connect to KDC server
  int kdc_sock = connect_server(kdc_server);

  // Authenticate NS part 1
  struct NS_msg_2 msg2;
  bool isAuthenticated = ns_part_1(kdc_sock, &msg2);
  if(!isAuthenticated) {
    printf("Authentication failed!!\n");
    return 1;
  }
  
  printf("NS part 1 done\n");

  // Close KDC connection
  retval = close(kdc_sock);
  if (retval < 0)
  {
    perror("Unable to close KDC socket at Client");
    exit(EXIT_FAILURE);
  }

  printf("\n----------------\n\n");

  // Connect to Chat server
  int chat_sock = connect_server(chat_server);

  // Authenticate NS part 2 --> bool
  send_data(chat_sock, message, strlen(message));
  printf("Message sent\n");

  char ciphertext[BUFFER_SIZE], plaintext[BUFFER_SIZE];
  memset(ciphertext, '\0', BUFFER_SIZE);
  memset(plaintext, '\0', BUFFER_SIZE);

  int recv_len = receive_data(chat_sock, ciphertext, BUFFER_SIZE);

  decrypt_data(ciphertext, recv_len, random_key, NULL, plaintext);

  printf("Decrypted Response from Chat Server: %s\n", plaintext);

  // Show the menu

  // Other Business Logic

  // Close chat socket
  retval = close(chat_sock);
  if (retval < 0)
  {
    perror("Unable to close Chat socket at Client");
    exit(EXIT_FAILURE);
  }

  return 0;
}