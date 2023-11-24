#include <arpa/inet.h>

#include "ns_auth.h"
#include "features.h"

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

  int num_fail_attempts = 0;
  bool pass_auth = false;
  while((!pass_auth) && num_fail_attempts < 3){
  
    memset(username, '\0', UNAME_LEN);
    printf("Username: ");
    scanf("%30s", username);

    memset(password, '\0', PASSWORD_LEN);
    printf("Password: ");
    scanf("%30s", password);

    if(strcmp(username, password) == 0) {
      pass_auth = true;
    }
    else{
      printf("Invalid authentication. Try again!\n\n");
      num_fail_attempts++;
    }
  }

  if(!pass_auth) {
    printf("Could not authenticate thrice!!\n");
    exit(EXIT_FAILURE);
  }

  srand(time(0));

  // Connect to KDC server
  int kdc_sock = connect_server(kdc_server);

  // Authenticate NS part 1
  struct NS_msg_2 msg2;
  bool isAuthenticated = ns_part_1(kdc_sock, &msg2, username);
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
  isAuthenticated = ns_part_2(chat_sock, msg2);
  if(!isAuthenticated) {
    printf("Authentication failed!!\n");
    return 1;
  }

  printf("NS part 2 done\n");

  printf("PID: %d\n", getpid());

  printf("\n----------------\n");
  printf("\n----------------\n\n");

  // Show the menu
  input_command(chat_sock);

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