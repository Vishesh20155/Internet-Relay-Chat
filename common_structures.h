#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define KDC_PORT 8888
#define CHAT_PORT 9999
#define KDC_SERVER 1
#define CHAT_SERVER 2
#define SERVER_IP "127.0.0.1"
#define BUFFER_SIZE 512

#define UNAME_LEN 128

struct server_args
{
  int port;
  // Define the type of server
  int server_type;
};

struct NS_msg_1 {
  char uname[UNAME_LEN];
  int nonce;
};

struct ticket {
  char *session_key;
  char *uname;
};

int generate_nonce() {
  // TODO: Complete this function to get a random integer
  return 5;
}

void encrypt_data(char *plaintext, char *key, char *ciphertext) {

}

void decrypt_data(char *ciphertext, char *key, char *plaintext) {

}

void send_data(int sock_fd, void *data, size_t data_len) {
  int retval = send(sock_fd, data, data_len, 0);
  if(retval < 0) {
    perror("Unable to send data");
    exit(EXIT_FAILURE);
  }
}

void receive_data(int sock_fd, void *data, size_t data_len) {
  int retval = recv(sock_fd, data, data_len, 0);
  if(retval < 0) {
    perror("Unable to receive data");
    exit(EXIT_FAILURE);
  }
}

#endif // COMMON_H