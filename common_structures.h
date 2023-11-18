#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <time.h>

// OpenSSL libcrypto includes
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/dh.h>
#include <openssl/bn.h>

#define NUM_USERS 10
#define MAX_LOGGED_IN_USERS 10
#define MAX_MSG_QUEUE_LEN 10
#define MAX_NUM_GRPS 10

#define KDC_PORT 12345
#define CHAT_PORT 54321
#define KDC_SERVER 1
#define CHAT_SERVER 2
#define SERVER_IP "127.0.0.1"
#define BUFFER_SIZE 1024
#define UNAME_LEN 32
#define PASSWORD_LEN 32
#define GRP_NAME_LEN 32
#define ENCRYPTED_TICKET_LEN 128
#define SESSION_KEY_LEN 32
#define LONG_TERM_KEY_LEN 32
#define NONCE_LEN 10
#define CMD_LEN 100

unsigned char *random_key = (unsigned char *)"01234567890123456789012345678901";

struct server_args
{
  int port;
  // Define the type of server
  int server_type;
};

struct NS_msg_1
{
  char uname[UNAME_LEN];
  int nonce;
};

struct ticket
{
  unsigned char session_key[SESSION_KEY_LEN + 1];
  char uname[UNAME_LEN];
};

struct NS_msg_2
{
  int nonce;
  unsigned char session_key[SESSION_KEY_LEN];
  int encrypted_t_len;
  unsigned char encrypted_t[ENCRYPTED_TICKET_LEN];
};

struct NS_msg_3
{
  int nonce2_resp, nonce3;
};

struct user_details
{
  int user_id;
  char username[UNAME_LEN];
  char password[UNAME_LEN];
  unsigned char key[SESSION_KEY_LEN];
};

struct logged_in_user_struct
{
  int user_id;
  char username[UNAME_LEN];
};

struct message_struct {
  char sender_name[UNAME_LEN], content[BUFFER_SIZE];
};

struct group_struct
{
  int group_id, num_members;
  char name[GRP_NAME_LEN];
  int users[NUM_USERS];
};


int generate_nonce()
{
  int randomNum = rand()%INT16_MAX;
  return randomNum;
}

int encrypt_data(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                 unsigned char *iv, unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;

  // Create and initialise the context
  if (!(ctx = EVP_CIPHER_CTX_new()))
  {
    ERR_print_errors_fp(stderr);
    return 0;
  }

  // Initialise the encryption operation
  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
  {
    ERR_print_errors_fp(stderr);
    EVP_CIPHER_CTX_free(ctx);
    return 0;
  }

  // Provide the message to be encrypted, and obtain the encrypted output
  if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
  {
    ERR_print_errors_fp(stderr);
    EVP_CIPHER_CTX_free(ctx);
    return 0;
  }
  ciphertext_len = len;

  // Finalise the encryption
  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
  {
    ERR_print_errors_fp(stderr);
    EVP_CIPHER_CTX_free(ctx);
    return 0;
  }
  ciphertext_len += len;

  // Clean up
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int decrypt_data(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;

  // Create and initialize the context
  if (!(ctx = EVP_CIPHER_CTX_new()))
  {
    ERR_print_errors_fp(stderr);
    return 0;
  }

  // Initialize the decryption operation
  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
  {
    ERR_print_errors_fp(stderr);
    EVP_CIPHER_CTX_free(ctx);
    return 0;
  }

  // Provide the message to be decrypted, and obtain the plaintext output
  if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
  {
    ERR_print_errors_fp(stderr);
    EVP_CIPHER_CTX_free(ctx);
    return 0;
  }
  plaintext_len = len;

  // Finalize the decryption
  if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
  {
    ERR_print_errors_fp(stderr);
    EVP_CIPHER_CTX_free(ctx);
    return 0;
  }
  plaintext_len += len;

  // Clean up
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}

void send_data(int sock_fd, void *data, size_t data_len)
{
  int retval = send(sock_fd, data, data_len, 0);
  if (retval < 0)
  {
    perror("Unable to send data");
    exit(EXIT_FAILURE);
  }
}

size_t receive_data(int sock_fd, void *data, size_t data_len)
{
  int retval = recv(sock_fd, data, data_len, 0);
  if (retval < 0)
  {
    perror("Unable to receive data");
    exit(EXIT_FAILURE);
  }

  return retval;
}

void print_byte_data(char *prefix, unsigned char *key, int data_len)
{
  printf("%s: ", prefix);
  for (int i = 0; i < data_len; ++i)
  {
    printf("%02x", key[i]);
  }
  printf("\n");
}

void password_to_key(char *password, unsigned char *key)
{
  if (PKCS5_PBKDF2_HMAC(password, strlen(password), "RandomSalt", 10, 5, EVP_sha256(), LONG_TERM_KEY_LEN / 2, key) != 1)
  {
    fprintf(stderr, "Error deriving key using PBKDF2\n");
    return;
  }
}

void send_ACK(int sock_fd) {
  int retval = send(sock_fd, "ACK", 3, 0);
  if (retval < 0)
  {
    perror("Unable to send ACK");
    exit(EXIT_FAILURE);
  }
}

void receive_ACK(int sock_fd) {
  char buf[3];
  int retval = recv(sock_fd, buf, 3, 0);
  if(retval < 0) 
  {
    perror("Unable to receive ACK");
    exit(EXIT_FAILURE);
  }
}

#endif // COMMON_H