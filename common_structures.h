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

// OpenSSL libcrypto includes
#include <openssl/evp.h>
#include <openssl/err.h>

#define KDC_PORT 8888
#define CHAT_PORT 9999
#define KDC_SERVER 1
#define CHAT_SERVER 2
#define SERVER_IP "127.0.0.1"
#define BUFFER_SIZE 1024
#define UNAME_LEN 32
#define KEY_LEN 128
#define ENCRYPTED_TEXT_LEN 256
#define SESSION_KEY_LEN 32

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
  unsigned char session_key[KEY_LEN];
  char uname[UNAME_LEN];
};

struct NS_msg_2
{
  int nonce;
  unsigned char session_key[KEY_LEN];
  unsigned char encrypted_t[ENCRYPTED_TEXT_LEN];
};

int generate_nonce()
{
  // TODO: Complete this function to get a random integer
  return 5;
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

#endif // COMMON_H