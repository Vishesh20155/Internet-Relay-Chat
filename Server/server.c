#include "create_server.h"

int main()
{
  int retval;
  
  pthread_t kdc_thread, chat_thread;

  // Struct to hold arguents to be sent into each thread:
  struct server_args kdc_args, chat_args;

  kdc_args.port = KDC_PORT;
  kdc_args.server_type = KDC_SERVER;

  chat_args.port = CHAT_PORT;
  chat_args.server_type = CHAT_SERVER;

  derive_all_keys();

  // Starting the 2 servers on 2 separate threads:
  retval = pthread_create(&kdc_thread, NULL, start_server, (void *)&kdc_args);
  if(retval != 0) {
    perror("pthread_create");
    return 1;
  }
  
  retval = pthread_create(&chat_thread, NULL, start_server, (void *)&chat_args);
  if(retval != 0) {
    perror("pthread_create");
    return 1;
  }

  retval = pthread_join(kdc_thread, NULL);
  if(retval < 0) {
    perror("Unable to join KDC thread");
    exit(EXIT_FAILURE);
  }

  retval = pthread_join(chat_thread, NULL);
  if(retval < 0) {
    perror("Unable to join Chat thread");
    exit(EXIT_FAILURE);
  }

  return 0;
}
