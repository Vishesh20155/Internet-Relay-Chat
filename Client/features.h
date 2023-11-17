#include "../common_structures.h"

/*Function to show the list of commands available to the users*/
void show_menu() {
  /*
  * /exit
  */
}

int evaluate_inp_cmd(int sock, char *inp) {
  if(strcmp(inp, "/exit") == 0) {
    return -1;
  }
  else {
    printf("Invalid command. Try Again!\n\n");
    return 0;
  }

  printf("\n--------------\n");
  printf("Executed command successfull\n");
  return 1;
}

void input_command(int sock) {
  char inp_cmd[CMD_LEN];
  while(1) {
    memset(inp_cmd, '\0', CMD_LEN);
    printf("Command: ");
    scanf("%s", inp_cmd);

    int retval = evaluate_inp_cmd(sock, inp_cmd);
    if(retval == -1) {
      return;
    }
  }
}