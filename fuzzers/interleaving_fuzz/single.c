#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
int LLVMFuzzerTestOneInput(const char *Data, size_t Size){
    if(strcmp(Data, "qefwdvrgwensDBVJHKSBVKHSGvfjhsgfvias") == 0) {
      int *p = NULL;
      *p = 666;
    }
}

int main() {
    char buf[10] = {0};
    LLVMFuzzerTestOneInput(buf, 10);
    return 0;
}
