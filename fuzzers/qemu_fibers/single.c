#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

int flag = 1;

int LLVMFuzzerTestOneInput(const char *Data, size_t Size){
    printf("Il flag è %d\n", flag);
    if(flag == 1 && strcmp(Data, "hello") == 0) {
      int *p = NULL;
      *p = 666;
    }
    flag = 0;
}

int main() {
    char buf[10] = {0};
    LLVMFuzzerTestOneInput(buf, 10);
    return 0;
}
