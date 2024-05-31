#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

#define NUM_THREADS 2

int flag = 1;


int LLVMFuzzerTestOneInput(const char *Data, size_t Size){
    printf("Il flag è %d\n", flag);
    if(flag == 1 && strcmp(Data, "hello") == 0) {
      int *p = NULL;
      *p = 666;
    }
    flag = 0;
}

void *thread_function(void *thread_id) {
    char buf[10] = {0};
    LLVMFuzzerTestOneInput(buf, 10);
}

void *thread_sleep(void* arg) {
    sleep(10);
}


int main() {
    pthread_t threads[NUM_THREADS];
    int i;

    pthread_create(&threads[0], NULL, thread_function, NULL);
    for (i = 1; i < NUM_THREADS; i++) {
        pthread_create(&threads[i], NULL, thread_sleep, NULL);
    }

    for (i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    return 0;
}
