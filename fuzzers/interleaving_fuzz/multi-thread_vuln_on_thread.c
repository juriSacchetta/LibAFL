#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NUM_THREADS 200
#define MAX_SIZE 100
char buf[MAX_SIZE] = {0};

int flag=0;

void LLVMFuzzerTestOneInput(const char *data, size_t size)
{
    memcpy(buf, data, size);
    printf("buf: %s\n", buf);
    if (strcmp("hello", buf) == 0)
    {
        int *p = NULL;
        *p = 666;
    }
}

void *thread_vuln(void *thread_id)
{
    char data[MAX_SIZE] = {0};
    while(flag==0) {
        
    }
    LLVMFuzzerTestOneInput(data, MAX_SIZE);
}

void *thread_nonpassi(void *arg)
{
    while(flag==0) {

    }
    memcpy(buf, "nonpassi", 9);
}

int main()
{
    pthread_t threads[NUM_THREADS];
    int i;

    for (i = 0; i < NUM_THREADS-1; i++)
    {
        pthread_create(&threads[i], NULL, thread_nonpassi, NULL);
        printf("Thread %d created\n", i);
    }
    pthread_create(&threads[NUM_THREADS-1], NULL, thread_vuln, NULL);
    printf("Thread %d created\n", NUM_THREADS-1);

    flag=1;

    for (i = 0; i < NUM_THREADS; i++)
    {
        pthread_join(threads[i], NULL);
        printf("Thread %d finished\n", i);
    }
    return 0;
    return 0;
}