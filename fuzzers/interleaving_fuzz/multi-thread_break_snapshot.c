#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_SIZE 1048576
char buf[MAX_SIZE] = {0};

int LLVMFuzzerTestOneInput(const char *data, size_t size)
{
    if (strcmp(data, "hello") == 0)
    {
        printf("Hello\n");
        int *p = NULL;
        *p = 666;
    }
}

void *thread_vuln(void *arg)
{
    printf("Thread vuln\n");
    LLVMFuzzerTestOneInput(buf, MAX_SIZE);
}

void *thread_vuln(void *arg)
{
    printf("Thread function\n");
    int x = 0;
    while (x < 10)
    {
        x++;
    }
    return 0;
}

int main()
{
    int i;
    pthread_t thread_1;
    pthread_t thread_2;

    pthread_create(&thread_1, NULL, thread_vuln, NULL);
    pthread_create(&thread_2, NULL, thread_vuln, NULL);

    pthread_join(thread_1, NULL);
    pthread_join(thread_2, NULL);
    return 0;
}
