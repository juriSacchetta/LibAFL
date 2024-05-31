#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NUM_THREADS 20
#define MAX_SIZE 100
char buf[MAX_SIZE] = {0};

void *thread_vuln(void *thread_id)
{
    if (strcmp("hellotrwyqcvdfboiaàsnfgilvafegfòiuaerdghbvànòaefidujhnpOSIHDÒGFUO<LVNUGJHKXVOIÒCDHBSGVLFIASU<dglfhòiusgkbasòdoiuhj", buf) == 0)
    {
        printf("VULN TRIGGERED\n");
        printf("%s\n", buf);
        int *p = NULL;
        *p = 666;
    }
}

void *thread_nonpassi(void *arg)
{
    memcpy(buf, "nonpassi", 8);
}

int race()
{
    pthread_t threads[NUM_THREADS];
    int i;

    for (i = 1; i < NUM_THREADS; i++)
    {
        pthread_create(&threads[i], NULL, thread_nonpassi, NULL);
    }
    pthread_create(&threads[0], NULL, thread_vuln, NULL);

    for (i = 0; i < NUM_THREADS; i++)
    {
        pthread_join(threads[i], NULL);
    }
    return 0;
}


int LLVMFuzzerTestOneInput(const char *data, size_t size)
{
    memcpy(buf, data, size);
    race();
    return 0;
}

int main()
{
    char data[MAX_SIZE];
    LLVMFuzzerTestOneInput(data, MAX_SIZE);
    return 0;
}