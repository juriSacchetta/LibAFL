#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NUM_THREADS 2
#define ITERATIONS 10000000

char shared_var[500];
pthread_mutex_t lock;

void LLVMFuzzerTestOneInput(const char *data, size_t size)
{
    printf("Lock addr: %p\n", &lock);
    pthread_mutex_lock(&lock);
    memcpy(shared_var, data, size);
    pthread_mutex_unlock(&lock);
}

void *thread_vuln_start(void *args)
{
    char data[500] = {0};
    LLVMFuzzerTestOneInput(data, 500);
}

void *thread_lock_fun(void *arg)
{
    for (int i = 0; i < ITERATIONS; i++)
    {
        pthread_mutex_lock(&lock);
        memset(shared_var, 0, sizeof(shared_var));
        pthread_mutex_unlock(&lock);
    }
    pthread_exit(NULL);
}

int main()
{
    pthread_t threads[NUM_THREADS];
    int rc;
    long t;

    // Initialize the mutex lock
    pthread_mutex_init(&lock, NULL);

    // Create threads
    for (t = 0; t < NUM_THREADS; t++)
    {
        rc = pthread_create(&threads[t], NULL, thread_lock_fun, NULL);
        if (rc)
        {
            printf("Error: pthread_create() failed with code %s\n", rc);
            exit(-1);
        }
    }

    pthread_t vuln_thread;
    rc = pthread_create(&vuln_thread, NULL, thread_vuln_start, NULL);

    // Wait for threads to finish
    for (t = 0; t < NUM_THREADS; t++)
    {
        pthread_join(threads[t], NULL);
    }

    pthread_join(vuln_thread, NULL);
    // Destroy the mutex lock
    pthread_mutex_destroy(&lock);

    printf("Main: Shared_var final value: %s\n", shared_var);

    return 0;
}
