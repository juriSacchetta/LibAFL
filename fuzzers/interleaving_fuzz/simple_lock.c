#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
    pthread_mutex_t lock;

    // Initialize the mutex lock
    pthread_mutex_init(&lock, NULL);

    pthread_mutex_lock(&lock);
    pthread_mutex_unlock(&lock);
    // Destroy the mutex lock
    pthread_mutex_destroy(&lock);

    printf("Lock addr: %p\n", &lock);

    return 0;
}
