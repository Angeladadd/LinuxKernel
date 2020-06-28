#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
// #include <pthread.h>

#define NUM_THREADS 5 

int cnt = 0;
int * a = NULL;

void* visit_arr(void * args) {
    while (1) {
        printf("start addr %p -> end addr %p\n", a, a+10);
        sleep(1);
    }
}

int main() {
    a  = (int *)malloc(10*sizeof(int));
    for (int i=0;i<10;i++) {
        a[i] = cnt++;
    }

    // pid_t pid;
    // printf("before calling fork,calling process pid = %d\n",getpid());
    // pid = fork();

    // if(pid == 0){
    //     printf("this is child process and child's pid = %d,parent's pid = %d\n",getpid(),getppid());
    //     visit_arr(NULL);
    // }
    // if(pid > 0){
    //     //sleep(1);
    //     printf("this is parent process and pid =%d ,child's pid = %d\n",getpid(),pid);
    //     visit_arr(NULL);
    // }

    // return 0;
    // pthread_t tids[NUM_THREADS];
    // for (int i = 0; i < NUM_THREADS; ++i) {
    //     int ret = pthread_create(&tids[i], NULL, visit_arr, NULL);
    //     if (ret != 0) {
    //         printf("pthread_create error: error_code = %d\n", ret);
    //     }
    // }
    // pthread_exit(NULL);
    visit_arr(NULL);
    return 0;
}