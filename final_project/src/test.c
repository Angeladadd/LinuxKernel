/*
 * test for basic functions of kpage_heat:
 * 1. print selected vma(start_vm and end_vm), which will include the addresses of arrays in this process
 * 2. print total pages and selected pages
 * 3. print running time and collecting time
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>

#define ARR_SIZE 40000

int cnt = 0;
int ** arrs = NULL;

void* visit_arr(int * arr) {
    printf("start addr %p -> end addr %p\n", arr, arr+ARR_SIZE);
    //sleep(1);
}

int main() {
    arrs  = (int **)malloc(1000*sizeof(int*));
    for (int i=0;i<10;i++) {
        arrs[i] = (int *)malloc(ARR_SIZE * sizeof(int*));
        for (int j=0;j<ARR_SIZE;j++) {
            arrs[i][j] = j;
        }
	if(i>0) {
		free(arrs[i-1]);
	}
        visit_arr(arrs[i]);
    }
    pid_t pid;
    	pid = getpid();
    	printf("pid %d\n", pid);
	char* cmd = (char*)malloc(80*sizeof(char));
	sprintf(cmd, "echo %d > /proc/kpage_heat", (int)pid);
	system(cmd);
	free(cmd);
    free(arrs[9]);
    //while(1){}
    return 0;
}
