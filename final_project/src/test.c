/*
 * test for basic functions of kpage_heat:
 * 1. print selected vma(start_vm and end_vm), which will include the addresses of arrays in this process
 * 2. print total pages and selected pages
 * 3. print running time and collecting time
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int cnt = 0;
int * a = NULL;

void* visit_arr(void) {
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
    visit_arr();
    return 0;
}