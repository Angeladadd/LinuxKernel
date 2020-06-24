#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int ** a;

int main() {
    int *p;
    int cnt = 0;
    a = (int **)malloc(10 * sizeof(int*));
    printf("a=\n");
    p = a[0];
    printf("p=\n");
    for (int i=0;i<10;i++) {
        a[i] = (int *) malloc(20*sizeof(int));
        printf("a[%d]=\n", i);
        for (int j=0;j<20;j++) {
            a[i][j] = cnt++;
        }
    }

    for (int i=0;i<10;i++) {
        printf("start addr %p value %d -> end addr %p\n", a[i], a[i][0], a[i+1]);
        //p+=20;
    }

    while(1) {
        
    }

    return 0;
}