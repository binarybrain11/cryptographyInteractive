#include <sys/types.h>
#include <stdio.h>

/* Define these constants BEFORE the header file */

#define lambda 4

#include "cryptointeractive.h"

char se2_3OtsExampleAttack(Scheme *scheme){
    char* m = malloc(sizeof(char)*lambda);
    zeroBytes(m, lambda);
    char* c = scheme->CTXT(m);
    if (isEqual(m, c)){
        free(m);
        free(c);
        return 'r';
    } else {
        free(m);
        free(c);
        return '$';
    }
}

int main(){
    if (se2_3OtsAttack(se2_3OtsExampleAttack) == 1){
        printf("Attack successful!\n");
    } else {
        printf("Attack failed!\n");
    }
    double advantage = Advantage(1000, se2_3OtsExampleAttack, se2_3OtsAttack);
    printf("Attack advantage: %f\n", advantage);
    return 0;
}