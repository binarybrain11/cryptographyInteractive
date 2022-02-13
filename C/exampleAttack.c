#include <sys/types.h>
#include <stdio.h>

#include "cryptointeractive.h"

char se2_3OtsExampleAttack(ssize_t lambda, Scheme *scheme){
    char* m = zeroBytes(lambda);
    char* c = scheme->CTXT(lambda, m);
    if (isEqual(lambda, m, c)){
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
    if (se2_3OtsAttack(4, se2_3OtsExampleAttack) == 1){
        printf("Attack successful!\n");
    } else {
        printf("Attack failed!\n");
    }
    double advantage = se2_3OtsAdvantage(4, 1000, se2_3OtsExampleAttack);
    printf("Attack advantage: %f\n", advantage);
    return 0;
}