#include <sys/types.h>
#include <stdio.h>

#include "cryptointeractive.h"

lambda = 4;

char se2_3OtsExampleAttack(Scheme *scheme){
    char* m = malloc(sizeof(char)*lambda);
    zeroBytes(m, lambda);
    /* Ask the scheme to encrypt the message. Since I'm calling CTXT(), this 
     * should be a real vs rand attack
     */
    char* c = scheme->CTXT(m);
    if (isEqual(m, c)){
        /* Remember to free allocated memory, especially if you use the
         * Advantage() function
         */
        free(m);
        free(c);
        /* return our guess */
        return 'r';
    } else {
        free(m);
        free(c);
        return '$';
    }
}

int main(){
    /*                       your attack here   */
    if (se2_3OtsDistinguish(se2_3OtsExampleAttack) == 1){
        printf("Attack successful!\n");
    } else {
        printf("Attack failed!\n");
    }
    /*                           Trials    your attack here   attack interface */
    double advantage = Advantage(1000, se2_3OtsExampleAttack, se2_3OtsDistinguish);
    printf("Attack advantage: %f\n", advantage);
    return 0;
}