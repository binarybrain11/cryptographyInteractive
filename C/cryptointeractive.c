#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <unistd.h>
#include "cryptointeractive.h"

char* randomBytes(ssize_t lambda){
    int random = open("/dev/urandom", O_RDONLY);
    if (random < 0){
        /* Error opening file */
        perror("Couldn't open /dev/urandom");
        exit(1);
    } else {
        char *k = malloc(sizeof(char)*lambda);
        ssize_t res = read(random, k, lambda);
        if (res < 0){
            /* Error reading file */
            perror("Couldn't read /dev/urandom");
            exit(1);
        }
        res = close(random);
        if (res < 0){
            perror("Couldn't close /dev/urandom");
            exit(1);
        }
        return k;
    }
}

char* zeroBytes(ssize_t lambda){
    char* bytes = malloc(sizeof(char)*lambda);
    for (ssize_t i=0; i<lambda; i++){
        bytes[i] = 0;
    }
    return bytes;
}

char* oneBytes(ssize_t lambda){
    char* bytes = malloc(sizeof(char)*lambda);
    for (ssize_t i=0; i<lambda; i++){
        bytes[i] = 0xFF;
    }
    return bytes;
}

int isEqual(ssize_t lambda, char* a, char* b){
    char res = 0;
    for (ssize_t i=0; i<lambda; i++){
        /* Any differing bits will be stored in res */
        res |= a[i] ^ b[i];
    }
    return res == 0;
}

char* KeyGen(ssize_t lambda){
    return randomBytes(lambda);
}

char* otpEnc(ssize_t lambda, char* k, char* m){
    char* c = malloc(sizeof(char)*lambda);
    for (ssize_t i=0; i<lambda; i++){
        c[i] = m[i] ^ k[i];
    }
    return c;
}

/* ==================================================================
 * CHAPTER 2
 * ==================================================================
 */

/* 
 * One time secrecy (ots) example from Chapter 2 Section 3 of the book 
 */
char* se2_3Enc(ssize_t lambda, char* k, char* m){
    if (k==NULL || m == NULL){
        perror("Null pointer passed to se2_Enc");
        exit(1);
    }
    char* c = malloc(sizeof(char)*lambda);
    for (ssize_t i=0; i<lambda; i++){
        c[i] = m[i] & k[i];
    }
    return c;
}

char* se2_3EAVESDROPL(ssize_t lambda, char* mL, char* mR){
    char* key = KeyGen(lambda);
    char* c = se2_3Enc(lambda, key, mL);
    free(key);
    return c;
}

char* se2_3EAVESDROPR(ssize_t lambda, char* mL, char* mR){
    char* key = KeyGen(lambda);
    char* c = se2_3Enc(lambda, key, mR);
    free(key);
    return c;
}

char* se2_3CTXTreal(ssize_t lambda, char* m){
    char* key = KeyGen(lambda);
    char* c = se2_3Enc(lambda, key, m);
    free(key);
    return c;
}

char* se2_3CTXTrandom(ssize_t lambda, char* m){
    return randomBytes(lambda);
}

int se2_3OtsAttack(ssize_t lambda, char (*attack)(ssize_t, Scheme*)){
    Scheme scheme = {NULL, NULL, NULL, NULL, NULL, NULL, NULL};
    char* choice = randomBytes(1);
    if (*choice & 1){
        scheme.EAVESDROP = se2_3EAVESDROPL;
    } else {
        scheme.EAVESDROP = se2_3EAVESDROPR;
    }
    if (*choice & 2){
        scheme.CTXT = se2_3CTXTrandom;
    } else {
        scheme.CTXT = se2_3CTXTreal;
    }
    char result = attack(lambda, &scheme);
    if ((*choice & 1) == 1 && result == 'L'){
        free(choice);
        return 1;
    } 
    if ((*choice & 1) == 0 && result == 'R'){
        free(choice);
        return 1;
    } 

    if ((*choice & 2) == 2 && result == '$'){
        free(choice);
        return 1;
    } 

    if ((*choice & 2) == 0 && result == 'r'){
        free(choice);
        return 1;
    } 
    
    free(choice);
    return 0;
}

double se2_3OtsAdvantage(ssize_t lambda, unsigned int trials, char (*attack)(ssize_t, Scheme*)){
    double advantage = 0;
    for (unsigned int i=0; i<trials; i++){
        advantage += se2_3OtsAttack(lambda, attack);
    }
    return advantage/(double) trials;
}

/* Chapter 2 Homework Problem 1 */

char* hw2_1KeyGen(ssize_t lambda){
    char* c = randomBytes(lambda);
    char* zero = zeroBytes(lambda);
    while (isEqual(lambda, c, zero)){
        c = randomBytes(lambda);
    }
    free(zero);
    return c;
}

char* hw2_1EAVESDROPL(ssize_t lambda, char* mL, char* mR){
    char* key = hw2_1KeyGen(lambda);
    char* c = otpEnc(lambda, key, mL);
    free(key);
    return c;
}

char* hw2_1EAVESDROPR(ssize_t lambda, char* mL, char* mR){
    char* key = hw2_1KeyGen(lambda);
    char* c = otpEnc(lambda, key, mR);
    free(key);
    return c;
}

char* hw2_1CTXTreal(ssize_t lambda, char* m){
    char* key = hw2_1KeyGen(lambda);
    char* c = otpEnc(lambda, key, m);
    free(key);
    return c;
}

char* hw2_1CTXTrandom(ssize_t lambda, char* m){
    return randomBytes(lambda);
}

int hw2_1OtsAttack(ssize_t lambda, char (*attack)(ssize_t, Scheme*)){
    Scheme scheme = {NULL, NULL, NULL, NULL, NULL, NULL, NULL};
    char* choice = randomBytes(1);
    if (*choice & 1){
        scheme.EAVESDROP = hw2_1EAVESDROPL;
    } else {
        scheme.EAVESDROP = hw2_1EAVESDROPR;
    }
    if (*choice & 2){
        scheme.CTXT = hw2_1CTXTrandom;
    } else {
        scheme.CTXT = hw2_1CTXTreal;
    }
    char result = attack(lambda, &scheme);
    if ((*choice & 1) == 1 && result == 'L'){
        free(choice);
        return 1;
    } 
    if ((*choice & 1) == 0 && result == 'R'){
        free(choice);
        return 1;
    } 

    if ((*choice & 2) == 2 && result == '$'){
        free(choice);
        return 1;
    } 

    if ((*choice & 2) == 0 && result == 'r'){
        free(choice);
        return 1;
    } 
    
    free(choice);
    return 0;
}

double hw2_1OtsAdvantage(ssize_t lambda, unsigned int trials, char (*attack)(ssize_t, Scheme*)){
    double advantage = 0;
    for (unsigned int i=0; i<trials; i++){
        advantage += hw2_1OtsAttack(lambda, attack);
    }
    return advantage/(double) trials;
}
