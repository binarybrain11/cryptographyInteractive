#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "cryptointeractive.h"

#ifndef BYTE
#define BYTE 8
#endif

#ifndef lambda
#define lambda 4
#endif

/* Global variables to persist between library calls. */
char* KEY = NULL;
void* T = NULL;

void randomBytes(char* res, ssize_t numBytes){
    int random = open("/dev/urandom", O_RDONLY);
    if (random < 0){
        /* Error opening file */
        perror("Couldn't open /dev/urandom");
        exit(1);
    } else {
        ssize_t ret = read(random, res, numBytes);
        if (ret < 0){
            /* Error reading file */
            perror("Couldn't read /dev/urandom");
            exit(1);
        }
        ret = close(random);
        if (ret < 0){
            perror("Couldn't close /dev/urandom");
            exit(1);
        }
    }
}

void zeroBytes(char* bytes, ssize_t numBytes){
    for (ssize_t i=0; i<numBytes; i++){
        bytes[i] = 0;
    }
}

void oneBytes(char* bytes, ssize_t numBytes){
    for (ssize_t i=0; i<lambda; i++){
        bytes[i] = 0xFF;
    }
}

void xorBytes(char* res, char* a, char* b){
    char* res = malloc(sizeof(char)*lambda);
    for (ssize_t i=0; i<lambda; i++){
        res[i] = a[i] ^ b[i];
    }
}

void andBytes(char* res, char* a, char* b){
    char* res = malloc(sizeof(char)*lambda);
    for (ssize_t i=0; i<lambda; i++){
        res[i] = a[i] & b[i];
    }
}

void orBytes(char* res, char* a, char* b){
    char* res = malloc(sizeof(char)*lambda);
    for (ssize_t i=0; i<lambda; i++){
        res[i] = a[i] | b[i];
    }
}

/* Returns false if either parameter is NULL */
int isEqual(char* a, char* b){
    if (a==NULL || b==NULL) { return 0; }
    char res = 0;
    for (ssize_t i=0; i<lambda; i++){
        /* Any differing bits will be stored in res */
        res |= a[i] ^ b[i];
    }
    return res == 0;
}

int isZero(char* a){
    if (a==NULL) { return 0; }
    char res = 0;
    for (ssize_t i=0; i<lambda; i++){
        /* Any differing bits will be stored in res */
        res |= a[i];
    }
    return res == 0;
}

void leftShiftBytes(unsigned char* res, unsigned char* a, int b){
    memcpy(res, a, lambda);
    /* shift one byte at a time */
    while (b > BYTE){
        for (ssize_t i=lambda-1; i>0; i--){
            res[i] = res[i-1];
        }
        b-=BYTE;
    }
    unsigned char carry;
    for (ssize_t i=lambda-1; i>0; i--){
        carry = res[i-1] >> (BYTE - b);
        res[i] = res[i] << b;
        res[i] |= carry;
    }
    res[0] = res[0] << b;
}

void rightShiftBytes(unsigned char* res, unsigned char* a, int b){
    memcpy(res, a, lambda);
    /* shift one byte at a time */
    while (b > BYTE){
        for (ssize_t i=1; i<lambda; i++){
            res[i-1] = res[i];
        }
        b-=BYTE;
    }
    unsigned char carry;
    for (ssize_t i=1; i<lambda; i++){
        carry = res[i] << (BYTE - b);
        res[i-1] = res[i-1] >> b;
        res[i-1] |= carry;
    }
    res[0] = res[0] >> b;
}

/* These next few arithmetic functions are from 
 * A Computational Introduction to Number Theory and Algebra
 * by Victor Shoup
 */

/* Reuses memory caller provides rather than allocating new memory */
void addBytes(char* res, char* a, char* b){
    unsigned char carry = 0;
    int tmp = 0;
    for (ssize_t i=0; i<lambda; i++){
        tmp = a[i] + b[i] + carry;
        res[i] = (char)tmp;
        carry = (char)(tmp >> (sizeof(char)*BYTE));
    }
}

/* Deals with 2*lambda to accomadate doubling PRG */
void addDoubleBytes(char* res, char* a, char* b){
    unsigned char carry = 0;
    int tmp = 0;
    for (ssize_t i=0; i<2*lambda; i++){
        tmp = a[i] + b[i] + carry;
        res[i] = (char)tmp;
        carry = (char)(tmp >> (sizeof(char)*BYTE));
    }
}

void subtractBytes(char* res, char* a, char* b){
    char carry = 0;
    /* tmp needs to be at least 1 byte bigger than a block (char) to catch carry bit */
    int tmp = 0;
    for (ssize_t i=0; i<lambda; i++){
        tmp = a[i] - b[i] + carry;
        res[i] = (char)tmp;
        carry = (char)(tmp >> (sizeof(char)*BYTE));
    }
}

void subtractDoubleBytes(char* res, char* a, char* b){
    char carry = 0;
    /* tmp needs to be at least 1 byte bigger than a block (char) to catch carry bit */
    int tmp = 0;
    for (ssize_t i=0; i<2*lambda; i++){
        tmp = a[i] - b[i] + carry;
        res[i] = (char)tmp;
        carry = (char)(tmp >> (sizeof(char)*BYTE));
    }
}

/* Notably returns string of length 2*lambda 
 * Also note the unsigned integers 
 */

void multiplyBytes(unsigned char* res, unsigned char* a, unsigned char* b){
    char carry = 0;
    /* tmp needs to be at least twice as big as a block (char)*/
    int tmp = 0;
    for (ssize_t i=0; i<lambda; i++){
        carry = 0;
        for (ssize_t j=0; j<lambda; j++){
            tmp = a[i]*b[j] + res[i+j] + carry;
            res[i+j] = (char)tmp;
            carry = (char)(tmp >> (sizeof(char)*BYTE));
        }
        res[i+lambda] = carry;
    }
}

/* Deals with 2*lambda to accomadate doubling PRG */
void multiplyDoubleBytes(unsigned char* res, unsigned char* a, unsigned char* b){
    char carry = 0;
    /* tmp needs to be at least twice as big as a block (char)*/
    int tmp = 0;
    for (ssize_t i=0; i<2*lambda; i++){
        carry = 0;
        for (ssize_t j=0; j<2*lambda; j++){
            tmp = a[i]*b[j] + res[i+j] + carry;
            res[i+j] = (char)tmp;
            carry = (char)(tmp >> (sizeof(char)*BYTE));
        }
        res[i+lambda] = carry;
    }
}

char* TInit(){
    T = malloc(1);
}

char* TFree(){

}

char* TLookup(char* x){
    void** Tcast = T;
}

/* ==================================================================
 * Primitives
 * ==================================================================
 */

char* KeyGen(){
    char* key = malloc(sizeof(char)*lambda);
    randomBytes(key, lambda);
    return key;
}

char* otpEnc(char* k, char* m){
    char* c = malloc(sizeof(char)*lambda);
    for (ssize_t i=0; i<lambda; i++){
        c[i] = m[i] ^ k[i];
    }
    return c;
}

char* linearGseed = NULL;
char* linearGx = NULL;

/* This is a linear congruential generator. This is only used in the 
 * libraries where the user passes a seed that they create. This is a bad 
 * generator, but hopefully attacking this is harder than the attacking 
 * intended library.
 */
void linearG(char* res, char* seed){
    if (!isEqual(seed, linearGseed)){
        if (linearGseed){
            free(linearGseed);
        }
        linearGseed = malloc(sizeof(char)*lambda);
        memcpy(linearGseed, seed, lambda);
        if (!linearGx){
            linearGx = malloc(sizeof(char)*lambda*2);
        }
        memcpy(linearGx, seed, lambda);
    }
    char* a = calloc(2*lambda, sizeof(char));
    char* c = calloc(2*lambda, sizeof(char));
    c[0] = 4;
    /* set a = 2^lambda - 4 */
    subtractBytesR(a,a,c);
    c[0] = 3;
    multiplyBytes(linearGx, linearGx, a);
    addBytes(linearGx, linearGx, c);
    /* only return upper bits since lower bits are somewhat predictable */
    memcpy(res, linearGx+lambda, lambda);
    free(a);
    free(c);
}

/* Length doubling PRG */
void linearDoubleG(char* res, char* seed){
    if (!isEqual(seed, linearGseed)){
        if (linearGseed){
            free(linearGseed);
        }
        linearGseed = malloc(sizeof(char)*lambda*2);
        memcpy(linearGseed, seed, lambda);
        if (!linearGx){
            linearGx = malloc(sizeof(char)*lambda*4);
        }
        memcpy(linearGx, seed, lambda);
    }
    char* a = calloc(2*lambda, sizeof(char));
    char* c = calloc(2*lambda, sizeof(char));
    c[0] = 4;
    /* set a = 2^lambda - 4 */
    subtractDoubleBytesR(a,a,c);
    c[0] = 3;
    multiplyDoubleBytes(linearGx, linearGx, a);
    addDoubleBytes(linearGx, linearGx, c);
    /* only return upper bits since lower bits are somewhat predictable */
    memcpy(res, linearGx+lambda, 2*lambda);
    free(a);
    free(c);
}

/* PRF constructed using linearG to specification of Construction 6.4 */
char* linearPrf(char* k, char* x){
    char* v = malloc(sizeof(char)*lambda*2);
    memcpy(v, k, lambda);
    for (ssize_t i=0; i<lambda/sizeof(char); i++){
        for (ssize_t j=1; j<((unsigned char)~0); j*=2){
            if (x[i] & j){
                linearG(v, v);
            } else {
                linearG(v, v+lambda);
            }
        }
    }
    return v;
}

/* ==================================================================
 * CHAPTER 2
 * ==================================================================
 */

/* 
 * One time secrecy (ots) example from Chapter 2 Section 3 of the book 
 */
char* se2_3Enc(char* k, char* m){
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

char* se2_3EAVESDROPL(char* mL, char* mR){
    char* key = KeyGen(lambda);
    char* c = se2_3Enc(key, mL);
    free(key);
    return c;
}

char* se2_3EAVESDROPR(char* mL, char* mR){
    char* key = KeyGen(lambda);
    char* c = se2_3Enc(key, mR);
    free(key);
    return c;
}

char* se2_3CTXTreal(char* m){
    char* key = KeyGen(lambda);
    char* c = se2_3Enc(key, m);
    free(key);
    return c;
}

char* se2_3CTXTrandom(char* m){
    char* c = malloc(sizeof(char)*lambda);
    randomBytes(c,lambda);
    return c;
}

int se2_3OtsAttack(char (*attack)(Scheme*)){
    Scheme scheme = {NULL, NULL, NULL, NULL, NULL, NULL, NULL};
    char choice;
    randomBytes(&choice, sizeof(char));
    if (choice & 1){
        scheme.EAVESDROP = se2_3EAVESDROPL;
    } else {
        scheme.EAVESDROP = se2_3EAVESDROPR;
    }
    if (choice & 2){
        scheme.CTXT = se2_3CTXTrandom;
    } else {
        scheme.CTXT = se2_3CTXTreal;
    }
    char result = attack(&scheme);
    if ((choice & 1) == 1 && result == 'L'){
        free(choice);
        return 1;
    } 
    if ((choice & 1) == 0 && result == 'R'){
        free(choice);
        return 1;
    } 

    if ((choice & 2) == 2 && result == '$'){
        free(choice);
        return 1;
    } 

    if ((choice & 2) == 0 && result == 'r'){
        free(choice);
        return 1;
    } 
    
    return 0;
}

double se2_3OtsAdvantage(unsigned int trials, char (*attack)(Scheme*)){
    double advantage = 0;
    for (unsigned int i=0; i<trials; i++){
        advantage += se2_3OtsAttack(attack);
    }
    return advantage/(double) trials;
}

/* Chapter 2 Homework Problem 1 */

char* hw2_1KeyGen(){
    char* c = malloc(sizeof(char)*lambda);
    randomBytes(c, lambda);
    const char zero[lambda] = {0};
    while (isEqual(c, zero)){
        randomBytes(c, lambda);
    }
    return c;
}

char* hw2_1EAVESDROPL(char* mL, char* mR){
    char* key = hw2_1KeyGen(lambda);
    char* c = otpEnc(key, mL);
    free(key);
    return c;
}

char* hw2_1EAVESDROPR(char* mL, char* mR){
    char* key = hw2_1KeyGen(lambda);
    char* c = otpEnc(key, mR);
    free(key);
    return c;
}

char* hw2_1CTXTreal(char* m){
    char* key = hw2_1KeyGen(lambda);
    char* c = otpEnc(key, m);
    free(key);
    return c;
}

char* hw2_1CTXTrandom(char* m){
    char* c = malloc(sizeof(char)*lambda);
    randomBytes(c,lambda);
    return c;
}

int hw2_1OtsAttack(char (*attack)(Scheme*)){
    Scheme scheme = {NULL, NULL, NULL, NULL, NULL, NULL, NULL};
    char choice;
    randomBytes(&choice, sizeof(char));
    if (choice & 1){
        scheme.EAVESDROP = hw2_1EAVESDROPL;
    } else {
        scheme.EAVESDROP = hw2_1EAVESDROPR;
    }
    if (choice & 2){
        scheme.CTXT = hw2_1CTXTrandom;
    } else {
        scheme.CTXT = hw2_1CTXTreal;
    }
    char result = attack(&scheme);
    if ((choice & 1) == 1 && result == 'L'){
        free(choice);
        return 1;
    } 
    if ((choice & 1) == 0 && result == 'R'){
        free(choice);
        return 1;
    } 

    if ((choice & 2) == 2 && result == '$'){
        free(choice);
        return 1;
    } 

    if ((choice & 2) == 0 && result == 'r'){
        free(choice);
        return 1;
    } 
    
    return 0;
}

double hw2_1OtsAdvantage(unsigned int trials, char (*attack)(Scheme*)){
    double advantage = 0;
    for (unsigned int i=0; i<trials; i++){
        advantage += hw2_1OtsAttack(attack);
    }
    return advantage/(double) trials;
}

/* ==================================================================
 * CHAPTER 5
 * ==================================================================
 */

/* Chapter 5 Homework Problem 1 a */
/* This is a *secure* length tripling PRG. stdlib rand() isn't cryptographically
 * secure, however it can be seeded and we assume users won't attack rand() but
 * rather the scheme described in the problem. The seed to srand() is limited to 
 * sizeof(int) so input seeds larger than that will be truncated.
 */
/* Length tripling PRG, security dependent on linearG */
char* hw5_1G(char* s){
    char* num = malloc(3*lambda*sizeof(char));
    for (ssize_t i=0; i<3; i++){
        linearG(num+(lambda*i), s);
    }
    return num;
}

char* hw5_1aPRGreal(){
    char* s = malloc(sizeof(char)*lambda);
    randomBytes(s, lambda);
    char* x = hw5_1G(s);
    const char zero[] = {0};
    char* y = hw5_1G(zero);
    /* We return x||y where x and y are each 3*lambda bytes long */
    char* res = malloc(6*lambda*sizeof(char));
    for (int i=0; i<3*lambda; i++){
        res[i] = x[i];
    }
    for (int i=3*lambda; i<6*lambda; i++){
        res[i] = y[i];
    }
    free(s);
    free(x);
    free(y);
    return res;
}

char* hw5_1aPRGrand(){
    char* res = malloc(6*lambda*sizeof(char));
    randomBytes(res, 6*lambda*sizeof(char));
    return res;
}

int hw5_1aPrgAttack(char (*attack)(Scheme*)){
    Scheme scheme = {NULL, NULL, NULL, NULL, NULL, NULL, NULL};
    char choice;
    randomBytes(&choice, sizeof(char));
    if (choice & 2){
        scheme.QUERY = hw5_1aPRGrand;
    } else {
        scheme.QUERY = hw5_1aPRGreal;
    }
    char result = attack(&scheme);
    if ((choice & 2) == 2 && result == '$'){
        free(choice);
        return 1;
    } 

    if ((choice & 2) == 0 && result == 'r'){
        free(choice);
        return 1;
    } 
    
    free(choice);
    return 0;
}

double hw5_1aPrgAdvantage(unsigned int trials, char (*attack)(Scheme*)){
    double advantage = 0;
    for (unsigned int i=0; i<trials; i++){
        advantage += hw5_1aPrgAttack(attack);
    }
    return advantage/(double) trials;
}

/* Chapter 5 Homework Problem 1b */
char* hw5_1bPRGreal(){
    char* s = malloc(sizeof(char)*lambda);
    randomBytes(s, lambda);
    char* x = hw5_1G(s);
    const char zero[lambda] = {0};
    char* y = hw5_1G(zero);
    /* x = x xor y then return the new x */
    xorBytes(x,x,y);
    free(s);
    free(y);
    return x;
}

char* hw5_1bPRGrand(){
    char* res = malloc(3*lambda*sizeof(char));
    randomBytes(res, 3*lambda*sizeof(char));
    return res;
}

int hw5_1bPrgAttack(char (*attack)(Scheme*)){
    Scheme scheme = {NULL, NULL, NULL, NULL, NULL, NULL, NULL};
    char choice;
    randomBytes(&choice, sizeof(char));
    if (choice & 2){
        scheme.QUERY = hw5_1bPRGrand;
    } else {
        scheme.QUERY = hw5_1bPRGreal;
    }
    char result = attack(&scheme);
    if ((choice & 2) == 2 && result == '$'){
        free(choice);
        return 1;
    } 

    if ((choice & 2) == 0 && result == 'r'){
        free(choice);
        return 1;
    } 
    
    free(choice);
    return 0;
}

double hw5_1bPrgAdvantage(unsigned int trials, char (*attack)(Scheme*)){
    double advantage = 0;
    for (unsigned int i=0; i<trials; i++){
        advantage += hw5_1bPrgAttack(attack);
    }
    return advantage/(double) trials;
}

/* Chapter 5 Homework Problem 1c */
char* hw5_1cPRGreal(){
    char* s = malloc(sizeof(char)*lambda);
    randomBytes(s,lambda);
    /* xyz = x||y||z = G(s) */
    char* xyz = hw5_1G(s);
    /* Even though xyz has 3*lambda length, the function will only read the
     * first lambda bytes, or x, for the seed
     */
    char* w = hw5_1G(xyz);
    /* res = x||y||z||w */
    char* res = malloc(6*lambda*sizeof(char));
    for (int i=0; i<3*lambda; i++){
        res[i] = xyz[i];
    }
    for (int i=3*lambda; i<6*lambda; i++){
        res[i] = w[i];
    }

    free(s);
    free(xyz);
    free(w);
    return res;
}

char* hw5_1cPRGrand(){
    char* res = malloc(3*lambda*sizeof(char));
    randomBytes(res, 3*lambda*sizeof(char));
    return res;
}

int hw5_1cPrgAttack(char (*attack)(Scheme*)){
    Scheme scheme = {NULL, NULL, NULL, NULL, NULL, NULL, NULL};
    char choice;
    randomBytes(&choice, sizeof(char));
    if (choice & 2){
        scheme.QUERY = hw5_1cPRGrand;
    } else {
        scheme.QUERY = hw5_1cPRGreal;
    }
    char result = attack(&scheme);
    if ((choice & 2) == 2 && result == '$'){
        free(choice);
        return 1;
    } 

    if ((choice & 2) == 0 && result == 'r'){
        free(choice);
        return 1;
    } 
    
    free(choice);
    return 0;
}

double hw5_1cPrgAdvantage(unsigned int trials, char (*attack)(Scheme*)){
    double advantage = 0;
    for (unsigned int i=0; i<trials; i++){
        advantage += hw5_1cPrgAttack(attack);
    }
    return advantage/(double) trials;
}

/* ==================================================================
 * CHAPTER 6
 * ==================================================================
 */
/* Chapter 6 Homework Problem 1 */
char* hw6_1Prf(char* k, char* m){
    /* linearPrf is defined to return lambda bits, but that pointer is 
     * assigned 2*lambda bits, so we will use those bits too.
     */
    char* res = linearPrf(k,m);
    char* tmp = linearPrf(k,res);
    memcpy(res+lambda, tmp, lambda);
    free(tmp);
    return res;
}

char* hw6_1LOOKUPreal(char* x){
    return hw6_1Prf(KEY, x);
}

char* hw6_1LOOKUPrand(char* x){

}

int hw6_1PrfAttack(char (*attack)(Scheme*)){
    Scheme scheme = {NULL, NULL, NULL, NULL, NULL, NULL, NULL};
    char choice;
    randomBytes(&choice, sizeof(char));
    if (choice & 1){
        scheme.LOOKUP = hw6_1LOOKUPrand;
    } else {
        scheme.LOOKUP = hw6_1LOOKUPreal;
    }
    T = malloc(sizeof(char*)*lambda);
    char result = attack(&scheme);
    if ((choice & 1) == 1 && result == '$'){
        free(choice);
        return 1;
    } 

    if ((choice & 1) == 0 && result == 'r'){
        free(choice);
        return 1;
    } 
    
    return 0;
}

double hw6_1PrfAdvantage(unsigned int trials, char (*attack)(Scheme*)){
    double advantage = 0;
    for (unsigned int i=0; i<trials; i++){
        advantage += hw6_1PrfAttack(attack);
    }
    return advantage/(double) trials;
}