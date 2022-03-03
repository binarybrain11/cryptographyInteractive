#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "cryptointeractive.h"

#ifndef lambda
#define lambda 4
#endif

/* Global variables to persist between library calls. */
char* KEY = NULL;

char* randomBytes(ssize_t numBytes){
    int random = open("/dev/urandom", O_RDONLY);
    if (random < 0){
        /* Error opening file */
        perror("Couldn't open /dev/urandom");
        exit(1);
    } else {
        char *k = malloc(sizeof(char)*numBytes);
        ssize_t res = read(random, k, numBytes);
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

char* zeroBytes(ssize_t numBytes){
    char* bytes = malloc(sizeof(char)*numBytes);
    for (ssize_t i=0; i<numBytes; i++){
        bytes[i] = 0;
    }
    return bytes;
}

char* oneBytes(ssize_t numBytes){
    char* bytes = malloc(sizeof(char)*numBytes);
    for (ssize_t i=0; i<lambda; i++){
        bytes[i] = 0xFF;
    }
    return bytes;
}

char* xorBytes(char* a, char* b){
    char* res = malloc(sizeof(char)*lambda);
    for (ssize_t i=0; i<lambda; i++){
        res[i] = a[i] ^ b[i];
    }
    return res;
}

char* andBytes(char* a, char* b){
    char* res = malloc(sizeof(char)*lambda);
    for (ssize_t i=0; i<lambda; i++){
        res[i] = a[i] & b[i];
    }
    return res;
}

char* orBytes(char* a, char* b){
    char* res = malloc(sizeof(char)*lambda);
    for (ssize_t i=0; i<lambda; i++){
        res[i] = a[i] | b[i];
    }
    return res;
}

int isEqual(char* a, char* b){
    if (a==NULL || b==NULL) { return 1; }
    char res = 0;
    for (ssize_t i=0; i<lambda; i++){
        /* Any differing bits will be stored in res */
        res |= a[i] ^ b[i];
    }
    return res == 0;
}

char* addBytes(char* a, char* b){
    char* c = malloc(sizeof(char)*lambda);
    char carry = 0;
    int tmp = 0;
    for (ssize_t i=0; i<lambda; i++){
        tmp = a[i] + b[i] + carry;
        c[i] = (char)tmp;
        carry = (char)(tmp >> (sizeof(char)*8));
    }
    return c;
}

char* subtractBytes(char* a, char* b){
    char* c = malloc(sizeof(char)*lambda);
    char carry = 0;
    /* tmp needs to be at least 1 byte bigger than a block (char) to catch carry bit */
    int tmp = 0;
    for (ssize_t i=0; i<lambda; i++){
        tmp = a[i] - b[i] + carry;
        c[i] = (char)tmp;
        carry = (char)(tmp >> (sizeof(char)*8));
    }
    return c;
}

char* multiplyBytes(char* a, char* b){
    char* c = zeroBytes(2*lambda);
    char carry = 0;
    /* tmp needs to be at least twice as big as a block (char)*/
    int tmp = 0;
    for (ssize_t i=0; i<lambda; i++){
        carry = 0;
        for (ssize_t j=0; j<lambda; j++){
            tmp = a[i]*b[j] + c[i+j] + carry;
            c[i+j] = (char)tmp;
            carry = (char)(tmp >> (sizeof(char)*8));
        }
        c[i+lambda] = carry;
    }
    return c;
}

/*
int main(){
    char a[] = {1,2,3,4};
    char b[] = {4,3,2,1};
    char* diff = multiplyBytes(b,a);
    printf("%lx\n", *(long*)diff);
    free(diff);
}
*/

/* ==================================================================
 * Primitives
 * ==================================================================
 */

char* KeyGen(){
    return randomBytes(lambda);
}

char* otpEnc(char* k, char* m){
    char* c = malloc(sizeof(char)*lambda);
    for (ssize_t i=0; i<lambda; i++){
        c[i] = m[i] ^ k[i];
    }
    return c;
}

char* linearGseed = NULL;
/* For size s bytes, m = mersennePrimes[s] is a sufficiently large prime 
 * modulus to return s psuedorandom bytes. mersennePrimes[16] is sufficiently 
 * large for 65 bytes. 
 */
const ssize_t mersennePrimes[] = {13, 17, 31, 61, 61, 61, 61, 89, 
89, 89, 89, 107, 107, 127, 127, 521};

char* linearG(char* seed){
    const char* a;
    const char* b;
    const char* m;
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
    return randomBytes(lambda);
}

int se2_3OtsAttack(char (*attack)(Scheme*)){
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
    char result = attack(&scheme);
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

double se2_3OtsAdvantage(unsigned int trials, char (*attack)(Scheme*)){
    double advantage = 0;
    for (unsigned int i=0; i<trials; i++){
        advantage += se2_3OtsAttack(attack);
    }
    return advantage/(double) trials;
}

/* Chapter 2 Homework Problem 1 */

char* hw2_1KeyGen(){
    char* c = randomBytes(lambda);
    char* zero = zeroBytes(lambda);
    while (isEqual(c, zero)){
        c = randomBytes(lambda);
    }
    free(zero);
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
    return randomBytes(lambda);
}

int hw2_1OtsAttack(char (*attack)(Scheme*)){
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
    char result = attack(&scheme);
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
/* Length tripling PRG */
char* hw5_1G(char* s){
    char* num = malloc(3*lambda*sizeof(char));
    /* Safely converts s to an integer to pass as seed to srand() */
    int seed = 0;
    for (int i=0; i<lambda && i < sizeof(int); i++){
        seed += s[i];
        seed << 8*sizeof(char);
    }

    srand(seed);
    for (int i=0; i<3*lambda; i++){
        num[i] = rand() & 0xFF;
    }
    return num;
}

char* hw5_1aPRGreal(){
    char* s = randomBytes(lambda);
    char* x = hw5_1G(s);
    char* zero = zeroBytes(lambda);
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
    free(zero);
    return res;
}

char* hw5_1aPRGrand(){
    return randomBytes(lambda);
}

int hw5_1aPrgAttack(char (*attack)(Scheme*)){
    Scheme scheme = {NULL, NULL, NULL, NULL, NULL, NULL, NULL};
    char* choice = randomBytes(1);
    if (*choice & 2){
        scheme.QUERY = hw5_1aPRGrand;
    } else {
        scheme.QUERY = hw5_1aPRGreal;
    }
    char result = attack(&scheme);
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

double hw5_1aPrgAdvantage(unsigned int trials, char (*attack)(Scheme*)){
    double advantage = 0;
    for (unsigned int i=0; i<trials; i++){
        advantage += hw5_1aPrgAttack(attack);
    }
    return advantage/(double) trials;
}

/* Chapter 5 Homework Problem 1b */
char* hw5_1bPRGreal(){
    char* s = randomBytes(lambda);
    char* x = hw5_1G(s);
    char* zero = zeroBytes(lambda);
    char* y = hw5_1G(zero);
    /* x = x^y then return the new x */
    for (int i=0; i<3*lambda; i++){
        x[i] ^= y[i];
    }
    free(s);
    free(y);
    free(zero);
    return x;
}

char* hw5_1bPRGrand(){
    return randomBytes(lambda);
}

int hw5_1bPrgAttack(char (*attack)(Scheme*)){
    Scheme scheme = {NULL, NULL, NULL, NULL, NULL, NULL, NULL};
    char* choice = randomBytes(1);
    if (*choice & 2){
        scheme.QUERY = hw5_1bPRGrand;
    } else {
        scheme.QUERY = hw5_1bPRGreal;
    }
    char result = attack(&scheme);
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

double hw5_1bPrgAdvantage(unsigned int trials, char (*attack)(Scheme*)){
    double advantage = 0;
    for (unsigned int i=0; i<trials; i++){
        advantage += hw5_1bPrgAttack(attack);
    }
    return advantage/(double) trials;
}

/* Chapter 5 Homework Problem 1c */
char* hw5_1cPRGreal(){
    char* s = randomBytes(lambda);
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
    return randomBytes(lambda);
}

int hw5_1cPrgAttack(char (*attack)(Scheme*)){
    Scheme scheme = {NULL, NULL, NULL, NULL, NULL, NULL, NULL};
    char* choice = randomBytes(1);
    if (*choice & 2){
        scheme.QUERY = hw5_1cPRGrand;
    } else {
        scheme.QUERY = hw5_1cPRGreal;
    }
    char result = attack(&scheme);
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
    
}

char* hw6_1EAVESDROPL(char* mL, char* mR){
    char* key = hw2_1KeyGen(lambda);
    char* c = otpEnc(key, mL);
    free(key);
    return c;
}

char* hw6_1EAVESDROPR(char* mL, char* mR){
    char* key = hw2_1KeyGen(lambda);
    char* c = otpEnc(key, mR);
    free(key);
    return c;
}

char* hw6_1CTXTreal(char* m){
    char* key = hw2_1KeyGen(lambda);
    char* c = otpEnc(key, m);
    free(key);
    return c;
}

char* hw6_1CTXTrandom(char* m){
    return randomBytes(lambda);
}

int hw6_1OtsAttack(char (*attack)(Scheme*)){
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
    char result = attack(&scheme);
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

double hw6_1OtsAdvantage(unsigned int trials, char (*attack)(Scheme*)){
    double advantage = 0;
    for (unsigned int i=0; i<trials; i++){
        advantage += hw6_1OtsAttack(attack);
    }
    return advantage/(double) trials;
}