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

/* Global variables to persist between library calls. */
static char* KEY = NULL;
static char** T = NULL;
static ssize_t Tsize = 0;
static ssize_t Tcapacity = 0;
static ssize_t TkeySize = 0;
static ssize_t TvalSize = 0;

/* Initialize T table to 100 elements. Use the getters and setters for 
 * elements in this table so the table can grow and access properly
 * - keySize indicates how many bytes the keys in this table are
 * - valSize indiactes how many btes the values in this table are
 */
void TInit(ssize_t keySize, ssize_t valSize){
    Tcapacity = 100;
    Tsize = 0;
    T = malloc(sizeof(char*) * Tcapacity);
    TkeySize = keySize;
    TvalSize = valSize;
}

/* Free will free all of the strings held by the table too */
void TFree(){
    for (ssize_t i=0; i<Tsize; i++){
        free(T[i]);
    }
    free(T);
    T = NULL;
    Tsize = 0;
    Tcapacity = 0;
    TkeySize = 0;
    TvalSize = 0;
}

/* Returns a copy of the value pointed to by key (so the table value stays intact) 
 * - key is TkeySize bytes long
 * - return value is TvalueSize bytes long
 */
char* TLookup(char* key){
    /* Looks for corresponding key, returns value */
    int equals = 1;
    for(ssize_t i=0; i<Tsize; i+=2){
        for (ssize_t j=0; j<(TkeySize/lambda); j++){
            equals &= isEqual(key + lambda*j, T[i] + lambda*j);
        }
        if (!equals){
            char* res = malloc(sizeof(char)*TvalSize);
            memcpy(res, T[i+1], sizeof(char)*TvalSize);
            return res;
        }
    }
    return NULL;
}

/* Adds key-value pair to T. If key exists, it will overwrite the existing value 
 * - key is TkeySize bytes long
 * - value is TvalueSize bytes long
 */
void Tadd(char* key, char* value){
    char* valcpy = malloc(sizeof(char)*TvalSize);
    memcpy(valcpy, value, sizeof(char)*TvalSize);
    for (ssize_t i=0; i<Tsize; i+=2){
        if (isEqual(key, T[i])){
            free(T[i+1]);
            T[i+1] = valcpy;
            return;
        }
    }
    char* keycpy = malloc(sizeof(char)*TkeySize);
    memcpy(keycpy, key, sizeof(char)*TkeySize);
    if (Tsize + 2 > Tcapacity){
        char** tmp =  malloc(sizeof(char*)*Tcapacity*2);
        for (ssize_t i=0; i<Tsize; i++){
            tmp[i] = T[i];
        }
        Tcapacity *= 2;
        free(T);
        T=tmp;
    }
    T[Tsize] = keycpy;
    T[Tsize+1] = valcpy;
    Tsize += 2;
}

/* Cleans all of the allocated memory in global variables */
void cleanGlobals(){
    if (T){
        TFree();
    }
    Tsize = 0;
    Tcapacity = 0;
    if (KEY){
        free(KEY);
        KEY = NULL;
    }
}

/* ==================================================================
 * Helpers
 * ==================================================================
 */

/* - res needs to be at least numBytes long
 * - numBytes is the number of bytes to store into res
 */
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

/* Computes the distinguishing advantage of an attacker. 0.5 is unable to distinguish, 
 * 1 is distinguishes correctly every time, 0 distinguishes incorrectly every time
 * - trials is the number of trials to run the attack. The more trials, the more 
 * accurate the advantage
 * - attack is the user attack function to be called inside of the distinguish
 * - distinguisher is the function representing the problem, e.g. se2_3OtsDistinguish()
 * - returns a double indicating the advantage of the attacker
 */
double Advantage(unsigned int trials, char (*attack)(), int (*distinguisher)()){
    double advantage = 0;
    for (unsigned int i=0; i<trials; i++){
        advantage += distinguisher(attack);
    }
    return advantage/(double) trials;
}

/* Sets a block of memory to 0 bytes 
 * - bytes is the block of memory to modify
 * - numBytes is the number of bytes to modify. bytes must be at least this big
 */
void zeroBytes(char* bytes, ssize_t numBytes){
    for (ssize_t i=0; i<numBytes; i++){
        bytes[i] = 0;
    }
}

/* Sets a block of memory to bytes of all 1's, eg 0xFF
 * - bytes is the block of memory to modify
 * - numBytes is the number of bytes to modify. bytes must be at least this big
 */
void oneBytes(char* bytes, ssize_t numBytes){
    for (ssize_t i=0; i<lambda; i++){
        bytes[i] = 0xFF;
    }
}

/* Does a bitwise XOR over lambda bytes. 
 * - res is the block of memory to store the results in. Must be at least lambda 
 * bytes
 * - a and b are operands of at least lambda bytes 
 */
void xorBytes(char* res, char* a, char* b){
    for (ssize_t i=0; i<lambda; i++){
        res[i] = a[i] ^ b[i];
    }
}

/* Does a bitwise AND over lambda bytes. 
 * - res is the block of memory to store the results in. Must be at least lambda 
 * bytes
 * - a and b are operands of at least lambda bytes 
 */
void andBytes(char* res, char* a, char* b){
    for (ssize_t i=0; i<lambda; i++){
        res[i] = a[i] & b[i];
    }
}

/* Does a bitwise OR over lambda bytes. 
 * - res is the block of memory to store the results in. Must be at least lambda 
 * bytes
 * - a and b are operands of at least lambda bytes 
 */
void orBytes(char* res, char* a, char* b){
    for (ssize_t i=0; i<lambda; i++){
        res[i] = a[i] | b[i];
    }
}

/* Returns 0 if operands aren't equal and a nonzero value if they are equal 
 * - a and b are operands of at least lambda bytes
 */
int isEqual(char* a, char* b){
    if (a==NULL || b==NULL) { return 0; }
    char res = 0;
    for (ssize_t i=0; i<lambda; i++){
        /* Any differing bits will be stored in res */
        res |= a[i] ^ b[i];
    }
    return res == 0;
}

/* Returns 0 if operand is nonzero, returns nonzero if 0. 
 * - a is the operand of at least lambda bytes 
 */
int isZero(char* a){
    if (a==NULL) { return 0; }
    char res = 0;
    for (ssize_t i=0; i<lambda; i++){
        /* Any differing bits will be stored in res */
        res |= a[i];
    }
    return res == 0;
}

/* Performs left bit shift on a over b bits and stores the result in res.
 * - res is the result, must be at least lambda bytes long. This will not 
 * exceed lambda bytes, so any bits shifted beyond lambda bytes will be lost,
 * however bits already in res beyond lambda bytes will remain.
 * - a is the operand of bits to be shifted, must be lambda bytes long.
 * - b is the number of bits to shift to the left.
 */
void leftShiftBytes(unsigned char* res, unsigned char* a, int b){
    memcpy(res, a, lambda*sizeof(char));
    /* shift one byte at a time */
    while (b > (BYTE*sizeof(char))){
        for (ssize_t i=lambda-1; i>0; i--){
            res[i] = res[i-1];
        }
        b-=BYTE*sizeof(char);
    }
    unsigned char carry;
    /* shift bits at a time */
    for (ssize_t i=lambda-1; i>0; i--){
        carry = res[i-1] >> (BYTE*sizeof(char) - b);
        res[i] = res[i] << b;
        res[i] |= carry;
    }
    res[0] = res[0] << b;
}

/* Performs right bit shift on a over b bits and stores the result in res.
 * - res is the result, must be at least lambda bytes long. 
 * - a is the operand of bits to be shifted, must be at least lambda bytes long.
 * - b is the number of bits to shift to the right.
 */
void rightShiftBytes(unsigned char* res, unsigned char* a, int b){
    memcpy(res, a, lambda*sizeof(char));
    /* shift one byte at a time */
    while (b > (BYTE*sizeof(char))){
        for (ssize_t i=1; i<lambda; i++){
            res[i-1] = res[i];
        }
        b-=BYTE*sizeof(char);
    }
    unsigned char carry;
    for (ssize_t i=1; i<lambda; i++){
        carry = res[i] << (BYTE*sizeof(char) - b);
        res[i-1] = res[i-1] >> b;
        res[i-1] |= carry;
    }
    res[0] = res[0] >> b;
}

/* These next few arithmetic functions are from 
 * A Computational Introduction to Number Theory and Algebra
 * by Victor Shoup
 */

/* Adds operands a and b together as though they were huge numbers 
 * - res stores the sum. Must be at least lambda bytes long. Carry beyond 
 * lambda bytes is ignored 
 * - a and b are the summands. Must be at least lambda bytes long.
 */
void addBytes(char* res, char* a, char* b){
    unsigned char carry = 0;
    int tmp = 0;
    for (ssize_t i=0; i<lambda; i++){
        tmp = a[i] + b[i] + carry;
        res[i] = (char)tmp;
        carry = (char)(tmp >> (sizeof(char)*BYTE));
    }
}

/* Adds operands a and b together as though they were huge numbers 
 * - res stores the sum. Must be at least 2*lambda bytes long. Carry beyond 
 * lambda bytes is ignored 
 * - a and b are the summands. Must be at least 2*lambda bytes long.
 */
void addDoubleBytes(char* res, char* a, char* b){
    unsigned char carry = 0;
    int tmp = 0;
    for (ssize_t i=0; i<2*lambda; i++){
        tmp = a[i] + b[i] + carry;
        res[i] = (char)tmp;
        carry = (char)(tmp >> (sizeof(char)*BYTE));
    }
}

/* Subtracts operands a and b as though they were huge numbers 
 * - res stores the difference, spesifically res = a - b. Must be at least 
 * lambda bytes long
 * - a is the minuend, must be at least lambda bytes long.
 * - a is the subtrahend, must be at least lambda bytes long.
 */
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

/* Subtracts operands a and b as though they were huge numbers 
 * - res stores the difference, spesifically res = a - b. Must be at least 
 * 2*lambda bytes long
 * - a is the minuend, must be at least 2*lambda bytes long.
 * - a is the subtrahend, must be at least 2*lambda bytes long.
 */
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

/* Multiplies a and b together as though they were huge numbers. 
 * - res stores the product. MUST be AT LEAST 2*lambda bytes long
 * - a and b are factors, must be at least lambda bytes long
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

/* Multiplies a and b together as though they were huge numbers. 
 * - res stores the product. MUST be AT LEAST 4*lambda bytes long
 * - a and b are factors, must be at least 2*lambda bytes long
 */
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

/* ==================================================================
 * Primitives
 * ==================================================================
 */

/* Creates a randomly generated key of size bytes */
char* KeyGen(ssize_t size){
    char* key = malloc(size*sizeof(char));
    randomBytes(key, size*sizeof(char));
    return key;
}

/* Performs deterministic OTP encrytpion on the message with the key.
 * - k must be at least lambda bytes long
 * - m must be at least lambda bytes long
 * - returns a ciphertext that is lambda bytes long
 */
char* otpDetEnc(char* k, char* m){
    char* c = malloc(sizeof(char)*lambda);
    xorBytes(c, k, m);
    return c;
}

/* Performs deterministic OTP decrytpion on the ciphertex with the key.
 * - k must be at least lambda bytes long
 * - c must be at least lambda bytes long
 * - returns a message that is lambda bytes long
 */
char* otpDetDec(char* k, char* c){
    char* m = malloc(sizeof(char)*lambda);
    xorBytes(m, k, c);
    return m;
}

/* Performs random OTP encrytpion on the message with the key.
 * - k must be at least lambda bytes long
 * - m must be at least lambda bytes long
 * - returns ciphertext that is 2*lambda bytes long
 */
char* otpRandEnc(char* k, char* m){
    char* c = malloc(sizeof(char)*2*lambda);
    randomBytes(c+lambda, lambda);
    char* prf = linearPrf(k, c+lambda);
    xorBytes(c, prf, m);
    free(prf);
    return c;
}

/* Performs random OTP decrytpion on the ciphertext with the key.
 * - k, must be at least lambda bytes long
 * - c must be at least 2*lambda bytes long
 * - returns messge that is lambda bytes long
 */
char* otpRandDec(char* k, char* c){
    char* m = malloc(sizeof(char)*lambda);
    char* prf = linearPrf(k, c+lambda);
    xorBytes(m, prf, c);
    free(prf);
    return m;
}

/* This is a linear congruential generator. This is only used in the 
 * libraries where the user passes a seed that they create. This is a bad 
 * generator, but hopefully attacking this is harder than the attacking 
 * intended library. 
 * - res stores the result and must be lambda bytes
 * - seed must be lambda bytes
 */
void linearG(char* res, char* seed){
    char* a = calloc(lambda, sizeof(char));
    char* c = calloc(lambda, sizeof(char));
    char* tmp = calloc(2*lambda, sizeof(char));
    c[0] = 4;
    /* set a = 2^lambda - 4 */
    subtractBytes(a,a,c);
    c[0] = 3;
    multiplyBytes(tmp, seed, a);
    addBytes(tmp, tmp, c);
    /* only return upper bits since lower bits are somewhat predictable */
    memcpy(res, tmp+lambda, sizeof(char)*lambda);
    free(a);
    free(c);
    free(tmp);
}

/* This is a length doubling linear congruential generator. This is a 
 * bad generator, but hopefully attacking this is harder than the attacking 
 * intended library. 
 * - res stores the result and must be 2*lambda bytes
 * - seed must be lambda bytes
 */
void linearDoubleG(char* res, char* seed){
    char* a = calloc(2*lambda, sizeof(char));
    char* c = calloc(2*lambda, sizeof(char));
    char* tmpSeed = calloc(2*lambda, sizeof(char));
    memcpy(tmpSeed, seed, lambda*sizeof(char));
    char* tmp = calloc(4*lambda, sizeof(char));
    c[0] = 4;
    /* set a = 2^(2*lambda) - 4 */
    subtractDoubleBytes(a,a,c);
    c[0] = 3;
    multiplyDoubleBytes(tmp, tmpSeed, a);
    addDoubleBytes(tmp, tmp, c);
    /* Generator is done twice to properly fill out tmp since seed 
     * only needs to be lambda bytes 
     */
    multiplyDoubleBytes(tmp, tmp, a);
    addDoubleBytes(tmp, tmp, c);
    /* only return upper bits since lower bits are somewhat predictable */
    memcpy(res, tmp+lambda, sizeof(char)*2*lambda);
    free(a);
    free(c);
    free(tmp);
    free(tmpSeed);
}

/* PRF constructed using linearG to specification of Construction 6.4 
 * - k is the key and must be at least lambda bytes
 * - x must be at least lambda bytes
 * - returns lambda bytes, however 2*lambda bytes are allocated there
 */
char* linearPrf(char* k, char* x){
    char* v = calloc(lambda*2, sizeof(char));
    memcpy(v, k, sizeof(char)*lambda);
    linearDoubleG(v, v);
    for (ssize_t i=0; i<lambda; i++){
        unsigned char j;
        for (j=1; j>0; j*=2){
            if (x[i] & j){
                /* lower bits of the output of linearDoubleG */
                linearDoubleG(v, v);
            } else {
                /* upper bits of the output of linearDoubleG */
                linearDoubleG(v, v+(lambda*sizeof(char)));
            }
        }
        if (x[i] & j){
            linearDoubleG(v, v);
        } else {
            linearDoubleG(v, v+(lambda*sizeof(char)));
        }
    }
    return v;
}

/* PRP constructed to the specification of Construction 6.11 
 * - k must be 3*lambda bytes long representing 3 unique keys 
 * - x must be 2*lambda bytes long 
 * - returns 2*lambda bytes
 */
char* linearPrp(char* k, char* x){
    char* v1 =  calloc(lambda, sizeof(char));
    memcpy(v1,x,lambda*sizeof(char));
    char* v0 =  calloc(lambda, sizeof(char));
    memcpy(v0,x+lambda,lambda*sizeof(char));
    char* tmp;
    for (ssize_t i=0;i<3;i++){
        tmp = linearPrf(k+(i*lambda), v1);
        xorBytes(tmp,v0,tmp);
        free(v0);
        v0 = v1;
        v1 = tmp;
    }
    /* Using the fact that linearPrf actually allocates 2*lambda bytes */
    memcpy(v0+lambda, v1, lambda*sizeof(char));
    free(v1);
    return v0;
}

/* PRP Inverse constructed to the specification of Construction 6.11
 * - k must be 3*lambda bytes long representing 3 unique keys 
 * - x must be 2*lambda bytes long 
 * - returns 2*lambda bytes
 */
char* linearPrpInverse(char* k, char* x){
    char* v1 =  calloc(lambda, sizeof(char));
    memcpy(v1,x,lambda*sizeof(char));
    char* v0 =  calloc(lambda, sizeof(char));
    memcpy(v0,x+lambda,lambda*sizeof(char));
    char* tmp;
    for (ssize_t i=2;i>=0;i--){
        tmp = linearPrf(k+(i*lambda), v1);
        xorBytes(tmp,v0,tmp);
        free(v0);
        v0 = v1;
        v1 = tmp;
    }
    /* Using the fact that linearPrf actually allocates 2*lambda bytes */
    memcpy(v0+lambda, v1, lambda*sizeof(char));
    free(v1);
    return v0;
}

/* ==================================================================
 * CHAPTER 2
 * ==================================================================
 */

/* 
 * One time secrecy (ots) example from Chapter 2 Section 3 of the book 
 * - k lambda bytes key
 * - m lambda bytes message
 * - returns lambda bytes ciphertext
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
    randomBytes(c,lambda*sizeof(char));
    return c;
}

int se2_3OtsDistinguish(char (*attack)(Scheme*)){
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
        return 1;
    } 
    if ((choice & 1) == 0 && result == 'R'){
        return 1;
    } 

    if ((choice & 2) == 2 && result == '$'){
        return 1;
    } 

    if ((choice & 2) == 0 && result == 'r'){
        return 1;
    } 
    
    return 0;
}

/* Chapter 2 Homework Problem 1 */

char* hw2_1KeyGen(){
    char* c = malloc(sizeof(char)*lambda);
    randomBytes(c, sizeof(char)*lambda);
    char* zero = malloc(sizeof(char)*lambda);
    zeroBytes(zero, lambda);
    while (isEqual(c, zero)){
        randomBytes(c, sizeof(char)*lambda);
    }
    free(zero);
    return c;
}

char* hw2_1EAVESDROPL(char* mL, char* mR){
    char* key = hw2_1KeyGen();
    char* c = otpDetEnc(key, mL);
    free(key);
    return c;
}

char* hw2_1EAVESDROPR(char* mL, char* mR){
    char* key = hw2_1KeyGen();
    char* c = otpDetEnc(key, mR);
    free(key);
    return c;
}

char* hw2_1CTXTreal(char* m){
    char* key = hw2_1KeyGen();
    char* c = otpDetEnc(key, m);
    free(key);
    return c;
}

char* hw2_1CTXTrandom(char* m){
    char* c = malloc(sizeof(char)*lambda);
    randomBytes(c,sizeof(char)*lambda);
    return c;
}

int hw2_1OtsDistinguish(char (*attack)(Scheme*)){
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
        return 1;
    } 
    if ((choice & 1) == 0 && result == 'R'){
        return 1;
    } 

    if ((choice & 2) == 2 && result == '$'){
        return 1;
    } 

    if ((choice & 2) == 0 && result == 'r'){
        return 1;
    } 
    
    return 0;
}

/* ==================================================================
 * CHAPTER 5
 * ==================================================================
 */

/* Chapter 5 Homework Problem 1 a */
/* This is a *secure* length tripling PRG. The security is dependent on 
 * the linear congruential generator linearG. While linearG clearly isn't 
 * secure, attacking the implementation of G should be more difficult than
 * attacking the intended library. 
 */
char* hw5_1G(char* s){
    char* num = malloc(3*lambda*sizeof(char));
    linearDoubleG(num, s);
    /* Using the upper bits as seed to next call, then replacing them */
    linearDoubleG(num + lambda, num + lambda);
    return num;
}

char* hw5_1aPRGreal(){
    char* s = malloc(sizeof(char)*lambda);
    randomBytes(s, sizeof(char)*lambda);
    char* x = hw5_1G(s);
    char* zero = malloc(sizeof(char)*lambda);
    zeroBytes(zero, lambda);
    char* y = hw5_1G(zero);
    /* We return x||y where x and y are each 3*lambda bytes long */
    char* res = malloc(6*lambda*sizeof(char));
    memcpy(res, y, 3*lambda*sizeof(char));
    memcpy(res+3*lambda, x, 3*lambda*sizeof(char));
    free(s);
    free(zero);
    free(x);
    free(y);
    return res;
}

char* hw5_1aPRGrand(){
    char* res = malloc(6*lambda*sizeof(char));
    randomBytes(res, 6*lambda*sizeof(char));
    return res;
}

int hw5_1aPrgDistinguish(char (*attack)(Scheme*)){
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
        return 1;
    } 

    if ((choice & 2) == 0 && result == 'r'){
        return 1;
    } 
    
    return 0;
}

/* Chapter 5 Homework Problem 1b */
char* hw5_1bPRGreal(){
    char* s = malloc(sizeof(char)*lambda);
    randomBytes(s, sizeof(char)*lambda);
    char* x = hw5_1G(s);
    char* zero = malloc(sizeof(char)*lambda);
    zeroBytes(zero, lambda);
    char* y = hw5_1G(zero);
    /* x = x xor y then return the new x */
    xorBytes(x,x,y);
    free(s);
    free(y);
    free(zero);
    return x;
}

char* hw5_1bPRGrand(){
    char* res = malloc(3*lambda*sizeof(char));
    randomBytes(res, 3*lambda*sizeof(char));
    return res;
}

int hw5_1bPrgDistinguish(char (*attack)(Scheme*)){
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
        return 1;
    } 

    if ((choice & 2) == 0 && result == 'r'){
        return 1;
    } 
    
    return 0;
}

/* Chapter 5 Homework Problem 1c 
 * - returns 6*lambda bytes
 */
char* hw5_1cPRGreal(){
    char* s = malloc(sizeof(char)*lambda);
    randomBytes(s,sizeof(char)*lambda);
    /* xyz = x||y||z = G(s) */
    char* xyz = hw5_1G(s);
    char* x = xyz + 2*lambda;
    char* w = hw5_1G(x);
    /* res = x||y||z||w */
    char* res = malloc(6*lambda*sizeof(char));
    memcpy(res, w, sizeof(char)*lambda*3);
    memcpy(res+3*lambda, xyz, sizeof(char)*lambda*3);
    
    free(s);
    free(xyz);
    free(w);
    return res;
}

char* hw5_1cPRGrand(){
    char* res = malloc(6*lambda*sizeof(char));
    randomBytes(res, 6*lambda*sizeof(char));
    return res;
}

int hw5_1cPrgDistinguish(char (*attack)(Scheme*)){
    Scheme scheme = {NULL, NULL, NULL, NULL, NULL, NULL, NULL};
    char choice;
    randomBytes(&choice, sizeof(char));
    if (choice & 2){
        scheme.QUERY = hw5_1cPRGrand;
    } else {
        scheme.QUERY = hw5_1cPRGreal;
    }
    char result = attack(&scheme);
    cleanGlobals();
    if ((choice & 2) == 2 && result == '$'){
        return 1;
    } 

    if ((choice & 2) == 0 && result == 'r'){
        return 1;
    } 
    
    return 0;
}

/* ==================================================================
 * CHAPTER 6
 * ==================================================================
 */
/* Chapter 6 Homework Problem 1 */

/* Returns 2*lambda bits */
char* hw6_1Prf(char* k, char* m){
    /* linearPrf is defined to return lambda bits, but that pointer is 
     * assigned 2*lambda bits, so we will use those bits too.
     */
    char* tmp = linearPrf(k,m);
    char* res = linearPrf(k,tmp);
    memcpy(res+lambda, tmp, sizeof(char)*lambda);
    free(tmp);
    return res;
}

char* hw6_1LOOKUPreal(char* x){
    return hw6_1Prf(KEY, x);
}

char* hw6_1LOOKUPrand(char* x){
    char* lookup = TLookup(x);
    if (lookup == NULL){
        lookup = malloc(sizeof(char)*2*lambda);
        randomBytes(lookup, sizeof(char)*2*lambda);
        Tadd(x, lookup);
    }
    return lookup;
}

int hw6_1PrfDistinguish(char (*attack)(Scheme*)){
    Scheme scheme = {NULL, NULL, NULL, NULL, NULL, NULL, NULL};
    char choice;
    randomBytes(&choice, sizeof(char));
    if (choice & 1){
        scheme.LOOKUP = hw6_1LOOKUPrand;
    } else {
        scheme.LOOKUP = hw6_1LOOKUPreal;
    }
    KEY = malloc(sizeof(char) * lambda);
    randomBytes(KEY, sizeof(char)*lambda);
    TInit(lambda, 2*lambda);
    char result = attack(&scheme);
    cleanGlobals();
    if ((choice & 1) == 1 && result == '$'){
        return 1;
    } 

    if ((choice & 1) == 0 && result == 'r'){
        return 1;
    } 
    
    return 0;
}

/* Homework 6 Problem 2 */
/* The homework uses blen for inputs but does operations in blen/2,
 * so this implementation will take 2*lambda inputs so operations
 * can be done in lambda
 * - k is 2*lambda bytes
 * - m is 2*lambda bytes
 */
char* hw6_2Prp(char* k, char* m){
    char* res = malloc(sizeof(char)*2*lambda);
    char* x = m+lambda;
    char* y = m;
    char* y1 = x;
    char* x1 = linearPrf(k,x);
    xorBytes(x1, y, x1);
    char* x2 = x1;
    char* y2 = linearPrf(k+lambda,y1);
    xorBytes(y2, x1, y2);
    memcpy(res, y2, sizeof(char)*lambda);
    memcpy(res + lambda, x2, sizeof(char)*lambda);
    free(x1);
    free(y2);
    return res;
}

char* hw6_2LOOKUPreal(char* x){
    return hw6_2Prp(KEY, x);
}

char* hw6_2LOOKUPrand(char* x){
    char* lookup = TLookup(x);
    if (lookup == NULL){
        lookup = malloc(sizeof(char)*2*lambda);
        randomBytes(lookup, sizeof(char)*2*lambda);
        Tadd(x, lookup);
    }
    return lookup;
}

int hw6_2PrpDistinguish(char (*attack)(Scheme*)){
    Scheme scheme = {NULL, NULL, NULL, NULL, NULL, NULL, NULL};
    char choice;
    randomBytes(&choice, sizeof(char));
    if (choice & 1){
        scheme.LOOKUP = hw6_2LOOKUPrand;
    } else {
        scheme.LOOKUP = hw6_2LOOKUPreal;
    }
    KEY = KeyGen(2*lambda);
    TInit(2*lambda, 2*lambda);
    char result = attack(&scheme);
    cleanGlobals();
    if ((choice & 1) == 1 && result == '$'){
        return 1;
    } 

    if ((choice & 1) == 0 && result == 'r'){
        return 1;
    } 
    
    return 0;
}

/* ==================================================================
 * CHAPTER 7
 * ==================================================================
 */
/* Chapter 7 Problem 2 */
/* Note k must be 3*lambda bytes long and m must be 2*lambda
 * bytes long for the PRP 
 * returns 
 */
char* hw7_2CpaEnc(char* k, char* m){
    char* s1 = malloc(sizeof(char)*2*lambda);
    randomBytes(s1, lambda);
    char* s2 = malloc(sizeof(char)*2*lambda);
    xorBytes(s2, s1, m);
    char* x = linearPrp(k,s1);
    char* c = linearPrp(k,s2);
    memcpy(c+lambda, x, lambda*sizeof(char));
    free(s1);
    free(s2);
    free(x);
    return c;
}

char* hw7_2EAVESDROPL(char* ml, char* mr){
    char* key = KeyGen(3*lambda);
    char* c = hw7_2CpaEnc(key, ml);
    free(key);
    return c;
}

char* hw7_2EAVESDROPR(char* ml, char* mr){
    char* key = KeyGen(3*lambda);
    char* c = hw7_2CpaEnc(key, mr);
    free(key);
    return c;
}

char* hw7_2CTXTreal(char* m){
    char* key = KeyGen(3*lambda);
    char* c = hw7_2CpaEnc(key, m);
    free(key);
    return c;
}

char* hw7_2CTXTrand(char* m){
    char* c = malloc(2*lambda*sizeof(char));
    randomBytes(c, 2*lambda);
    return c;
}

int hw7_2CpaDistinguish(char (*attack)(Scheme*)){
    Scheme scheme = {NULL, NULL, NULL, NULL, NULL, NULL, NULL};
    char choice;
    randomBytes(&choice, sizeof(char));
    if (choice & 1){
        scheme.EAVESDROP = hw7_2EAVESDROPL;
    } else {
        scheme.EAVESDROP = hw7_2EAVESDROPR;
    }
    if (choice & 2){
        scheme.CTXT = hw7_2CTXTrand;
    } else {
        scheme.CTXT = hw7_2CTXTreal;
    }
    char result = attack(&scheme);
    if ((choice & 1) == 1 && result == 'L'){
        return 1;
    } 
    if ((choice & 1) == 0 && result == 'R'){
        return 1;
    } 

    if ((choice & 2) == 2 && result == '$'){
        return 1;
    } 

    if ((choice & 2) == 0 && result == 'r'){
        return 1;
    } 
    
    return 0;
}