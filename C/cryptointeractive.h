
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>

static ssize_t lambda = 4;

typedef struct {
    /* Prototypes below are empty to support varying arguments depending 
     * on the scheme. 
     */
    char* (*EAVESDROP)(char* ml, char* mr);
    char* (*CTXT)(char* m);
    char* (*SHARE)();
    char* (*QUERY)();
    char* (*LOOKUP)(char* m);
    char* (*INVERSE)(char* c);
    char* (*DECRYPT)(char* c);
} Scheme;

/* Generic Helper Functions */

/* Sets a block of memory to 0 bytes 
 * - bytes is the block of memory to modify
 * - numBytes is the number of bytes to modify. bytes must be at least this big
 */
void zeroBytes(char* res, ssize_t numBytes);

/* Sets a block of memory to bytes of all 1's, eg 0xFF
 * - bytes is the block of memory to modify
 * - numBytes is the number of bytes to modify. bytes must be at least this big
 */
void oneBytes(char* res, ssize_t numBytes);

/* - res needs to be at least numBytes long
 * - numBytes is the number of bytes to store into res
 */
void randomBytes(char* res, ssize_t numBytes);

/* Does a bitwise XOR over lambda bytes. 
 * - res is the block of memory to store the results in. Must be at least lambda 
 * bytes
 * - a and b are operands of at least lambda bytes 
 */
void xorBytes(char* res, char* a, char* b);

/* Does a bitwise AND over lambda bytes. 
 * - res is the block of memory to store the results in. Must be at least lambda 
 * bytes
 * - a and b are operands of at least lambda bytes 
 */
void andBytes(char* res, char* a, char* b);

/* Does a bitwise OR over lambda bytes. 
 * - res is the block of memory to store the results in. Must be at least lambda 
 * bytes
 * - a and b are operands of at least lambda bytes 
 */
void orBytes(char* res, char* a, char* b);

/* Returns 0 (false) if operands aren't equal and a nonzero (true) value if they 
 * are equal 
 * - a and b are operands of at least lambda bytes
 */
int isEqual(char* a, char* b);

/* Returns 0 (false) if operand is nonzero, returns nonzero (true) if 0. 
 * - a is the operand of at least lambda bytes 
 */
int isZero(char* a);

/* Adds operands a and b together as though they were huge numbers 
 * - res stores the sum. Must be at least lambda bytes long. Carry beyond 
 * lambda bytes is ignored 
 * - a and b are the summands. Must be at least lambda bytes long.
 */
void addBytes(char* res, char* a, char* b);

/* Subtracts operands a and b as though they were huge numbers 
 * - res stores the difference, spesifically res = a - b. Must be at least 
 * lambda bytes long
 * - a is the minuend, must be at least lambda bytes long.
 * - a is the subtrahend, must be at least lambda bytes long.
 */
void subtractBytes(char* res, char* a, char* b);

/* Multiplies a and b together as though they were huge numbers. 
 * - res stores the product. MUST be AT LEAST 2*lambda bytes long
 * - a and b are factors, must be at least lambda bytes long
 */
void multiplyBytes(unsigned char* res, unsigned char* a, unsigned char* b);

/* Some Primitives */
/* Creates a randomly generated key of size bytes */
char* KeyGen(ssize_t size);

/* Performs deterministic OTP encrytpion on the message with the key.
 * - k must be at least lambda bytes long
 * - m must be at least lambda bytes long
 * - returns a ciphertext that is lambda bytes long
 */
char* otpDetEnc(char* k, char* m);

/* Performs deterministic OTP decrytpion on the ciphertex with the key.
 * - k must be at least lambda bytes long
 * - c must be at least lambda bytes long
 * - returns a message that is lambda bytes long
 */
char* otpDetDec(char* k, char* c);

/* Performs random OTP encrytpion on the message with the key.
 * - k must be at least lambda bytes long
 * - m must be at least lambda bytes long
 * - returns ciphertext that is 2*lambda bytes long
 */
char* otpRandEnc(char* k, char* m);

/* Performs random OTP decrytpion on the ciphertext with the key.
 * - k, must be at least lambda bytes long
 * - c must be at least 2*lambda bytes long
 * - returns messge that is lambda bytes long
 */
char* otpRandDec(char* k, char* c);

/* This is a length doubling linear congruential generator. This is a 
 * bad generator, but hopefully attacking this is harder than the attacking 
 * intended library. 
 * - res stores the result and must be 2*lambda bytes
 * - seed must be lambda bytes
 */
void linearDoubleG(char* res, char* seed);

/* PRF constructed using linearG to specification of Construction 6.4 
 * - k is the key and must be at least lambda bytes
 * - x must be at least lambda bytes
 * - returns lambda bytes, however 2*lambda bytes are allocated there
 */
char* linearPrf(char* k, char* x);

/* PRP constructed to the specification of Construction 6.11 
 * - k must be 3*lambda bytes long representing 3 unique keys 
 * - x must be 2*lambda bytes long 
 * - returns 2*lambda bytes
 */
char* linearPrp(char* k, char* x);

/* PRP Inverse constructed to the specification of Construction 6.11
 * - k must be 3*lambda bytes long representing 3 unique keys 
 * - x must be 2*lambda bytes long 
 * - returns 2*lambda bytes
 */
char* linearPrpInverse(char* k, char* x);

/* Computes the distinguishing advantage of an attacker. 0.5 is unable to distinguish, 
 * 1 is distinguishes correctly every time, 0 distinguishes incorrectly every time
 * - trials is the number of trials to run the attack. The more trials, the more 
 * accurate the advantage
 * - attack is the user attack function to be called inside of the distinguish
 * - distinguisher is the function representing the problem, e.g. se2_3OtsDistinguish()
 * - returns a double indicating the advantage of the attacker
 */
double Advantage(unsigned int trials, char (*attack)(), int (*distinguisher)());

/* ======================================
 * Implemented Problems 
 * ======================================
 */

/* Chapter 2 section 3 example 
 * Implements CTXT() and EAVESDROP() 
 */
int se2_3OtsDistinguish(char (*attack)(Scheme*));

/* Chapter 2 Homework Problem 1 
 * Implements CTXT() and EAVESDROP() 
 */
int hw2_1OtsDistinguish(char (*attack)(Scheme*));

/* Chapter 5 Homework Problem 1 
 * *secure* length tripling PRG. Not actually secure, but treat it as such. 
 * - s is the seed with at least lambda bytes
 * - returns 3*lambda bytes
 */
char* hw5_1G(char* s);
/* Chapter 5 Homework Problem 1a 
 * Implements QUERY() 
 */
int hw5_1aPrgDistinguish(char (*attack)(Scheme*));
/* Chapter 5 Homework Problem 1b 
 * Implements QUERY() 
 */
int hw5_1bPrgDistinguish(char (*attack)(Scheme*));
/* Chapter 5 Homework Problem 1c 
 * Implements QUERY() 
 */
int hw5_1cPrgDistinguish(char (*attack)(Scheme*));
/* Chapter 6 Homework Problem 1
 * Implements LOOKUP() 
 */
int hw6_1PrfDistinguish(char (*attack)(Scheme*));
/* Chapter 6 Homework Problem 2 
 * Implements LOOKUP() 
 * Inputs and outputs for this scheme are 2*lambda rather than lambda
 */
int hw6_2PrpDistinguish(char (*attack)(Scheme*));
/* Chapter 7 Homeowrk Problem 2
 * Implements CTXT() and EAVESDROP() 
 * The output (x,y) is concatenated with x as the most significant bits
 * Inputs and outputs are 2*lambda rather than lambda
 */
int hw7_2CpaDistinguish(char (*attack)(Scheme*));