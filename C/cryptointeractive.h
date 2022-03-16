
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>

typedef struct {
    /* Prototypes below are empty to support varying arguments depending 
     * on the scheme 
     */
    /* For every function, the first parameter is the block length lambda */
    char* (*EAVESDROP)();
    char* (*CTXT)();
    char* (*SHARE)();
    char* (*QUERY)();
    char* (*LOOKUP)();
    char* (*INVERSE)();
    char* (*DECRYPT)();
} Scheme;

/* Generic Helper Functions */
void zeroBytes(char* res, ssize_t numBytes);
void oneBytes(char* res, ssize_t numBytes);
void randomBytes(char* res, ssize_t numBytes);
void xorBytes(char* res, char* a, char* b);
void andBytes(char* res, char* a, char* b);
void orBytes(char* res, char* a, char* b);
int isEqual(char* a, char* b);
int isZero(char* a);

/* Some Primitives */
void linearDoubleG(char* res, char* seed);
char* linearPrf(char* k, char* x);

/* Helper function to compute attack advantage */
double Advantage(unsigned int trials, char (*attack)(), int (*attackInterface)());

/* ======================================
 * Implemented Problems 
 * ======================================
 */

/* Chapter 2 section 3 example 
 * Implements CTXT() and EAVESDROP() 
 */
int se2_3OtsAttack(char (*attack)(Scheme*));

/* Chapter 2 Homework Problem 1 
 * Implements CTXT() and EAVESDROP() 
 */
int hw2_1OtsAttack(char (*attack)(Scheme*));

/* Chapter 5 Homework Problem 1 
 * *secure* length tripling PRG. Not actually secure, but treat it as such. 
 * - s is the seed with at least lambda bytes
 * - returns 3*lambda bytes
 */
char* hw5_1G(char* s);
/* Chapter 5 Homework Problem 1a 
 * Implements QUERY() 
 */
int hw5_1aPrgAttack(char (*attack)(Scheme*));
/* Chapter 5 Homework Problem 1b 
 * Implements QUERY() 
 */
int hw5_1bPrgAttack(char (*attack)(Scheme*));
/* Chapter 5 Homework Problem 1c 
 * Implements QUERY() 
 */
int hw5_1cPrgAttack(char (*attack)(Scheme*));
/* Chapter 6 Homework Problem 1
 * Implements LOOKUP() 
 */
int hw6_1PrfAttack(char (*attack)(Scheme*));
/* Chapter 6 Homework Problem 2 
 * Implements LOOKUP() 
 * Inputs and outputs for this scheme are 2*lambda rather than lambda
 */
int hw6_2PrfAttack(char (*attack)(Scheme*));
/* Chapter 7 Homeowrk Problem 2
 * Implements CTXT() and EAVESDROP() 
 * The output (x,y) is concatenated with x as the most significant bits
 */
int hw7_2CpaAttack(char (*attack)(Scheme*)){