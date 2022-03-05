
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

/* Chapter 2 section 3 example */
/* Implements CTXT() and EAVESDROP() */
int se2_3OtsAttack(char (*attack)(Scheme*));
double se2_3OtsAdvantage(unsigned int trials, char (*attack)(Scheme*));

/* Chapter 2 Homework Problem 1 */
/* Implements CTXT() and EAVESDROP() */
int hw2_1OtsAttack(char (*attack)(Scheme*));
double hw2_1OtsAdvantage(unsigned int trials, char (*attack)(Scheme*));

/* Chapter 5 Homework Problem 1 */
/* *secure* length tripling PRG. Not actually secure, but treat it as such. 
 * Seeds given to this function are truncated to sizeof(int) so consider using 
 * a size less than or equal to sizeof(int) for lambda 
 */
char* hw5_1G(char* s);
/* Chapter 5 Homework Problem 1a */
/* Implements QUERY() */
int hw5_1aPrgAttack(char (*attack)(Scheme*));
double hw5_1aPrgAdvantage(unsigned int trials, char (*attack)(Scheme*));
/* Chapter 5 Homework Problem 1b */
/* Implements QUERY() */
int hw5_1bPrgAttack(char (*attack)(Scheme*));
double hw5_1bPrgAdvantage(unsigned int trials, char (*attack)(Scheme*));
/* Chapter 5 Homework Problem 1c */
/* Implements QUERY() */
int hw5_1cPrgAttack(char (*attack)(Scheme*));
double hw5_1cPrgAdvantage(unsigned int trials, char (*attack)(Scheme*));