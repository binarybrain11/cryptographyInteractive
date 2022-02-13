
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
char* zeroBytes(ssize_t lambda);
char* oneBytes(ssize_t lambda);
char* randomBytes(ssize_t lambda);
int isEqual(ssize_t lambda, char* a, char* b);

/* Chapter 2 section 3 example */
/* Implements CTXT() and EAVESDROP() */
int se2_3OtsAttack(ssize_t lambda, char (*attack)(ssize_t, Scheme*));
double se2_3OtsAdvantage(ssize_t lambda, unsigned int trials, char (*attack)(ssize_t, Scheme*));

/* Chapter 2 Homework Problem 1 */
/* Implements CTXT() and EAVESDROP() */
int hw2_1OtsAttack(ssize_t lambda, char (*attack)(ssize_t, Scheme*));
double hw2_1OtsAdvantage(ssize_t lambda, unsigned int trials, char (*attack)(ssize_t, Scheme*));

/* Chapter 5 Homework Problem 1 */
/* *secure* length tripling PRG. Not actually secure, but treat it as such. 
 * Seeds given to this function are truncated to sizeof(int) so consider using 
 * a size less than or equal to sizeof(int) for lambda 
 */
char* hw5_1G(ssize_t lambda, char* s);
/* Chapter 5 Homework Problem 1a */
/* Implements QUERY() */
int hw5_1aPrgAttack(ssize_t lambda, char (*attack)(ssize_t, Scheme*));
double hw5_1aPrgAdvantage(ssize_t lambda, unsigned int trials, char (*attack)(ssize_t, Scheme*));
/* Chapter 5 Homework Problem 1b */
/* Implements QUERY() */
int hw5_1bPrgAttack(ssize_t lambda, char (*attack)(ssize_t, Scheme*));
double hw5_1bPrgAdvantage(ssize_t lambda, unsigned int trials, char (*attack)(ssize_t, Scheme*));
/* Chapter 5 Homework Problem 1c */
/* Implements QUERY() */
int hw5_1cPrgAttack(ssize_t lambda, char (*attack)(ssize_t, Scheme*));
double hw5_1cPrgAdvantage(ssize_t lambda, unsigned int trials, char (*attack)(ssize_t, Scheme*));