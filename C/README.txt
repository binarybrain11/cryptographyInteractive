Welcome to the C implementation!

Here in C land, any data whose length is defined by lambda bytes are 
represented as character arrays and passed around with char* such as messages, 
ciphertexts, and keys. lambda itself is a constant that you define in your 
file BEFORE including cryptointeractive.h, like so:

#define lambda 4
#include "cryptointeractive.h"

You can check cryptointeractive.h to see what problems are implemented 
and for any extra details about a specific problem like which functions 
a scheme implements or if the input/output have different sizes than 
specified in the book or homework. 

The attacking function will have the following prototype:
char myAttack(Scheme *scheme);
The Scheme struct carries function pointers to all of the functions defined 
by the implemented library. Only the functions that are defined by the library 
are given pointers, the others are NULL pointers; if the compiler doesn't
like a function call, check that the function is implemented for the scheme.
Every function that returns a char* returns allocated memory, so it 
is up to the caller (you) to free this memory.
The attacking function will return a single character to indicated its guess
for distinguishing the actual libraries. The guesses are:
'L' for the Left library in a left vs right attack
'R' for the Right library in a left vs right attack
'$' for the random library in a real vs random attack 
'r' for the real library in a real vs random attack 
Every time the scheme's attack function is called to run your attacking 
function, it will randomly select which library to give your attacking 
function and put that implementation in the Scheme.

The header also includes some helper functions to make working with char* 
easier. 
void zeroBytes(char* res, ssize_t size);
This function puts size bytes of zero bytes into res.
void oneBytes(char* res, ssize_t size);
This function puts size bytes of one bytes into res. 
void randomBytes(char* res, ssize_t size);
This function puts size bytes of random bytes generated from /dev/urandom into res.

These functions assume the parameters have lambda bytes.
void xorBytes(char* res, char* a, char* b);
This function performs xor on a and b and puts the result in res.
void andBytes(char* res, char* a, char* b);
This function performs and on a and b and puts the result in res.
void orBytes(char* res, char* a, char* b);
This function performs or on a and b and puts the result in res.
int isEqual(char* res, char* a, char* b);
This function checks whether the first lambda bytes pointed to by a and b are 
equal. Returns 1 if they are, 0 if they aren't.