Welcome to the C implementation!

Here in C land, any data whose length is defined by lambda bytes are 
represented as character arrays and passed around with char* such as messages, 
ciphertexts, and keys. lambda itself is a ssize_t, a type included by 
<sys/types.h>. 

The attacking function will have the following prototype:
char myAttack(ssize_t lambda, Scheme *scheme);
The Scheme struct carries function pointers to all of the functions defined 
by the implemented library. Only the functions that are defined by the library 
are given pointers, the others are NULL pointers; if the compiler doesn't
like a function call, check that the function is implemented for the scheme.
All of these functions return char*, and every one is allocated memory, so it 
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
char* zeroBytes(ssize_t lambda);
This function returns lambda bytes of zero bytes. 
char* oneBytes(ssize_t lambda);
This function returns lambda bytes of one bytes. 
char* randomBytes(ssize_t lambda);
This function returns lambda bytes of random bytes generated from /dev/urandom.
int isEqual(ssize_t lambda, char* a, char* b);
This function checks whether the first lambda bytes pointed to by a and b are 
equal. Returns 1 if they are, 0 if they aren't.