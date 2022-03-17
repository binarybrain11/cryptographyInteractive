# CryptoInteractive

This repository is an interactive companion to Mike Rosulek's "The Joy of Cryptography".
You can find implementations of the insecure libraries described in the book
to test an actual implementation of your attack.

Each library will contain a few security definitions that implement the specific encrytpion
scheme and can be attacked through a few set interfaces. In general, a security definition
sdf that implements the encryption scheme ens has the following interfaces:

### ensSdfDistinguish(attackFun):

This interface will run the attacking program once and check for correctness.
Often a security definition is attacked by distinguishing between left and right
or real and random, so calling this interface will select one implementation at
random, for example left or real, and see if your attacking program can correctly
distinguish between them. It will then return a true or a false to indicate
if the attacking program succeeded.

### Advantage(trials, attackFun, distinguisher):

This interface will basically call distinguisher() trials times to compute an
advantage which will be returned as a decimal value. Sometimes an attacking
program has a significant advantage but occaisonally fails, so running many
trials to see if the attacker distinguishes correctly gives a more accurate
depiction of the attacker's capability. Capability is measured from 0 to 1,
with 0.5 indicating the attack wasn't able to distinguish better than
random, 1 indicating the attack was able to distinguish correctly every time,
and 0 indicating the attack was able to distinguish incorrectly every time
(consider flipping your output if you read a 0).

For example, suppose we want to attack the one time secrecy of one time pad,
then we could call otpOtsAttack(). The size and trials are parameters so
users can fine tune runtime and precision to their attacking program's needs.
The way the parameters are passed are language specific, see the README in the
corresponding folders.

The attacking function shall accept a security definition
object and return a value indicating the attack's guess. Again, see the README
for your particular language for specific syntax. This object has members or
methods that are defined for that security defnition, for example one time
secrecy has an EAVESDROP() method, so attacking functions passed to otpOtsAttack()
will be given an object that has an EAVESDROP() method. The following methods should
be implemented for each security defnition:

### One Time Secrecy (Ots) and Chosen Plaintext Attack (Cpa):

#### EAVESDROP(mL, mR):

This function will either encrypt mL or mR and return the ciphertext.

#### CTXT(m):

This function will either encrypt m and return the ciphertext or will return
random bits.

### Secret Sharing Scheme (Sss):

#### SHARE(mL, mR, U):

This function will store how ever many shares specified by the scheme into U.
It is up to the caller to make sure there is enough room in U when attacking
the given scheme. While it could be possible to attack Sss with an overflow
on U, this would be an attack on the implementation and not the scheme which
we advise against, not to mention it's likely a more difficult attack.

### PsudeoRandom number Generators (Prg):

#### QUERY():

This function returns a psudeorandom number based on the implementation.

###PsudeoRandom Function (Prf):

#### LOOKUP(x):

This function returns a psudeorandom number generated from the function
specified by the scheme.
Developer's Note: Prf's require a running lookup table and key. The table
and key should be created at the beginning of an attack and destroyed at
the end of an attack.

### PsudeoRandom Permutation (Prp):

#### LOOKUP(x):

This function returns a psudeorandom number generated from the permutation
function specified by the scheme and is invertable by INVERSE(). For
example, INVERSE(LOOKUP(x)) == x.

#### INVERSE(y):

This function returns a psudeorandom number generated from the permutation
function specified by the scheme and is invertable by LOOKUP(). For
example, LOOKUP(INVERSE(y)) == y.
Developer's Note: Prp's require a running lookup table and key just like a Prf.

#### Chosen Ciphertext Attack (Cca):

EAVESDROP(mL, mR):
This function will either encrypt mL or mR and return the ciphertext.

#### DECRYPT(c):

This function will decrypt c and return the plaintext m.
Developer's Note: Similar to Prf's and Prp's, Cca's need to keep a running
lookup table and key.

From this overview, check out the README for each language to see what chapters
and problems were successfully implemented. The schemes are labelled with
source, chapter, followed by number. For example, the chapter 5 homework
problem 1a is labelled as: hw5_1a and a call to attack on that homework problem
would be hw5_1aPrgAttack(). Problems can come from homework (hw), section examples (se),
and exercises (ex). Since example attacks don't have clear numbers, we'll use
the section number that the example appears in.
There should also be an example solution in each language to demonstrate how
an attacking program is constructed and called, probably the example in chapter
2 section 3, or ex2_3OtsAttack().

# C

Here in C land, any data whose length is defined by lambda bytes are
represented as character arrays and passed around with char\* such as messages,
ciphertexts, and keys. lambda itself is a global variable provided by
cryptointeractive.h and is set to 4, but feel free to change it.

You can check cryptointeractive.h to see what problems are implemented
and for any extra details about a specific problem like which functions
a scheme implements or if the input/output have different sizes than
specified in the book or homework.

Your attacking function must have the following prototype:
char myAttack(Scheme _scheme);
The Scheme struct carries function pointers to all of the functions defined
by the implemented library. Only the functions that are defined by the library
are given pointers, the others are NULL pointers; if the compiler doesn't
like a function call, check that the function is implemented for the scheme.
Every function that returns a char_ returns allocated memory, so it
is up to the caller (you) to free this memory. Some functions return
concatenated outputs or multiple variables in the output, in C we do
this by concatenating everything. Items reading left to right are
organized by most significant bits to least significant. For example, suppose
the output of a function is stored into c, but the return says (x,y).
We can access x and y by doing pointer arithmetic on c:

```
char* c = exampleFunction();
char* x = c + lambda;
char* y = c;
```

x stores the bytes that occur after lambda bytes while y stores the lambda
least significant bytes. The same would be true if a function returns x||y.

The attacking function will return a single character to indicated its guess
for distinguishing the actual libraries. The guesses are:  
'L' for the Left library in a left vs right attack  
'R' for the Right library in a left vs right attack  
'$' for the random library in a real vs random attack  
'r' for the real library in a real vs random attack  
Every time the scheme's distinguisher function is called to run your attacking
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

# Python

### Bits class

The python implementation uses a class to represent binary that allows for easy manipulation. For example bitwise operations have been overloaded to match binary behavior. The bits can also be spliced using python string slicing i.e. x.bits[0:10] where x is a Bytes object.

#### Constructor

The class takes 1 argument for size i.e. exampleBits = Bits(size)

#### Bits.set()

To set the bits to a specific value you can use the Bits.set() method.
The set method takes an int argument. 0 or 1 will set the entire string to 0's or 1's. Any other integer will set the bits to the binary representation of the number.

### Operators and Methods

#### Supported Operators:

-   +,^,|,==

#### Overloaded methods

-   print: prints binary string
-   len: Returns length in bytes

### Attack Function

The attacking function will return a string to indicated its guess
for distinguishing the actual libraries. The guesses are:  
'left' for the Left library in a left vs right attack  
'right' for the Right library in a left vs right attack  
'random' for the random library in a real vs random attack  
'real' for the real library in a real vs random attack

# Perl

Data is passed to subroutines as a list of bytes casted to characters. For
example a message of all zeros of length lambda could be written as:

    $message = chr(0x0) x $lambda;


### Attack Function

The attacking function will be passed two arguments: lambda and scheme.
These can be captured with the line  

    my ($lambda, $scheme) = @_;
    
#### Scheme

`$scheme` is a hash that contains the relevant subroutines for the problem you
are working on. The following keys will return subroutines, if they exist for the problem:  

    $scheme->{CTXT}  
    $scheme->{EAVESDROP}  
    $scheme->{QUERY}  
    $scheme->{LOOKUP}  

#### Return value
The attacking function will return a string to indicated its guess
for distinguishing the actual libraries. The guesses are:  
'left' for the Left library in a left vs right attack  
'right' for the Right library in a left vs right attack  
'random' for the random library in a real vs random attack  
'real' for the real library in a real vs random attack
