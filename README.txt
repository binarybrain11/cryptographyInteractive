This repository is an interactive companion to Mike Rosulek's "The Joy of Cryptography".
You can find implementations of the insecure libraries described in the book 
to test an actual implementation of your attack. 

Each library will contain a few security definitions that implement the specific encrytpion 
scheme and can be attacked through a few set interfaces. In general, a security definition 
sdf that implements the encryption scheme ens has the following interfaces:

ensSdfAttack(attackFun):
This interface will run the attacking program once and check for correctness.
Often a security definition is attacked by distinguishing between left and right 
or real and random, so calling this interface will select one implementation at 
random, for example left or real, and see if your attacking program can correctly 
distinguish between them. It will then return a true or a false to indicate 
if the attacking program succeeded.

ensSdfAdvantage(trials, attackFun):
This interface will basically call sdfAttack() trials times to compute an 
advantage which will be returned as a decimal value. Sometimes an attacking 
program has a significant advantage but occaisonally fails, so running many 
trials to see if the attacker distinguishes correctly gives a more accurate 
depiction of the attacker's capability. 

For example, suppose we want to attack the one time secrecy of one time pad, 
then we could call otpOtsAttack(). The size and trials are parameters so 
users can fine tune runtime and precision to their attacking program's needs. 
The way the parameters are passed are language specific, see the README in the 
corresponding folders.

The attacking function shall accept a security definition 
object and return a value indicating the attack's guess. Again, see the README 
for your particular language for specific syntax.  This object has members or 
methods that are defined for that security defnition, for example one time 
secrecy has an EAVESDROP() method, so attacking functions passed to otpOtsAttack() 
will be given an object that has an EAVESDROP() method.  The following methods should 
be implemented for each security defnition:

One Time Secrecy (Ots) and Chosen Plaintext Attack (Cpa):
EAVESDROP(mL, mR):
This function will either encrypt mL or mR and return the ciphertext. 

CTXT(m):
This function will either encrypt m and return the ciphertext or will return 
random bits. 

Secret Sharing Scheme (Sss):
SHARE(mL, mR, U):
This function will store how ever many shares specified by the scheme into U.
It is up to the caller to make sure there is enough room in U when attacking 
the given scheme. While it could be possible to attack Sss with an overflow 
on U, this would be an attack on the implementation and not the scheme which 
we advise against, not to mention it's likely a more difficult attack.

PsudeoRandom number Generators (Prg):
QUERY():
This function returns a psudeorandom number based on the implementation. 

PsudeoRandom Function (Prf):
LOOKUP(x):
This function returns a psudeorandom number generated from the function 
specified by the scheme. 
Developer's Note: Prf's require a running lookup table and key. The table 
and key should be created at the beginning of an attack and destroyed at 
the end of an attack. This could require launching a new thread to keep 
the table and key in scope so that an attacking program can call LOOKUP() 
many times. 

PsudeoRandom Permutation (Prp):
LOOKUP(x):
This function returns a psudeorandom number generated from the permutation 
function specified by the scheme and is invertable by INVERSE(). For 
example, INVERSE(LOOKUP(x)) == x. 

INVERSE(y):
This function returns a psudeorandom number generated from the permutation 
function specified by the scheme and is invertable by LOOKUP(). For 
example, LOOKUP(INVERSE(y)) == y. 
Developer's Note: Prp's require a running lookup table and key just like a Prf. 

Chosen Ciphertext Attack (Cca):
EAVESDROP(mL, mR):
This function will either encrypt mL or mR and return the ciphertext. 

DECRYPT(c):
This function will decrypt c and return the plaintext m. 
Developer's Note: Similar to Prf's and Prp's, Cca's need to keep a running 
lookup table and key. 

Block Ciphers:
Some of the chapters discuss block ciphers. In this case, functions have 
an extra parameter blocks that describes the number of blocks of size bytes
that are in the message or ciphertext parameters. EAVESDROP() is a function 
that has two message parameters, in this case blocks describes both parameters 
since there is a trivial attack on EAVESDROP() when the messages differ in 
length.

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
