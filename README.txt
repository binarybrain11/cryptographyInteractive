This repository is an interactive companion to Mike Rosulek's "The Joy of Cryptography".
You can find implementations of the insecure libraries described in the book 
to test an actual implementation of your attack. 

Each library will contain a few security definitions that implement the specific encrytpion 
scheme and can be attacked through a few set interfaces. In general, a security definition 
sdf that implements the encryption scheme ens has the following interfaces:

ensSdfDistinguish(attackFun):
This interface will run the attacking program once and check for correctness.
Often a security definition is attacked by distinguishing between left and right 
or real and random, so calling this interface will select one implementation at 
random, for example left or real, and see if your attacking program can correctly 
distinguish between them. It will then return a true or a false to indicate 
if the attacking program succeeded.

Advantage(trials, attackFun, distinguisher):
This interface will basically call distinguisher() trials times to compute an 
advantage which will be returned as a decimal value. Sometimes an attacking 
program has a significant advantage but occaisonally fails, so running many 
trials to see if the attacker distinguishes correctly gives a more accurate 
depiction of the attacker's capability. Capability is measured from 0 to 1, 
with 0.5 indicating the attack wasn't able to distinguish better than 
random, 1 indicating the attack was able to distinguish correctly every time,
and 0 indicating the attack was able to distinguish incorrectly every time 
(consider flipping your output if you read a 0). 

For example, suppose we want to attack the one time secrecy of section example 2.3, 
then we could call se2_3OtsDistinguish(). The size and trials are parameters so 
users can fine tune runtime and precision to their attacking program's needs. 
The way the parameters are passed are language specific, see the README in the 
corresponding folders.

The attacking function shall accept a security definition 
object and return a value indicating the attack's guess. Again, see the README 
for your particular language for specific syntax.  This object has members or 
methods that are defined for that security defnition, for example one time 
secrecy has an EAVESDROP() method, so attacking functions passed to se2_3OtsDistinguish() 
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
the end of an attack. 

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

CTXT(m):
This function will either encrypt m and return the ciphertext or will return 
random bits. 

DECRYPT(c):
This function will decrypt c and return the plaintext m. 
Developer's Note: Similar to Prf's and Prp's, Cca's need to keep a running 
lookup table and key. 

From this overview, check out the README for each language to see what chapters 
and problems were successfully implemented. The schemes are labelled with 
source, chapter, followed by number. For example, the chapter 5 homework 
problem 1a is labelled as: hw5_1a and a call to attack on that homework problem 
would be hw5_1aPrgDistinguish(). Problems can come from homework (hw), section examples 
(se), and exercises (ex). Since example attacks don't have clear numbers, we'll use 
the section number that the example appears in.  There should also be an example 
solution in each language to demonstrate how an attacking program is constructed 
and called, probably the example in chapter 2 section 3, or ex2_3OtsDistinguish().
