This repository is an interactive companion to Mike Rosulek's "The Joy of Cryptography".
You can find implementations of the insecure libraries described in the book 
to test an actual implementation of your attack. 

Each library will contain a few security definitions that implement the specific encrytpion 
scheme and can be attacked through a few set interfaces. In general, a security definition 
sdf that implements the encryption scheme ens has the following interfaces:

ensSdfAttack(size, attackFun):
This interface will run the attacking program once and check for correctness.
Often a security definition is attacked by distinguishing between left and right 
or real and random, so calling this interface will select one implementation at 
random, for example left or real, and see if your attacking program can correctly 
distinguish between them. 

ensSdfAdvantage(size, trials, attackFun):
This interface will basically call sdfAttack() trials times to compute an 
advantage. Sometimes an attacking program has a significant advantage but 
occaisonally fails, so running many trials to see if the attacker distinguishes 
correctly gives a more accurate depiction of the attacker's capability. 

For example, suppose we want to attack the one time secrecy of one time pad, 
then we could call otpOtsAttack(). The size and trials are parameters so 
users can fine tune runtime and precision to their attacking program's needs. 
The way the parameters are passed are language specific, see the README in the 
corresponding folders.

The attacking function shall accept a size parameter and a security definition 
object. Again, see the README for your particular language for specific syntax. 
This object has members or methods that are defined for that security defnition,
for example one time secrecy has an EAVESDROP() method, so attacking functions 
passed to otpOtsAttack() will be given an object that has an EAVESDROP() method.
The following methods should be implemented for each security defnition:

One time secrecy (ots):
EAVESDROP(size, mL, mR):
This function will either encrypt mL or mR and return the ciphertext. 

CTXT(size, m):
This function will either encrypt m and return the ciphertext or will return 
random bits. 
