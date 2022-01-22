# About the application
This application was developed as part of a **training assignment** and provides access to the following functionality:

+ user authorization;
+ new user registration;
+ encrypting text of any length with a given key according to AES standard;
+ decrypting text of any length with a given key according to AES standard;

This implementation of AES cipher works with 128-bit key length, but it is only in encapsulated program mechanisms.
The users can use a key of any length due to the use of digest of key during key processing.

All implementation of the AES standard has been realized according to the official documentation (see the "References" section)



## About AES-128
The Advanced Encryption Standard (AES) is a variant of the Rijndael block cipher. For AES selected  three members of the Rijndael family, each with a block size of 128 bits, but three different key lengths: 128, 192 and 256 bits.
This implementation can receive a key of any length and a text no longer than 4080 characters.
Any unicode characters can be used as characters for key and source text.
Also, the ciphertext contains the length of the source text (because of this, there is a limit on the length of the source text).

### How to use it outside the application
The entire implementation of the algorithm is stored in a single C# [class](https://github.com/Stix-tomsk/AES-Encryption-Application/blob/main/AES128.cs), so you can copy this code and put into your program or include this class in your project and create a class instance.
For example:
```C#
AES128 aes = new AES128();
string inputText  = "your source data";
string key = "your key";

// To encrypt
string ciphertext = aes.encrypt(inputText, key);

// To decrypt
string decryptedText = aes.decrypt(ciphertext, key);
```

## About MD5
The Message Digest 5 (MD5) is 128-bit hash algorithm designed to create message digests of arbitrary length.
MD5 processes an any length string into a fixed length output string of 128 bits.
> The result of this implementation is consistent with the results of other implementations.


### How to use it outside the application
This implementation is just a C# [class](https://github.com/Stix-tomsk/AES-Encryption-Application/blob/main/MD5.cs), so you can follow the same advices as for AES.
An example in case you decide to include the class in your project:
```C#
MD5 md5 = new MD5();
string message  = "your message";
string hash = md5.digest(message);
```
By the way, this is how MD5 is used in the AES encryption process.


## References
The following sources were used to implement this program:

+ official documentation of AES - [FIPS 197] (https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf);
+ description of the MD5 algorithm - [MD5 Wiki] (https://en.wikipedia.org/wiki/MD5);
