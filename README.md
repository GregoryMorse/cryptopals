# cryptopals
Cryptopals challenges 1 to 7 completed solutions in C#

1.1)	 Convert hex to base64
Hex representation from 0-9, A-F and each byte 0-255 taking a hex value 00-FF, generally in big-endian byte order but sometimes when data in numeric units can be in little-endian format where the bytes in a chunk are reversed in order.  Base64 uses A-Z, a-z, 0-9 and ‘+’ and ‘/’ and either 0, 1 or 2 ‘=’ at the end to pad it to the nearest 3 bytes.  It does this by taking the bits as a continuous stream of bits looking at 6 bits at a time so that it looks at 6 bits of the first byte, the last 2 bits and next 4 bits of the next byte, the last 4 bits of that byte and next 2 of the byte after that, and finally the last 6 bits of the 4th byte.  These 6 bits are an index into the A-Z, a-z, 0-9, ‘+’, ‘/’ values which are 26+26+10+2=2^6=64 values.
1.2)	 Fixed XOR
XOR has truth table such that 0^0=0, 0^1=1, 1^0=1, 1^1=0 or linguistically “a or b but not both a and b” hence the exclusiveness of the or.  Note also a^0=a and a^1=!a.  This can be done on any sequence of bytes of same length on a bit by bit basis.
1.3)	 Single-byte XOR cipher
If text to decipher is language text, take language letter frequency data such as in English a-z (or A-Z):
.082, .015, .028, .043, .127, .022, .020, .061, .070, .002, .008, .040, .024,
.067, .075, .019, .001, .060, .063, .091, .028, .010, .023, .001, .020, .001
‘RSTLNE’ are famously known for being most frequent.  For each possible byte XOR value from 00-FF, score a value of these frequencies times 100 for each byte in the message and then take the highest sum, using optionally a value such as .3 for space which is frequent as well (and any other anticipated special or punctuation characters).  This is a histogram like problem using statistical frequency.  Then one can XOR with the highest frequency value to recover the plaintext.
1.4)	 Detect single-character XOR 
To detect which line had single-character XOR on many lines of data, take the best frequency score for each XOR byte as done in the previous single-byte XOR problem and hold onto the score and XOR byte value.  Then take the line which was maximum score and use its XOR byte to decrypt only that line.
1.5)	 Implement repeating-key XOR 
A repeating-key XOR is just repeating the key over and over against any arbitrary length message.
1.6)	 Break repeating-key XOR 
Using the hamming distance: number of differing bits between two values, one can compute the hamming distance between different key sizes from 2 to 39 bytes and see which has the smallest hamming edit distance between them.  This smallest one is likely the key size.  Now every 1st byte of key size bytes can be evaluated as a single-byte XOR as per previous problem, so can the 2nd byte, etc until the whole key is decoded and then the plaintext can be recovered.
1.7)	 AES in ECB mode 
Decrypting AES (Advaned Encryption Standard) in ECB (Electronic Codebook) mode is as simple as passing the key and ciphertext into a library supporting it.  Having a working AES ECB mode implementation can be reused for many other purposes such as the other AES modes.
1.8)	 Detect AES in ECB mode
One way to detect AES in ECB mode is to look for 2 identical 16-byte blocks which is the case in this scenario.  AES in ECB always produced the same output for identical blocks.  The repeating-key XOR idea of using hamming weight may also show that the 16-byte blocks are closer to each other than with other encrypted texts.
2.9) Implement PKCS#7 padding
A basic padding strategy which finds out by remainder division with 16 the number of bytes necessary to make the message a multiple of 16 bytes.  It will add 1 hex 0x01 or 16 hex 0x16 to the end to enforce this, actually adding a whole block of padding in the 16 case so that we can be sure the message was padding deterministically.  This is an important point that the algorithm is totally deterministic for adding and removing padding because of how it handles the even 16-byte block size.
2.10) Implement CBC mode
AES CBC mode encryption/decryption can be implemented using a byte XOR of the IV or previous block, and then the AES ECB cipher to encrypt or vice versa for decrypting.  
2.11) An ECB/CBC detection oracle
Even when prepending and appending a small amount of data to messages, ECB mode can be distinguished from CBC mode by looking for repeated blocks as was done before.
2.12) Byte-at-a-time ECB decryption (Simple)
Given your data followed by some unknown data with an unknown key and an oracle function which will return the AES ECB encrypted value, we do the following:
First, pass no data to get the length of output.  Then pass one byte, two bytes, etc until the output length changes.  Subtracting from initial output length gets the block length.  The unknown message length is the final output length minus the number of bytes that were used to change the length.
In this case it is the typical 16 byte blocks.  Gather a set of data which is bigger than the unknown message.  Now build a dictionary with all last block values for any fixed 15 bytes plus the 00-FF values of the 16th byte.  Now call the oracle with only 15 bytes.  The 16th byte of this output block is the first byte of the unknown block and thus is found by looking in the dictionary for a match.  Now repeat this process with a clean dictionary and last block of 14 bytes plus the 15th recovered byte from previously and the 00-FF values for the 16th byte.  Now call the oracle with only last block of 14 bytes.  The 16th byte is the second byte of the unknown block found by looking in the dictionary.  Repeat this process until all bytes are recovered.  There is no problem with transference to the shorter blocks as when all 16 bytes are recovered in one block we start with the last block of 15 bytes and the 00-FF values.
2.13) ECB cut-and-paste
Given an ECB encrypted text which is padded, one can still cut and paste full blocks on other ECB encrypted chunks as long as the last block is always spliced with a properly padded one.  So if we have a user profile with “role=user” and we have another user profile for “role=admin”.  There will be a way to splice one message for the other.  So the key to this challenge was first to realize another user needs to be created since only the profile_for function is allowed to be called and as well we must know the email of one admin role account.  Let us say admin@bar.com exists in addition to the example given foo@bar.com.  Now we can query for admin@bar.com which has “role=admin” and we can assume that the stuff before the role is email and userid so we can take the length of “email=foo@bar.com&uid=10&” bytes rounded up to the nearest block from the beginning of the encrypted profile string, and then splice on the last blocks of the admin@bar.com profile without the first blocks of bytes which are in the same string “email=foo@bar.com&uid=10&” but this time rounded down.  Then we get a resulting string which is “email=foo@bar.com&uid=10&role=uscom&uid=11&role=admin” and very likely will get by the parsing with the final values of a corrupted role and user id.
2.14) Byte-at-a-time ECB decryption (Harder)
Similar to the problem from 2.12, this problem now requires analysis of a random prefix.  There may be multiple methods to solve this.  Finding the block size is identical to the previous problem.  Finding the byte by byte unknown value is the same as the previous problem.
The only difference is that now we must find which block and where inside the block to begin which will be some value between 0 and 16 because the random prefix makes it harder for us to accurately start at the 15th character and generating the 16th character is a dictionary and so forth as proceeding.  As well not knowing which block means we do not already know which block of output to look at (though it is the only one that would vary).
A solution is to send 3 blocks of identical data.
With 2 blocks of identical data, if they are evenly aligned and the random prefix was a multiple of the key size, we would have 2 identical blocks, otherwise we would not.
But with 3 blocks of identical data, there will be minimum 2 and possibly 3 blocks of identical data in the output.  To find the starting block, we simply find these 2 identical blocks of data.  To find where to start in the block, simply keep comparing the prior block to our identical 2 blocks with 0 bytes of the original user data, then 1 byte, etc until the prior block is identical so we see how many bytes of data spilled into it.  Now with the number of prior blocks, and the position within the block, we can proceed with the attack as before being careful to add and subtract values properly.
2.15) PKCS#7 padding validation
PKCS#7 validation can be done by looking at the last byte and making sure there are that many of that byte in the final positions so if it is 01 then it is good, if it is 02 then make sure the last bytes are 02, 02 and if its 16, make sure there are 16 16’s for the last bytes.  Otherwise throw an error which can be caught.  This sets up for padding oracle attacks.
2.16) CBC bitflipping attacks
In this attack, we use the property of CBC that an edit can be made by corrupting one block so that the next block is just a fixed byte XOR with the string we want to replace with.  So we get a valid cipher string based on some random user data we passed in then do this: <2 blocks of encrypted output> + <the 2nd block of our userdata XOR the 3rd block of encrypted output XOR the one blockstring “;admin=true;    ”) + <the encrypted output after the first 3 blocks>.  The precise XOR modification involving the previous block of userdata, the block of output data, and the target edit string is the key here.
3.17) The CBC padding oracle
By knowing whether a CBC mode message has valid PKCS7 padding, one byte at a time at the end of the message, one can try all values 00-FF XORed with the byte until one determines the original padding bytes and the previous bytes in that block.  This process is then repeated by stripping the last block recovered and beginning with the new block looking for a value that when XORed with makes a 01 padding then 02, 02, and so forth.  When a XOR value is found, then to recover the original plaintext, one just XORs with what we know the padding to be at that stage from 01 to 16.
Problem on very last byte: 2 values could have good padding for example 01 and the original padding value.  Simple solution: search from FF to 00 so that the larger value would be found first which would be correct.
Note: The IV would be recovered though it is known in this case when the first block is decrypted by a simple XOR with the first output block and first plaintext recovered block.
3.18) Implement CTR, the stream cipher mode
CTR mode is implemented by using a counter and a value called nonce similar to the IV.  CTR makes an XOR keystream by encrypting the fixed nonce value concatenated with the IV and XORing this with the value to encrypt/decrypt.  Padding is not required and the encryption and decryption functions are identical.  Typically the nonce and counter would be 8 byte integers to make best use of AES.  AES ECB cipher can again be reused to implement this.
3.19) Break fixed-nonce CTR mode using substitutions
This is the same as breaking the repeating key XOR problems in the first set.  However the strings are of different lengths and the end of the strings thus can have only a few other strings with the same length which is not sufficient for a frequency analysis.  Statistical analysis only works when enough data flows through to make it probable these frequent patterns emerge.
In this case a further analysis needs to be done, namely trigraphs which are triplet combinations of letters in a language.
3.20) Break fixed-nonce CTR statistically
Same as the last problem though the last one they encouraged to do letter by letter looking at the output not programmatically.  They also mention truncations which again is not elegant like using trigraphs or extra frequency information to solve this – bigraphs, trigraphs, frequencies at beginnings of words, frequencies at end of words, frequencies in the middle of the word, frequency of punctuation and special characters, etc.  This data can be found including a large database done based on famous and public domain books by Google.
3.21) Implement the MT19937 Mersenne Twister RNG
The Mersenne Twister is a pseudorandom number generator (PRNG). It is by far the most widely used general-purpose PRNG.[1] Its name derives from the fact that its period length is chosen to be a Mersenne prime.
The Mersenne Twister was developed in 1997 by Makoto Matsumoto (ja) (松本 眞?) and Takuji Nishimura (西村 拓士?).[2] It was designed specifically to rectify most of the flaws found in older PRNGs. It was the first PRNG to provide fast generation of high-quality pseudorandom integers.
The most commonly used version of the Mersenne Twister algorithm is based on the Mersenne prime 219937−1. The standard implementation of that, MT19937, uses a 32-bit word length. There is another implementation that uses a 64-bit word length, MT19937-64; it generates a different sequence.
The Mersenne Twister algorithm is based on a matrix linear recurrence over a finite binary field F2. The algorithm is a twisted generalised feedback shift register[45] (twisted GFSR, or TGFSR) of rational normal form (TGFSR(R)), with state bit reflection and tempering. The basic idea is to define a series  through a simple recurrence relation, and then output numbers of the form  , where  is an invertible F2 matrix called a tempering matrix.
Pseudocode from Wikipedia:
// Create a length n array to store the state of the generator
 int[0..n-1] MT
 int index := n+1
 const int lower_mask = (1 << r) - 1 // That is, the binary number of r 1's
 const int upper_mask = lowest w bits of (not lower_mask)
 
 // Initialize the generator from a seed
 function seed_mt(int seed) {
     index := n
     MT[0] := seed
     for i from 1 to (n - 1) { // loop over each element
         MT[i] := lowest w bits of (f * (MT[i-1] xor (MT[i-1] >> (w-2))) + i)
     }
 }
 
 // Extract a tempered value based on MT[index]
 // calling twist() every n numbers
 function extract_number() {
     if index >= n {
         if index > n {
           error "Generator was never seeded"
           // Alternatively, seed with constant value; 5489 is used in reference C code[48]
         }
         twist()
     }
 
     int y := MT[index]
     y := y xor ((y >> u) and d)
     y := y xor ((y << s) and b)
     y := y xor ((y << t) and c)
     y := y xor (y >> l)
 
     index := index + 1
     return lowest w bits of (y)
 }
 
 // Generate the next n values from the series x_i 
 function twist() {
     for i from 0 to (n-1) {
         int x := (MT[i] and upper_mask)
                   + (MT[(i+1) mod n] and lower_mask)
         int xA := x >> 1
         if (x mod 2) != 0 { // lowest bit of x is 1
             xA := xA xor a
         }
         MT[i] := MT[(i + m) mod n] xor xA
     }
     index := 0
 }

3.22) Crack an MT19937 seed
By seeding the random number generator with the time, then waiting some random amount of time in seconds, then returning another random number, the original seed can be discovered.  As seen in the above, seed_mt() routine writes the seed to the first value of the array.  So if we see a random number generated and we know it is seeded on time which was not long ago, we can keep seeding the random number generator with the current time minus increasing values until the first random output is the one we are looking for.  It is a sort of brute-force backwards time search.
3.23) Clone an MT19937 RNG from its output
By unextracting all 624 values from the Mersenne Twister generator, then splicing these values into a Mersenne Twister generator, we can have the same internal state.  It requires an unextraction and splicing function where the splicing function does nothing but copy the array.  The unextraction code on the other hand uses the following C/C#/java/pseudo-code which reverses the extract_number function above because it is invertible until the twist operation occurs hence 624 operations are invertible.
        public uint Unextract(uint value) //untemper
        {
            value = value ^ value >> 18; //inverse of x ^ (x >> 18)
            value = value ^ ((value & 0x1DF8Cu) << 15); //inverse of ((x & 0xFFFFDF8C) << 15) ^ x = (x << 15) & 0xEFC60000 ^ x
            uint t = value; //inverse of ((x & 0xFF3A58AD) << 7) ^ x = ((x << 7) & 0x9D2C5680) ^ x
            t =     ((t & 0x0000002D) << 7) ^ value; //7 bits
            t =     ((t & 0x000018AD) << 7) ^ value; //14 bits
            t =     ((t & 0x001A58AD) << 7) ^ value; //21 bits
            value = ((t & 0x013A58AD) << 7) ^ value; //32-7 bits
            //inverse of x ^ x >> 11
            uint top = value & 0xFFE00000;
            uint mid = value & 0x001FFC00;
            uint low = value & 0x000003ff;
            return top | ((top >> 11) ^ mid) | ((((top >> 11) ^ mid) >> 11) ^ low);
        }
3.24) Create the MT19937 stream cipher and break it
If MT is used as a keystream by pulling 4 byte values out and converting them to byte arrays which can be XORed with the plaintext creating cipher text, and it is seeded with a 16 bit value.  Then one can simple brute force the seed by trying all values from 0 to 2^16 until seeding the MT yields the same cipher text as the one in question.
The random password reset token is really identical to the 3.22 challenge as it is just brute forcing the current time minus an increasing value which makes a password token instead of what was an arbitrary value in that task without an intended use.
4.25) Break "random access read/write" AES CTR
If one has access to an edit function for CTR mode which can simply use the counter to calculate a keystream and edit a certain part – the whole plaintext can be recovered by simply XORing the original cipher text with the output of editing from 0 to the length of the text with all 0’s.  This could be generalized so you XOR the original cipher text with some arbitrary data the same length, and the output of editing from 0 to the length of the text with that same arbitrary data.  0 is often used to make a double XOR simplification out of a triple XOR.  But the triple XOR is useful to be as general as possible.
4.26) CTR bitflipping
Nearly identical to 2.16 where CBC was used to corrupt one block to inject arbitrary data into the next.
Here is the precise XOR modification: <2 blocks of encrypted output> + <the 1st block of our userdata XOR the 3rd block of encrypted output XOR the one blockstring “;admin=true;    ”) + <the encrypted output after the first 3 blocks>.  Notice the only change here is that we use the 1st block of our userdata now the 2nd block since in CBC mode the XOR value chains to the next round where in CTR mode it does not.
4.27) Recover the key from CBC with IV=Key
If the IV and Key are identical in CBC, then given AES-CBC(P_1, P_2, P_3) -> C_1, C_2, C_3, an attacker in the middle can send it as C_1, C_2, C_3 -> C_1, 0, C_1 whereby the server if it returns a value then it gives the IV which is the key based on P'_1 XOR P'_3.  This could be generalized as well to not use 0 but to use any value which would require a triple XOR for the IV/Key.
4.28) Implement a SHA-1 keyed MAC
SHA1 implementation pseudocode:
Note 1: All variables are unsigned 32-bit quantities and wrap modulo 232 when calculating, except for
        ml, the message length, which is a 64-bit quantity, and
        hh, the message digest, which is a 160-bit quantity.
Note 2: All constants in this pseudo code are in big endian.
        Within each word, the most significant byte is stored in the leftmost byte position

Initialize variables:

h0 = 0x67452301
h1 = 0xEFCDAB89
h2 = 0x98BADCFE
h3 = 0x10325476
h4 = 0xC3D2E1F0

ml = message length in bits (always a multiple of the number of bits in a character).

Pre-processing:
append the bit '1' to the message e.g. by adding 0x80 if message length is a multiple of 8 bits.
append 0 ≤ k < 512 bits '0', such that the resulting message length in bits
   is congruent to −64 ≡ 448 (mod 512)
append ml, the original message length, as a 64-bit big-endian integer. Thus, the total length is a multiple of 512 bits.

Process the message in successive 512-bit chunks:
break message into 512-bit chunks
for each chunk
    break chunk into sixteen 32-bit big-endian words w[i], 0 ≤ i ≤ 15

    Extend the sixteen 32-bit words into eighty 32-bit words:
    for i from 16 to 79
        w[i] = (w[i-3] xor w[i-8] xor w[i-14] xor w[i-16]) leftrotate 1

    Initialize hash value for this chunk:
    a = h0
    b = h1
    c = h2
    d = h3
    e = h4

    Main loop:[2][48]
    for i from 0 to 79
        if 0 ≤ i ≤ 19 then
            f = (b and c) or ((not b) and d)
            k = 0x5A827999
        else if 20 ≤ i ≤ 39
            f = b xor c xor d
            k = 0x6ED9EBA1
        else if 40 ≤ i ≤ 59
            f = (b and c) or (b and d) or (c and d) 
            k = 0x8F1BBCDC
        else if 60 ≤ i ≤ 79
            f = b xor c xor d
            k = 0xCA62C1D6

        temp = (a leftrotate 5) + f + e + k + w[i]
        e = d
        d = c
        c = b leftrotate 30
        b = a
        a = temp

    Add this chunk's hash to result so far:
    h0 = h0 + a
    h1 = h1 + b 
    h2 = h2 + c
    h3 = h3 + d
    h4 = h4 + e

Produce the final hash value (big-endian) as a 160 bit number:
hh = (h0 leftshift 128) or (h1 leftshift 96) or (h2 leftshift 64) or (h3 leftshift 32) or h4

MAC with SHA-1 is simply prepending the key and calling SHA1(key || message) and changing the message will change the MAC.
4.29) Break a SHA-1 keyed MAC using length extension
Takes advantage of the fact that SHA1 breaks the message into 64 byte blocks and the intermediate hash state is the output hash state though a length counter is important and must be simulated.  A new message with a new MAC will still have the same key by this length extension since the key is merely a prefix.
SHA1(SHA1Reset(), key || original-message || glue-padding || new-message) = SHA1(SHA1ResetFromHashLen(SHA1(key || original-message || glue-padding), block-count), new-message)
In other words, when SHA1Reset sets the algorithm defaults including a 0 length, we can initialize the context structure to have its intermediate hash as the previous SHA1 hash, and its block length equal to the prior block length.  Then by simply SHA1 more data it simulates the way SHA1 works anyway taking more blocks and hashing them onto the last state in a chaining manner.  The output will preserve the key prefix that was used and hence the forgery will look authentic.  In the example the length is 2 since the data is 77 bytes which is over 64 bytes for a single block.
4.30) Break an MD4 keyed MAC using length extension
MD4 works identical to SHA1 using intermediate hash states and a length.  It can be broken in an identical way with a length extension attack which makes it look like a new message with a new MAC by length extensioning.
MD4 algorithm from RFC1320:
        F(X,Y,Z) = XY v not(X) Z
        G(X,Y,Z) = XY v XZ v YZ
        H(X,Y,Z) = X xor Y xor Z
      Process each 16-word block. */
      For i = 0 to N/16-1 do

        /* Copy block i into X. */
        For j = 0 to 15 do
          Set X[j] to M[i*16+j].
        end /* of loop on j */

        /* Save A as AA, B as BB, C as CC, and D as DD. */
        AA = A
        BB = B
        CC = C
        DD = D

        /* Round 1. */
        /* Let [abcd k s] denote the operation
             a = (a + F(b,c,d) + X[k]) <<< s. */
        /* Do the following 16 operations. */
        [ABCD  0  3]  [DABC  1  7]  [CDAB  2 11]  [BCDA  3 19]
        [ABCD  4  3]  [DABC  5  7]  [CDAB  6 11]  [BCDA  7 19]
        [ABCD  8  3]  [DABC  9  7]  [CDAB 10 11]  [BCDA 11 19]
        [ABCD 12  3]  [DABC 13  7]  [CDAB 14 11]  [BCDA 15 19]

        /* Round 2. */
        /* Let [abcd k s] denote the operation
             a = (a + G(b,c,d) + X[k] + 5A827999) <<< s. */
        /* Do the following 16 operations. */
        [ABCD  0  3]  [DABC  4  5]  [CDAB  8  9]  [BCDA 12 13]
        [ABCD  1  3]  [DABC  5  5]  [CDAB  9  9]  [BCDA 13 13]
        [ABCD  2  3]  [DABC  6  5]  [CDAB 10  9]  [BCDA 14 13]
        [ABCD  3  3]  [DABC  7  5]  [CDAB 11  9]  [BCDA 15 13]

        /* Round 3. */
        /* Let [abcd k s] denote the operation
             a = (a + H(b,c,d) + X[k] + 6ED9EBA1) <<< s. */
        /* Do the following 16 operations. */
        [ABCD  0  3]  [DABC  8  9]  [CDAB  4 11]  [BCDA 12 15]
        [ABCD  2  3]  [DABC 10  9]  [CDAB  6 11]  [BCDA 14 15]
        [ABCD  1  3]  [DABC  9  9]  [CDAB  5 11]  [BCDA 13 15]
        [ABCD  3  3]  [DABC 11  9]  [CDAB  7 11]  [BCDA 15 15]

        /* Then perform the following additions. (That is, increment each
           of the four registers by the value it had before this block
           was started.) */
        A = A + AA
        B = B + BB
        C = C + CC
        D = D + DD

      end /* of loop on i */
The message digest produced as output is A, B, C, D
4.31) Implement and break HMAC-SHA1 with an artificial timing leak
By measuring the time of calls to the verification of an HMAC-SHA1 where the comparison will exit after the first non-match, one can look for the longest time after sending all bytes 00-FF for the first byte, then when that is discovered fix it in place and try 2nd byte, etc.  Eventually the MAC will be discovered after 20 of these steps.  It works fine with 50ms delays which is a bit unrealistic.
4.32) Break HMAC-SHA1 with a slightly less artificial timing leak
With a less artificial timing leak, a precise stop watch which is accurate to clock cycles or ticks must be employed.  Then a certain number of rounds such as 5 rounds with a 5ms delay in the compare function will also break this by taking the time to do 5 rounds instead of 1 call as before.  5 calls will amplify the error to a reasonable value which can be measured or detected.  Generally a sleep call can only be reduced to 1ms but eventually more precision than task-switching and the environment provides would make this infeasible.
5.33) Implement Diffie-Hellman
A strategy to implement cryptography protocols where interaction is going on and a middle device which can relay or see in Object Oriented Programming languages is to use a class for a Participant and another class for the ManInTheMiddle.
Another note that most default BigInteger libraries will treat values as signed if starting with a byte that is greater than 0x80 unless a 0x00 is prefixed.  Then on the other side, the 0x00 when reading the bytes out of the BigInteger must be stripped.  Also, some BigInteger libraries expect bytes in Big Endian order which is the normal way cryptographic data is viewed but others treat them as numbers in little Endian order which requires a byte reversal.  Also, some BigInteger libraries do not process mod or remainder operations with positive numbers and custom routines and care must be taken to make them positive.
Modular exponentiation is mostly provided by BigInteger libraries otherwise an algorithm which can do it efficiently with squaring should be employed.  Here is an example of the algorithm in C#:
        BigInteger modPow(BigInteger b, BigInteger e, BigInteger m)
        {
            BigInteger result = 1;
            while (e != 0) {
                if (!e.IsEven) result = (result * b) % m;
                e /= 2;
                b = (b ^ 2) % m;
            }
            return result;
        }
DH requires Alice to choose a from p number field, calculate A=g^a mod p, then A is sent to Bob then Bob chooses b from p number field, calculates B=g^b mod p, then B is sent to Alice and both calculate s=B^a=A^b=g^ab mod p.  This s value is to be a shared secret for symmetric cryptography.
5.34) Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection
Now the parameters are sent as part of the protocol.  Alice sends Bob: p, g, A.  Bob sends Alice: B.  Alice sends Bob: AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv, Bob sends Alice: AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv.
With a MITM actively attacking, this is modified:
Alice sends MITM: p, g, A.  MITM sends Bob: p, g, p.  Bob sends MITM: B.  MITM sends Alice: p.  The AES-CBC messages are now relayed.
By the MITM using p as both the public exponents, p^a=p^b=p mod p=0.  So the key for the AES-CBC is the SHA1 hash of 0 by relaying a bad A or B value of p which causes all calculations in the number field to violate assumptions that should have been checked by clients.  So the MITM can relay the messages while decrypting all of them.
5.35) Implement DH with negotiated groups, and break with malicious "g" parameters
Same as the last one but in this case the p, g are sent followed by an acknowledgement then the DH protocol.  We only thus need analyze what secret to use with each and how to make sure that Alice and Bob have the same secret.  Bob’s g has been poisoned so:
    g = 1, 1^b mod p=1 so B=1.  So Alice will always generate shared secret 1^a=1.  To make Bob always generate this, we also must forge A so that Bob receives it as A=1 and hence 1^b=1 and then all messages can be relayed and decrypted with shared secret 1.
    g = p, p^b mod p=0 so B=0.  So Alice will always generate shared secret 0^a=0.  To make Bob always generate this, we must also forge A so that Bob receives it as A=0 or A=p and hence 0^b=0 and then all messages can be relayed and decrypted with shared secret 0.
    g = p – 1, (p-1)^b mod p=1, p-1 so B=1 or p-1.  This is a problem because we must make sure Alice and Bob have the same shared secret.  But we must forge A before we know B.  So Alice based on B will always generate shared secret 1^a=1 or (p-1)^a=1 or p-1.  75% chance that indeed 1 will work if we forge A=1.  If we forge A=p-1, then it’s a 50% chance that it will work and more modifications of B would be needed so it is minimal to forge A=1 and Bob’s shared secret will thus always be 1.  So we must determine how to correct the 25% of cases where Alice has a shared secret of p-1 and the messages sent with 2 different shared secrets occur.  Can merely check the PKCS7 padding trying the default of shared secret of 1 for the majority of cases then if it fails, it is p-1.  In this case, we must also not only decrypt the message but re-encrypt the message before resending it and it must be done in both directions.  If it fails when Alice sends Bob a message, we swap the shared secret and key with the newly calculated one and vice-versa so that in the case that we guessed correctly, we still forward the correct message from and to both, and if they both chose 1, then nothing would be done except the usual forwarding.  Hence in the first 2 cases, 2 modifications are needed to g and A.  In the third case, 25% of the time we must also modify messages in both directions or B to be 1.  But modifying B defeats the purpose of modifying g altogether like proposed in the previous problem hence it is not done for this exercise.
5.36) Implement Secure Remote Password (SRP)
DH can be used to implement a salted password authentication by taking hashes of passwords which are mixed with the DH parameters in this 2 round manner:
Client sends: email, A=g**a % N
Server sends: generated salt, B=kv + g**b % N (slightly different than normal DH) where x=int(SHA256(salt|password)), v=g**x % N
Client sends: HMAC-SHA256(K, salt) where x=int(SHA256(salt|password)), S = (B - k * g**x)**(a + u * x) % N, K = SHA256(S)
Server sends: "OK" if HMAC-SHA256(K, salt) validates where S = (A * v**u) ** b % N, K = SHA256(S)
5.37) Break SRP with a zero key
With a 0 value for A in the previous protocol or the modules value N or even N^2, then S will always be 0 so the client could calculate the key for HMAC-SHA256(S) as K=SHA256(0) and authenticate regardless of password.  These two steps poisoning the A value as 0, N or N^2 so that it will be 0 after modulo, and then passing 0 as the S value when computing the key for HMAC will break SRP.
5.38) Offline dictionary attack on simplified SRP
The protocol from 5.36 can be simplified so the only changes are what the server sends and what the client calculates on receipt as indicated in bold:
Server sends: generated salt, B = g**b % n (now normal DH key), u = 128 bit random number where x = int(SHA256(salt|password)), v = g**x % n
Client sends: HMAC-SHA256(K, salt) where x = int(SHA256(salt|password)), S = B**(a + ux) % n, K = SHA256(S)
Server sends: "OK" if HMAC-SHA256(K, salt) validates where S = (A * v ** u)**b % n, K = SHA256(S)
So an active MITM posing as the server sees HMAC-SHA256(K, salt) and knows the parameters: now a dictionary attack can be launched using the server verification strategy not the clients (since a is unknown).
Check for matching values of HMAC-SHA256(K, salt) where x = int(SHA256(salt|password)), v = g**x % n, S = (A * v ** u)**b % n, K = SHA256(S).  The MITM knows previously: g, n, A, from protocol and since here it is posing as server knows b, B, salt, u.  If salt is fixed likely to 0, a hash table could be precomputed.  For dictionary attack, the password is varied until a match is found.  As seen, significant computation effort required though if the b and u parameters are chosen as 1 (hence B=g) then S=Av % n which would greatly speed up computation without losing information.
5.39) Implement RSA
RSA parameters: Generate 2 random primes p, q: n=p*q (modulus), et = (p-1)*(q-1) (the Euler "totient"), e=3 (public exponent), d = invmod(e, et) (private exponent).
Your public key is [e, n]. Your private key is [d, n].
To encrypt: c = m**e%n. To decrypt: m = c**d%n
Classic extended Euclid GCD of 1 inverse modulo code in C#/Java:
        //Extended Euclid GCD of 1
        static BigInteger modInverse(BigInteger a, BigInteger n)
        {
            BigInteger i = n, v = 0, d = 1;
            while (a > 0) {
                BigInteger t = i / a, x = a;
                a = i % x;
                i = x;
                x = d;
                d = v - t * x;
                v = x;
            }
            v %= n;
            if (v < 0) v = (v + n) % n;
            return v;
        }
5.40) Implement an E=3 RSA Broadcast attack
RSA encrypting the same plaintext 3 times under 3 different public keys allows efficient recovery:
1)	Capture 3 ciphertexts and their corresponding public keys
2)	Chinese Remainder Theorem application - result =  (c_0 * m_s_0 * invmod(m_s_0, n_0)) +
  (c_1 * m_s_1 * invmod(m_s_1, n_1)) +  (c_2 * m_s_2 * invmod(m_s_2, n_2)) mod N_012
 c_0, c_1, c_2 are the three respective residues mod n_0, n_1, n_2
 m_s_n (for n in 0, 1, 2) are the product of the moduli EXCEPT n_n --- ie, m_s_1 is n_0 * n_2
 N_012 is the product of all three moduli
3)	Integer cube root the prior result.
Integer cube root efficient algorithm from book Hacker’s Delight customized for BigInteger’s in C#/java:
        //from Hacker's Delight
        public static BigInteger icbrt2(BigInteger x)
        {
            BigInteger b;
            BigInteger y2 = 0;
            BigInteger y = 0;
            for (int s = (GetBitSize(x) / 3) * 3; s >= 0; s = s - 3) {
                y2 = 4 * y2;
                y = 2 * y;
                b = (3 * (y2 + y) + 1) * BigInteger.Pow(2, s);
                if (x >= b) {
                    x = x - b;
                    y2 = y2 + 2 * y + 1;
                    y = y + 1;
                }
            }
            return y;
        }
