# Cryptopals Crypto Challenges — Complete C# Solutions (Sets 1–8, plus unreleased Set 9)

> Full solutions to all **64 challenges** across **Sets 1–8** of the [Cryptopals Crypto Challenges](https://cryptopals.com/), plus the **2 privately distributed Set 9 challenges**, implemented in **C# (.NET Framework 4.7.2)**. Companion Python solutions and [Manim](https://www.manim.community/) visualisation animations are also included.

**Author:** Gregory Morse  
**GitHub:** [GregoryMorse](https://github.com/GregoryMorse)  
**Email:** [gregory.morse@live.com](mailto:gregory.morse@live.com)

---

## Table of Contents

- [About](#about)
- [Project Structure](#project-structure)
- [Building and Running](#building-and-running)
- [Dependencies](#dependencies)
- [Set 1 — Basics](#set-1--basics)
- [Set 2 — Block Crypto](#set-2--block-crypto)
- [Set 3 — Block & Stream Crypto](#set-3--block--stream-crypto)
- [Set 4 — Stream Crypto and Randomness](#set-4--stream-crypto-and-randomness)
- [Set 5 — Diffie-Hellman and Friends](#set-5--diffie-hellman-and-friends)
- [Set 6 — RSA and DSA](#set-6--rsa-and-dsa)
- [Set 7 — Hashes](#set-7--hashes)
- [Set 8 — Abstract Algebra](#set-8--abstract-algebra)
- [Set 9 — Unreleased Challenges](#set-9--unreleased-challenges)

---

## About

The [Cryptopals Crypto Challenges](https://cryptopals.com/) are a set of practical cryptography exercises created by the security team at Cryptography Services (NCC Group / Matasano). They build from basic encoding through to cutting-edge attacks on real-world cryptographic systems. Each solution here is a self-contained, verified C# implementation backed by automated pass/fail assertions against the provided test vectors.

Additional companion files:

- **Python** (`sets.py`, `utility.py`, `1.py`–`9.py`) — independent Python solutions for selected challenges.
- **Manim** (`manim.py`) — mathematical visualisation animations (rendered to `videos/`) illustrating cryptographic concepts.
- **n-gram frequency data** (`english_monograms.txt`, `english_bigrams.txt`, `english_trigrams.txt`, `english_quadgrams.txt`, `english_quintgrams.txt`) — used for statistical frequency analysis attacks in Sets 1 and 3.
- **Challenge data files** (`4.txt`, `6.txt`, `7.txt`, `8.txt`, `10.txt`, `20.txt`, `25.txt`, `44.txt`) — ciphertext inputs from the challenge website.

---

## Project Structure

```
cryptopals/
├── Cryptopals.cs          # All challenge implementations (Challenge1–Challenge66)
├── sets.cs                # Challenge runner, set definitions, and Main entry point
├── Utility.cs             # Shared utility functions (hex encode/decode, XOR, padding, etc.)
├── Cryptopals.csproj      # .NET Framework 4.7.2 project file
├── Cryptopals.sln         # Visual Studio solution file
├── manim.py               # Manim animation scripts for visualisations
├── sets.py / utility.py   # Python companion implementations
├── 1.py – 9.py            # Python per-set solutions
├── english_*.txt          # n-gram frequency tables for statistical attacks
├── 4.txt, 6.txt, …        # Challenge input data files
└── videos/                # Rendered Manim animation output
```

---

## Building and Running

### Prerequisites

- **Visual Studio 2019+** (or MSBuild with .NET Framework 4.7.2 targeting pack)
- **NuGet** package restore (handled automatically by Visual Studio)

### Build

Open `Cryptopals.sln` in Visual Studio and build (`Ctrl+Shift+B`), or from a Developer Command Prompt:

```bash
msbuild Cryptopals.sln /p:Configuration=Release
```

### Run

```bash
bin\Release\Cryptopals.exe
```

Edit the `Main` method in `sets.cs` to select which challenge sets to run (e.g. `RunSet(1, Set1)`).

---

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| [`Security.Cryptography`](https://github.com/MicrosoftArchive/clrsecurity) | 1.7.2 | CLR Security — AES-GCM support |
| [`System.Security.Cryptography.Primitives`](https://www.nuget.org/packages/System.Security.Cryptography.Primitives/) | 4.3.0 | Cryptographic primitive base types |
| `System.Numerics` | (built-in) | `BigInteger` for RSA, DH, and ECC arithmetic |

---

## Set 1 — Basics

> Challenges 1–8. Foundations of encoding, XOR ciphers, and AES.

### 1.1 — Convert Hex to Base64

Hex encodes bytes 0x00–0xFF using characters `0-9, A-F` in big-endian order. Base64 encodes using `A-Z, a-z, 0-9, +, /` with `=` padding to the nearest 3 bytes. The conversion treats the input as a continuous bit stream, reading 6 bits at a time and mapping each group (0–63) to one of the 64 Base64 characters (26+26+10+2 = 2⁶ = 64 values).

### 1.2 — Fixed XOR

XOR truth table: `0^0=0, 0^1=1, 1^0=1, 1^1=0` — "one or the other but not both". Key identities: `a^0=a` and `a^1=~a`. Fixed XOR operates on two equal-length byte arrays bit-by-bit.

### 1.3 — Single-Byte XOR Cipher

To break a single-byte XOR cipher on natural-language text, score each candidate key byte (0x00–0xFF) using English letter frequency data:

```
a–z: .082, .015, .028, .043, .127, .022, .020, .061, .070, .002, .008, .040, .024,
     .067, .075, .019, .001, .060, .063, .091, .028, .010, .023, .001, .020, .001
```

`RSTLNE` are famously the most common letters. Space (≈0.13) and common punctuation are also scored. The key byte that produces the highest frequency score is the correct key. This is a histogram/statistical frequency problem.

### 1.4 — Detect Single-Character XOR

Apply the single-byte XOR scoring from Challenge 1.3 to every line of a multi-line file. Track the best score and corresponding key per line, then take the globally highest-scoring line. Only that line's plaintext is recovered using the best key.

### 1.5 — Implement Repeating-Key XOR

A repeating-key XOR simply tiles the key over and over against an arbitrary-length message, XORing each message byte with the corresponding key byte modulo the key length.

### 1.6 — Break Repeating-Key XOR

Use the **Hamming distance** (number of differing bits) between pairs of consecutive key-sized blocks of ciphertext to determine the key length. The key size with the smallest normalised Hamming distance is the most likely candidate. Then treat every Nth byte (for N = key length) as a single-byte XOR problem, solving each independently to recover the full key.

### 1.7 — AES in ECB Mode

AES (Advanced Encryption Standard) in ECB (Electronic Codebook) mode decrypts by passing the key and ciphertext directly to a standard AES library. ECB processes each 16-byte block independently. The working ECB implementation is reused as a building block throughout all subsequent AES challenges.

### 1.8 — Detect AES in ECB Mode

ECB mode produces identical output blocks for identical input blocks. Detection works by scanning ciphertext for any repeated 16-byte blocks — their presence is a strong indicator of ECB mode. The Hamming distance approach used for repeating-key XOR can also reveal that ECB-encrypted 16-byte blocks are closer to each other than blocks from other ciphers.

---

## Set 2 — Block Crypto

> Challenges 9–16. Padding, CBC mode, and oracle attacks on block ciphers.

### 2.9 — Implement PKCS#7 Padding

PKCS#7 padding extends a message to a multiple of the block size (16 bytes) by appending `n` bytes each with value `n`, where `n = 16 - (len % 16)`. When the message is already block-aligned, a full padding block of sixteen `0x10` bytes is appended. This determinism ensures padding can always be unambiguously added and removed.

### 2.10 — Implement CBC Mode

AES-CBC (Cipher Block Chaining) encrypts by XORing each plaintext block with the previous ciphertext block (or the IV for the first block) before AES-ECB encryption. Decryption reverses this: AES-ECB decrypt each block, then XOR with the previous ciphertext block.

### 2.11 — An ECB/CBC Detection Oracle

Even when a random prefix and suffix are prepended/appended to user-controlled input, ECB mode can be distinguished from CBC by submitting at least two blocks of identical input bytes. ECB will produce repeated ciphertext blocks; CBC will not.

### 2.12 — Byte-at-a-Time ECB Decryption (Simple)

Given an AES-ECB oracle that appends an unknown secret suffix to attacker-controlled input:

1. Determine the block size by incrementally lengthening the input until the output length jumps — the jump size is the block length.
2. Build a dictionary of all 256 possible last bytes of a controlled 15-byte prefix block.
3. Query the oracle with 15 bytes; the 16th output byte matches a dictionary entry, revealing the first secret byte.
4. Slide the window forward one byte at a time, using previously recovered bytes to populate the dictionary, until all secret bytes are recovered.

### 2.13 — ECB Cut-and-Paste

ECB's deterministic, block-independent nature allows forging a ciphertext by splicing blocks from different oracle queries. By crafting email addresses that push the target field (`role=admin\x0b\x0b...`) to a block boundary in one query and aligning the prefix of the target profile in another, the admin block can be grafted onto a legitimate-looking profile ciphertext to produce a forged `role=admin` token.

### 2.14 — Byte-at-a-Time ECB Decryption (Harder)

Extends Challenge 2.12 to handle an unknown random prefix prepended by the oracle. Sending three identical blocks of attacker data always produces at least two consecutive identical ciphertext blocks wherever the attacker data aligns. Count the padding bytes needed to achieve alignment, determine which block index the attacker data starts in, and then proceed byte-by-byte as before adjusting all offsets by the prefix length.

### 2.15 — PKCS#7 Padding Validation

Validate PKCS#7 padding by reading the last byte value `n` and confirming the final `n` bytes all equal `n`. If validation fails, throw an exception. Valid examples: `01` is always valid; `02 02` is valid; a full trailing block of sixteen `10` bytes is valid. Correct validation is the prerequisite for padding oracle attacks.

### 2.16 — CBC Bitflipping Attacks

CBC decryption XORs each decrypted block with the previous ciphertext block. An attacker who controls a ciphertext block can flip specific bits in the *next* plaintext block. To inject `;admin=true;` into a cookie string, XOR the corresponding bytes of the preceding ciphertext block with `(known_plaintext_byte XOR desired_plaintext_byte)`. The modified block decrypts as garbage but the following block contains the injected payload.

---

## Set 3 — Block & Stream Crypto

> Challenges 17–24. Padding oracles, CTR mode, and the Mersenne Twister PRNG.

### 3.17 — The CBC Padding Oracle

Given a padding oracle (a black-box that reveals only whether a decrypted ciphertext has valid PKCS#7 padding), recover plaintext one byte at a time from the last block backwards. For each target byte, iterate 0x00–0xFF XORed into the corresponding position of the preceding ciphertext block until the oracle reports valid padding. XORing the found value with the expected padding value recovers the plaintext byte. Repeat, extending the valid-padding suffix by one byte each round.

**Edge case:** The very last byte may have two valid values (the original padding byte and `0x01`). Searching from `0xFF` down to `0x00` ensures the larger, correct value is found first.

### 3.18 — Implement CTR Mode

AES-CTR (Counter) mode generates a keystream by AES-ECB-encrypting successive 64-bit counter values concatenated with a fixed 64-bit nonce. The keystream blocks are XORed with plaintext/ciphertext. No padding is required and encryption and decryption are identical operations. The AES-ECB primitive is reused directly.

### 3.19 — Break Fixed-Nonce CTR Using Substitutions

Fixed-nonce CTR produces the same keystream for every message, making it equivalent to a repeating-key XOR (Vigenère cipher) across all messages aligned at the same byte position. Standard single-byte frequency analysis applies for positions where enough ciphertexts overlap. For shorter strings where only a few overlap, trigraph (three-letter combination) frequency statistics bridge the gap.

### 3.20 — Break Fixed-Nonce CTR Statistically

Same attack as Challenge 3.19 but solved entirely programmatically. The ciphertexts are truncated to the length of the shortest one to form a uniform keystream, then statistical frequency analysis (monographs, bigraphs, trigraphs, word-boundary frequencies, etc.) is applied across all columns simultaneously. Large n-gram databases derived from public-domain literature provide the statistical baseline.

### 3.21 — Implement the MT19937 Mersenne Twister RNG

The Mersenne Twister (MT19937) is the most widely used general-purpose PRNG, designed in 1997 by Matsumoto and Nishimura. Its period is the Mersenne prime 2¹⁹⁹³⁷−1. It operates on a 624-element 32-bit state array using a twisted generalised feedback shift register (TGFSR) with tempering.

```
// State initialisation
function seed_mt(seed):
    index = n;  MT[0] = seed
    for i = 1 to n-1:
        MT[i] = lowest_w_bits(f * (MT[i-1] XOR (MT[i-1] >> (w-2))) + i)

// Number generation
function extract_number():
    if index >= n: twist()
    y = MT[index]
    y = y XOR ((y >> u) AND d);  y = y XOR ((y << s) AND b)
    y = y XOR ((y << t) AND c);  y = y XOR (y >> l)
    index += 1;  return lowest_w_bits(y)

// State transition
function twist():
    for i = 0 to n-1:
        x = (MT[i] AND upper_mask) + (MT[(i+1) mod n] AND lower_mask)
        xA = x >> 1
        if x is odd: xA = xA XOR a
        MT[i] = MT[(i+m) mod n] XOR xA
    index = 0
```

### 3.22 — Crack an MT19937 Seed

When MT19937 is seeded with the current Unix timestamp, the seed space is small enough to brute-force. Given one output value and an approximate upper bound on when it was generated, decrement a candidate timestamp and re-seed MT19937 until the first output matches. The original seed (and thus the timestamp) is recovered by searching backwards over a small time window.

### 3.23 — Clone an MT19937 RNG from Its Output

The MT19937 tempering transform is invertible. By collecting 624 consecutive outputs and untempering each one, the full internal state array can be reconstructed. Splicing this state into a fresh MT instance produces an exact clone. The untempering reversal:

```csharp
public uint Unextract(uint value) // untemper
{
    value = value ^ value >> 18;
    value = value ^ ((value & 0x1DF8Cu) << 15);
    uint t = value;
    t     = ((t & 0x0000002D) << 7) ^ value;  // 7 bits
    t     = ((t & 0x000018AD) << 7) ^ value;  // 14 bits
    t     = ((t & 0x001A58AD) << 7) ^ value;  // 21 bits
    value = ((t & 0x013A58AD) << 7) ^ value;  // 32-7 bits
    uint top = value & 0xFFE00000;
    uint mid = value & 0x001FFC00;
    uint low = value & 0x000003FF;
    return top | ((top >> 11) ^ mid) | ((((top >> 11) ^ mid) >> 11) ^ low);
}
```

### 3.24 — Create the MT19937 Stream Cipher and Break It

Using MT19937 as a keystream cipher (extracting 32-bit words, converting to bytes, XORing with plaintext) seeded with a 16-bit value is trivially broken by exhaustive search (0–65535). For the password-reset token variant the attack mirrors Challenge 3.22: brute-force candidate Unix timestamps backwards from the current time until the MT output matches the token.

---

## Set 4 — Stream Crypto and Randomness

> Challenges 25–32. CTR edits, CBC IV=Key, SHA-1/MD4 keyed MACs, and timing attacks.

### 4.25 — Break "Random Access Read/Write" AES CTR

A CTR edit oracle allows replacing a range of plaintext bytes and returning the new ciphertext. XOR the original ciphertext with the result of editing the same range with all-zero bytes to cancel the keystream and recover the plaintext: `plaintext = original_ciphertext XOR edit(0, len, zeroes)`.

### 4.26 — CTR Bitflipping

Analogous to the CBC bitflipping attack (Challenge 2.16), but simpler: in CTR mode the keystream is XORed directly with plaintext at the same position, so flipping bits in the ciphertext flips the same bits in the plaintext with no block-chaining offset. The precise modification to inject `;admin=true;` is: `<2 encrypted blocks> + <userdata_block_1 XOR ciphertext_block_3 XOR ";admin=true;    "> + <remaining ciphertext>`.

### 4.27 — Recover the Key from CBC with IV=Key

When IV = Key in AES-CBC, submit the forged ciphertext `C_1 || 0x00…0x00 || C_1`. If the server decrypts and returns the invalid plaintext, it reveals `P'_1 XOR P'_3`. Since `P'_3 = AES_decrypt(C_1) XOR 0 = AES_decrypt(C_1)` and `P'_1 = AES_decrypt(C_1) XOR IV = AES_decrypt(C_1) XOR Key`, the key is recovered as `P'_1 XOR P'_3`.

### 4.28 — Implement a SHA-1 Keyed MAC

A custom SHA-1 implementation built from scratch following the FIPS specification.

**Initialisation:** `h0=0x67452301, h1=0xEFCDAB89, h2=0x98BADCFE, h3=0x10325476, h4=0xC3D2E1F0`

**Pre-processing:** Append `0x80`, zero-pad to 448 bits mod 512, then append the 64-bit big-endian message length.

**Compression function (per 512-bit chunk, i = 0..79):**

```
if  0 ≤ i ≤ 19:  f = (b AND c) OR (NOT b AND d);     k = 0x5A827999
if 20 ≤ i ≤ 39:  f = b XOR c XOR d;                  k = 0x6ED9EBA1
if 40 ≤ i ≤ 59:  f = (b AND c) OR (b AND d) OR (c AND d);  k = 0x8F1BBCDC
if 60 ≤ i ≤ 79:  f = b XOR c XOR d;                  k = 0xCA62C1D6
temp = (a <<< 5) + f + e + k + w[i]
e=d; d=c; c=(b<<<30); b=a; a=temp
```

A SHA-1 keyed MAC is `SHA1(key || message)`. Altering the message invalidates the MAC, assuming the key is secret.

### 4.29 — Break a SHA-1 Keyed MAC Using Length Extension

SHA-1 processes data in 64-byte blocks and its output *is* the intermediate compression state. A length extension attack initialises a new SHA-1 context with the hash output as the starting state and a faked message length of `len(key) + len(original_message) + len(glue_padding)`. Hashing additional data from this state produces a valid forged MAC without knowing the key:

```
SHA1(key || msg || glue || extension) =
    SHA1_from_state(SHA1(key || msg || glue), block_count, extension)
```

### 4.30 — Break an MD4 Keyed MAC Using Length Extension

MD4 (RFC 1320) uses the same Merkle–Damgård construction as SHA-1. The identical length extension technique applies — initialise the MD4 context from the prior hash output and padded length, then hash the extension. The forged MAC authenticates a new message the server will accept.

**MD4 round functions** (little-endian, 32-bit, mod 2³²):

```
F(X,Y,Z) = (X AND Y) OR (NOT X AND Z)
G(X,Y,Z) = (X AND Y) OR (X AND Z) OR (Y AND Z)
H(X,Y,Z) = X XOR Y XOR Z
```

Round 1 uses F; Round 2 uses G + `0x5A827999`; Round 3 uses H + `0x6ED9EBA1`.

### 4.31 — Implement and Break HMAC-SHA1 with an Artificial Timing Leak

An HMAC-SHA1 comparison that returns early on the first mismatched byte leaks timing information. By trying all 256 values for each byte position and measuring which takes longest (with a 50 ms artificial sleep per compared byte), the correct MAC byte is identified. Fixing each discovered byte and moving to the next recovers all 20 bytes of the HMAC.

### 4.32 — Break HMAC-SHA1 with a Slightly Less Artificial Timing Leak

With only a 5 ms per-byte sleep the signal is subtler. Amplify it by repeating each candidate measurement multiple times (e.g. 5 rounds) and averaging — this reduces noise from OS scheduling jitter enough to identify the correct byte. A high-resolution stopwatch (CPU ticks) is used in place of wall-clock time.

---

## Set 5 — Diffie-Hellman and Friends

> Challenges 33–40. Key exchange, MITM parameter injection, SRP, and RSA fundamentals.

### 5.33 — Implement Diffie-Hellman

Alice picks secret `a`, computes `A = g^a mod p` and sends it to Bob. Bob picks secret `b`, computes `B = g^b mod p` and sends it to Alice. Both derive the shared secret `s = g^(ab) mod p = B^a mod p = A^b mod p`.

Implementation notes for C# `BigInteger`:
- Byte arrays are treated as little-endian; cryptographic data is big-endian — byte reversal is required.
- Prepend a `0x00` byte to prevent sign-bit misinterpretation for values with the high bit set.
- Modular exponentiation via repeated squaring (if `BigInteger.ModPow` is unavailable):

```csharp
BigInteger modPow(BigInteger b, BigInteger e, BigInteger m) {
    BigInteger result = 1;
    while (e != 0) {
        if (!e.IsEven) result = (result * b) % m;
        e /= 2;
        b = (b * b) % m;
    }
    return result;
}
```

OOP design uses a `Participant` class for Alice and Bob and a `ManInTheMiddle` class for the MITM relay.

### 5.34 — MITM Key-Fixing Attack on Diffie-Hellman with Parameter Injection

The MITM replaces Alice's public key `A` with `p` when forwarding to Bob, and Bob's `B` with `p` when forwarding to Alice. Since `p^x mod p = 0` for any `x`, both parties compute shared secret 0. The MITM derives the AES key as `SHA1(0)[0:16]` and silently decrypts and re-encrypts all AES-CBC traffic in both directions.

### 5.35 — DH with Negotiated Groups — Break with Malicious "g" Parameters

The MITM poisons the negotiated generator `g` before the DH protocol runs:

- **g = 1:** `B = 1^b mod p = 1`. Forge `A = 1`. Shared secret is always 1.
- **g = p:** `B = p^b mod p = 0`. Forge `A = p`. Shared secret is always 0.
- **g = p−1:** `B` is 1 or p−1. Forge `A = 1`. Alice's shared secret is 1 (75%) or p−1 (25%). The MITM first tries key derived from secret 1; on PKCS#7 padding failure falls back to key derived from p−1 and re-encrypts before forwarding.

### 5.36 — Implement Secure Remote Password (SRP)

SRP authenticates a client to a server using DH without transmitting the password:

```
Client → Server:  email, A = g^a % N
Server → Client:  salt, B = k*v + g^b % N   (k=3, v = g^x % N, x = SHA256(salt||password))
Client → Server:  HMAC-SHA256(K, salt)       (u = SHA256(A||B), S = (B - k*g^x)^(a+u*x) % N, K = SHA256(S))
Server verifies:  S = (A * v^u)^b % N,  K = SHA256(S)
```

### 5.37 — Break SRP with a Zero Key

Send `A = 0`, `A = N`, or `A = N^k` (any multiple of N). The server computes `S = (A * v^u)^b % N = 0`. The attacker independently computes `K = SHA256(0)` and forges a valid `HMAC-SHA256(K, salt)` — authenticating without knowing the password.

### 5.38 — Offline Dictionary Attack on Simplified SRP

In the simplified protocol `B = g^b % n` and `u` is a random 128-bit nonce. A MITM posing as the server chooses its own `b, B, salt, u` and receives the client HMAC. It then mounts an offline dictionary attack: for each candidate password compute `x, v, S = (A * v^u)^b % n, K = SHA256(S)` and compare against the observed HMAC. Setting `b = u = 1` (so `S = A*v % n`) eliminates expensive modular exponentiation and drastically speeds up the search.

### 5.39 — Implement RSA

**Key generation:** choose random primes `p, q`; compute `n = p*q`, Euler totient `φ = (p−1)*(q−1)`, public exponent `e = 3`, private exponent `d = e⁻¹ mod φ`.  
**Encryption:** `c = m^e mod n`. **Decryption:** `m = c^d mod n`.

Extended-Euclidean modular inverse:

```csharp
static BigInteger modInverse(BigInteger a, BigInteger n) {
    BigInteger i = n, v = 0, d = 1;
    while (a > 0) {
        BigInteger t = i / a, x = a;
        a = i % x; i = x; x = d;
        d = v - t * x; v = x;
    }
    v %= n;
    if (v < 0) v = (v + n) % n;
    return v;
}
```

### 5.40 — Implement an E=3 RSA Broadcast Attack

Encrypting the same plaintext `m` under three independent RSA public keys with `e=3` leaks `m`:

1. Collect ciphertexts `c₀, c₁, c₂` and moduli `n₀, n₁, n₂`.
2. Apply the **Chinese Remainder Theorem**:
   ```
   result = ( c₀·ms₀·invmod(ms₀, n₀)
            + c₁·ms₁·invmod(ms₁, n₁)
            + c₂·ms₂·invmod(ms₂, n₂) ) mod (n₀·n₁·n₂)
   where msᵢ = product of all nⱼ with j ≠ i
   ```
3. Take the integer cube root of `result` to recover `m`.

Integer cube root (from *Hacker's Delight*, adapted for `BigInteger`):

```csharp
public static BigInteger icbrt2(BigInteger x) {
    BigInteger b, y2 = 0, y = 0;
    for (int s = (GetBitSize(x) / 3) * 3; s >= 0; s -= 3) {
        y2 = 4 * y2; y = 2 * y;
        b = (3 * (y2 + y) + 1) * BigInteger.Pow(2, s);
        if (x >= b) { x -= b; y2 += 2 * y + 1; y++; }
    }
    return y;
}
```

---

## Set 6 — RSA and DSA

> Challenges 41–48. Signature forgery, DSA nonce attacks, RSA parity oracle, and Bleichenbacher padding attacks.

### 6.41 — Recover the Plaintext from "Unpadded" RSA Message Recovery Oracle

An RSA decryption oracle that refuses to decrypt the same ciphertext twice can still be beaten. Blind the ciphertext by computing `c' = (s^e * c) mod n` for a random `s`, submit `c'` to the oracle (which has never seen it), receive `p' = c'^d mod n`, then recover `p = p' * s⁻¹ mod n`. The blinding makes the oracle see a fresh ciphertext each time.

### 6.42 — Bleichenbacher's e=3 RSA Attack (Signature Forgery)

A broken PKCS#1 v1.5 signature verifier that only checks the *prefix* of the padded hash can be fooled by crafting a signature `s` such that `s^3` begins with `0x00 0x01 0xFF 0x00 <ASN.1 prefix> <hash>` followed by arbitrary garbage. The cube root of a number with the correct prefix can be found by integer cube root plus rounding up — forging a valid-looking signature without the private key.

### 6.43 — DSA Key Recovery from Nonce

In DSA, if the per-signature nonce `k` is known or guessable (e.g. weak RNG or small `k`), the private key `x` can be recovered from a single signature `(r, s)` and message hash `H(m)`:

```
x = (s*k - H(m)) * r⁻¹ mod q
```

A small `k` (< 2¹⁶) can be exhaustively searched. The recovered key is verified by checking that `SHA1(hex(x))` matches the provided fingerprint.

### 6.44 — DSA Nonce Recovery from Repeated Nonce

If the same nonce `k` is reused across two signatures `(r₁,s₁)` and `(r₂,s₂)` on different messages (detected by `r₁ = r₂`), `k` can be recovered:

```
k = (H(m₁) - H(m₂)) * (s₁ - s₂)⁻¹ mod q
```

Once `k` is known, the private key follows from the Challenge 6.43 formula.

### 6.45 — DSA Parameter Tampering

Malicious group parameters break DSA security:

- **g = 0:** All signatures have `r = 0`. Signature verification collapses in ways that allow `(r=1, s=1)` to pass trivially depending on implementation.
- **g = p+1 ≡ 1 mod p:** `r = (g^k mod p) mod q = 1` for all `k`. A magic signature `(r=1, s=H(m)/r mod q)` verifies for *any* message without the private key.

### 6.46 — RSA Parity Oracle

An oracle that reveals only whether a decrypted RSA value is odd or even enables full plaintext recovery via binary search. Multiplying the ciphertext by `2^e mod n` doubles the plaintext mod `n`; the parity of the result narrows the plaintext to one half of the remaining range each iteration. After `log₂(n)` steps (~1024 for a 1024-bit key), the plaintext is uniquely determined.

### 6.47 — Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)

Given an oracle that reports whether a decrypted RSA ciphertext has valid PKCS#1 v1.5 padding (`0x00 0x02 ...`), Bleichenbacher's 1998 attack recovers the plaintext through adaptive chosen-ciphertext queries. The simplified version (assuming the plaintext is already PKCS-conforming) narrows the plaintext to a single interval through iterative multiplications and range halving.

### 6.48 — Bleichenbacher's PKCS 1.5 Padding Oracle (Complete Case)

The full Bleichenbacher attack without simplifying assumptions. The algorithm maintains a set of intervals `M` containing the plaintext and iteratively tightens them by searching for valid blinding factors `s`. Each oracle call returning "valid padding" shrinks the interval set. The attack terminates when `|M| = 1` and the interval collapses to the plaintext value.

---

## Set 7 — Hashes

> Challenges 49–56. CBC-MAC forgery, hash multicollisions, and RC4 biases.

### 7.49 — CBC-MAC Message Forgery

CBC-MAC authenticates a message by taking the final AES-CBC block with a fixed IV. Two weaknesses allow forgery:

- **Fixed IV:** If the IV is known or zero, an attacker can XOR a desired prefix adjustment into the first block of a known valid (message, MAC) pair to forge a new valid pair.
- **Length extension:** Given `MAC(m)`, a new message `m || m'` has `MAC = CBC-MAC(m', IV=MAC(m))`, enabling forgery of extended messages without the key.

### 7.50 — Hashing with CBC-MAC

CBC-MAC used as a public hash (with a known IV) is not collision-resistant. A collision is found by constructing a two-block message `m₁ || m₂` where `m₂ = AES_decrypt(target_hash) XOR CBC-MAC(m₁)`, making the CBC-MAC of the two-block message equal to any desired target.

### 7.51 — Compression Ratio Side-Channel Attacks

When a secret is compressed together with attacker-controlled data (analogous to HTTPS/CRIME), the compressed output length leaks information. If the attacker's input matches a substring of the secret, compression achieves a better ratio and output is shorter. Iterating character by character and observing length decreases reveals the secret one byte at a time.

### 7.52 — Iterated Hash Function Multicollisions

For a hash function with `b`-bit state, finding a single collision takes ~2^(b/2) work (birthday bound). An iterated Merkle–Damgård construction allows generating an exponential number of **multicollisions** with only linear work — one collision per tree level. This demonstrates that concatenating a weak hash with a strong one (`H(m) = weak(m) || strong(m)`) provides no additional collision resistance beyond the weak component alone.

### 7.53 — Kelsey and Schneier's Expandable Messages

An expandable message is a pair `(short, long)` with the same intermediate hash output, where their lengths differ by a power of 2. By constructing a chain of `k` such pairs (one per level), an attacker can produce a message of any length from `k` to `k + 2^k − 1` blocks that collides at a target hash state — a prerequisite for the Nostradamus attack.

### 7.54 — Kelsey and Kohno's Nostradamus Attack

Using expandable messages, an attacker can commit to a hash before the content is known:

1. Build a binary tree of hash collisions down to a single final hash (the "commitment").
2. Publish the commitment hash.
3. After the content is revealed, construct a prefix linking the target content to the precomputed collision tree, producing a document matching the committed hash.

### 7.55 — MD4 Collisions

Wang et al.'s 2004 differential cryptanalysis attack on MD4 finds collisions by exploiting differential paths through the three-round structure. Specific bit conditions on intermediate state variables are enforced through message modification, enabling near-instant collision generation and demonstrating that MD4 is completely broken.

### 7.56 — RC4 Single-Byte Biases

The RC4 stream cipher has well-known statistical biases: byte positions 0, 1, 15, 31, and others in the keystream are strongly biased toward specific values. By repeatedly encrypting `unknown_prefix || secret_byte` and collecting many samples at the biased position, a maximum-likelihood estimate identifies each secret byte. Repeating across all byte positions recovers the full secret.

---

## Set 8 — Abstract Algebra

> Challenges 57–64. Subgroup confinement, Pollard's kangaroo, elliptic curves, and GCM attacks.

### 8.57 — Diffie-Hellman Revisited: Small Subgroup Confinement

If the DH modulus `p` has a smooth order `p-1` (many small prime factors), an attacker can send public keys that force the shared secret into small subgroups. By the Chinese Remainder Theorem, discrete logarithms computed modulo each small subgroup factor combine (Pohlig–Hellman) to recover the full private key `b mod (p-1)` even for large `p`.

### 8.58 — Pollard's Method for Catching Kangaroos

Pollard's kangaroo algorithm solves the discrete logarithm problem in a known interval `[a, b]` in `O(√(b−a))` time. Two pseudo-random walks — a "tame" kangaroo starting from a known point and a "wild" kangaroo starting from the target — are run until they collide, revealing the discrete log. Combined with the subgroup results from Challenge 8.57, this recovers the remaining high-order bits of the private key.

### 8.59 — Elliptic Curve Diffie-Hellman and Invalid-Curve Attacks

ECDH over a Weierstrass curve `y² = x³ + ax + b mod p` is subject to invalid-curve attacks when the server accepts arbitrary points without group membership validation. By sending points from twist curves (related curves with different group orders), the attacker confines the server's scalar multiplication to small subgroups of the twist and uses CRT and Pohlig–Hellman to recover the private key — directly analogous to Challenge 8.57 but on elliptic curves.

### 8.60 — Single-Coordinate Ladders and Insecure Twists

Montgomery curves enable efficient single-coordinate (x-only) scalar multiplication via the Montgomery ladder. If an implementation uses x-only arithmetic without verifying that the received point lies on the correct curve, the same invalid-curve/twist attack from Challenge 8.59 applies. Points on the quadratic twist have a different group order and can be used for the same subgroup confinement attack.

### 8.61 — Duplicate-Signature Key Selection in ECDSA (and RSA)

Given an ECDSA signature `(r, s)` on a message, it is possible to construct a different public key `Q'` under which the same signature also verifies. This means ECDSA signatures do not bind to a unique key without additional context — a property that enables cross-key signature validity forgery. An analogous duplicate-key construction exists for RSA PKCS#1 v1.5 signatures.

### 8.62 — Key-Recovery Attacks on ECDSA with Biased Nonces

If the ECDSA nonce `k` is biased (e.g. the top few bits are always zero due to a faulty RNG), the private key can be recovered using lattice methods (Hidden Number Problem / LLL lattice basis reduction). Each signature equation `s = k⁻¹(H(m) + r·x) mod q` with a partially known `k` provides a linear constraint; enough constraints allow the lattice to be solved for the private key `x`.

### 8.63 — Key-Recovery Attacks on GCM with Repeated Nonces

AES-GCM authentication uses a polynomial MAC over GF(2¹²⁸). If the nonce is ever reused with the same key, the authentication key `H` (the GCM hash key) can be recovered by XORing two ciphertext+tag pairs and solving for `H` as a root of a polynomial in GF(2¹²⁸). With `H` known, arbitrary message forgeries become possible.

### 8.64 — Key-Recovery Attacks on GCM with a Truncated MAC

When the GCM authentication tag is truncated (e.g. to 32 bits), birthday-bound tag collisions become feasible. An attacker can find two messages that collide under the truncated MAC, use the collision to narrow down possible values of the authentication polynomial, and iteratively recover the GCM hash key `H` — eventually enabling full forgery with far fewer queries than against a full 128-bit tag.

---

## Set 9 — Unreleased Challenges

> Challenges 65–66. Distributed privately by the Cryptopals authors and never published on the public website. Set 9 pushes both GCM cryptanalysis and elliptic curve fault attacks to their practical limit.

### 9.65 — Key-Recovery Attack on GCM with a Truncated MAC (Matrix Method)

This challenge extends Challenge 8.64 to a much more powerful setting: a 32-bit truncated MAC on messages of 2¹⁷ × 128-bit blocks, using the matrix-based key recovery technique described by Niels Ferguson in his [2005 critique of GCM](https://csrc.nist.gov/csrc/media/projects/block-cipher-techniques/documents/bcm/comments/cwc-gcm/ferguson2.pdf).

The GCM authentication tag is a polynomial in the key `H` over GF(2¹²⁸):
```
tag = c₁·H^n + c₂·H^(n-1) + … + cₙ·H + E(nonce)
```
The ciphertext coefficients assemble into a 128×128 matrix `Ad` such that `Ad · H = tag_vector`. The attack:

1. **Build dependency matrix T** — For each bit that can be flipped in the ciphertext, compute how the flip changes `Ad` as a linear map over GF(2). Each column of `T` represents one bit-flip; each row represents a cell of `Ad`. Squaring matrices `Ms = M_H^(2^i)` are precomputed using the Frobenius endomorphism to accelerate the coefficient expansion.
2. **Find null-space vectors** — Gaussian elimination over GF(2) on the transpose of `T` yields a basis for `N(T)`: bit-flip combinations that leave the upper rows of `Ad` unchanged, i.e. that preserve the truncated tag.
3. **Query the oracle** — Combine null-space basis vectors (exhaustively for small bases, randomly for larger ones), flip the corresponding ciphertext bits, and query the truncated-MAC oracle. A tag match means the modification is invisible.
4. **Accumulate constraints on H** — Each successful collision gives new linearly independent rows of a constraint matrix `K` such that `K · H = 0` over GF(2). Gaussian elimination on `K` progressively shrinks the right null space `Xm`, which contains `H`.
5. **Terminate** — When `Xm` has dimension 1, its unique nonzero vector is the recovered authentication key `H`.

Two operating phases are used: a *length-mode* phase that targets the GCM length field for cheap early constraints, followed by a general-coefficient phase. Fast GCM tag computation via a native library keeps the inner loop practical at 2¹⁷-block message sizes.

### 9.66 — Differential Fault Attack on Elliptic Curve Scalar Multiplication

This challenge implements the differential fault attack on ECDH introduced by Biehl, Meyer, and Müller (2000), recovering a full ECC private scalar one bit at a time by observing whether a hardware fault is triggered during scalar multiplication.

The target uses the same Weierstrass curve as Challenge 8.59 (`y² = x³ + ax + b mod p`, `p = 233970423115425145524320034830162017933`). The faulty oracle `scaleECfault(h, d)` simulates a fault-injection device: during the double-and-add loop, a specific intermediate doubling step may be silently skipped depending on the bit pattern of `d` and the input point `h`.

Recovery proceeds from the most significant bit downward:

1. **Maintain a partial key** `k` with all recovered bits set and unknown bits zero. The two candidates for the next bit are `k` and `k | (1 << i)`.
2. **Find a discriminating point** — Search for a random curve point `h` such that `scaleECcheckfault(h, k, i-1)` and `scaleECcheckfault(h, k|(1<<i), i-1)` produce *different* fault outcomes. Such a point distinguishes the two bit hypotheses without querying the secret.
3. **Query the oracle** — Call `scaleECfault(h, d)` to observe the real fault behaviour under the true private key `d`. The result selects which candidate matches.
4. **Resolve ambiguity** — If the oracle returns "no fault" for both candidates (inconclusive), a second discriminating point is found and queried to confirm the bit before advancing.
5. **Recover the last bit** — The LSB cannot be determined by a fault (no doubling occurs at the final step). It is instead inferred by testing whether `k · A_pub` equals the known shared secret, and toggling the bit if not.

The attack requires O(n) oracle queries for an n-bit private key — approximately one discriminating point search plus one oracle call per bit — making it highly practical given physical or simulated fault-injection capability.

---

## References

- [Cryptopals Crypto Challenges](https://cryptopals.com/) — the original challenge sets
- [MT19937 — Wikipedia](https://en.wikipedia.org/wiki/Mersenne_Twister)
- [Bleichenbacher 1998 — "Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard"](https://link.springer.com/chapter/10.1007/BFb0055716)
- [Wang et al. 2004 — "Cryptanalysis of the Hash Functions MD4 and RIPEMD"](https://link.springer.com/chapter/10.1007/11426639_1)
- [Kelsey & Schneier 2005 — "Second Preimages on n-Bit Hash Functions for Much Less than 2^n Work"](https://www.schneier.com/academic/paperfiles/paper-preimages.pdf)
- [Hacker's Delight — Henry S. Warren Jr.](https://www.hackersdelight.org/) — integer cube root algorithm
- [RFC 1320 — The MD4 Message-Digest Algorithm](https://www.rfc-editor.org/rfc/rfc1320)
- [Ferguson 2005 — "Authentication weaknesses in GCM"](https://csrc.nist.gov/csrc/media/projects/block-cipher-techniques/documents/bcm/comments/cwc-gcm/ferguson2.pdf)
- [Biehl, Meyer & Müller 2000 — "Differential Fault Attacks on Elliptic Curve Cryptosystems"](https://link.springer.com/chapter/10.1007/3-540-44598-6_8)

---

*All challenge solutions are original implementations by [Gregory Morse](https://github.com/GregoryMorse). Feel free to reach out at [gregory.morse@live.com](mailto:gregory.morse@live.com) with questions or discussion.*