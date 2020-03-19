import codecs
def hexToBase64(str):
  #base64 encoding leaves extra new line at end so it is trimmed
  return codecs.encode(codecs.decode(str, "hex"), "base64")[:-1].decode()

#test cases are: all characters from 0 to 255
#in production code: ord('0'), ord('A'), ord('a') should be cached and reused
def hexPartToInt(char):
  return (ord(char) - ord('0') if char >= '0' and char <= '9' else
          ord(char) - ord('A') + 10 if char >= 'A' and char <= 'F' else
          ord(char) - ord('a') + 10 if char >= 'a' and char <= 'f' else None)

#test cases are: empty string, odd length string, invalid characters in string,
#  all hex characters 00-FF in string
#in production code: a cached dictionary lookup after conversion to lower case
def hexStrToBin(str):
  l, res = len(str), []
  if l & 1: return None #cannot decode odd length string
  for i in range(0, l, 2):
    u, v = hexPartToInt(str[i]), hexPartToInt(str[i + 1])
    if u == None or v == None: return None #illegal character encountered
    res.append((u << 4) | v)
  return bytes(res)
  
#https://en.wikipedia.org/wiki/Base64
#test cases are: empty string, single byte, two bytes, three bytes
#in production code: base64table and padChar should be cached
#  also the specific cases for i % 24 of 0, 6, 12, 18 should be done directly
#  not generally as is done here where the code could be adapted to any base
def binToBase64(bin):
  base64table = ("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                 "abcdefghijklmnopqrstuvwxyz0123456789+/")
  padChar = ord('=')
  bitLen, res = len(bin) << 3, []
  for i in range(0, bitLen, 6):
    startByte, startBit = i >> 3, i & 7
    val = bin[startByte] & ((1 << (8 - startBit)) - 1) #trim left bits
    if startBit > 2:
      val <<= startBit - 2 #shift to left-most position
      if ((startByte + 1) << 3) < bitLen: #another byte available
        #10 - startBit comes from 8 - (startBit + 6 - 8)
        val |= bin[startByte + 1] >> (10 - startBit) #shift right and add on
    else: val = (val >> (2 - startBit)) #shift to right-most position
    res.append(ord(base64table[val]))
  remBits = bitLen % 24
  if remBits <= 18 and remBits != 0: res.append(padChar)
  if remBits <= 12 and remBits != 0: res.append(padChar)
  return bytes(res)

def hexToBase64Alt(str):
  res = hexStrToBin(str)
  if res == None: return res
  return binToBase64(res).decode("utf-8")
  
def xorBins(bin1, bin2):
  l = len(bin1)
  if l != len(bin2): return None
  return bytes([bin1[i] ^ bin2[i] for i in range(l)])

def characterScore(bin, exclude, freqs):
  #use unprintable characters as immediate exclusion except new line...
  d = dict()
  for i in bin: #group by frequency
    if i in d: d[i] += 1
    else: d[i] = 1
  if any(x in d for x in exclude): return 0
  return sum([freqs[i] * (d[i] if i in d else 0) for i in freqs]) * 100

def getLeastXORCharacterScore(bin):
  exclude = list(range(0, 10)) + list(range(11, 32)) + list(range(127, 256)) + list([ord(x) for x in "$#<>[]{}+^*&%()~|"] )
  
  freqs = {ord('.'):0.0653, ord(','):0.0616, ord(';'):0.0032, ord(':'):0.0034,
           ord('!'):0.0033, ord('?'):0.0056, ord('\''): 0.0243, ord('"'):0.0267,
           ord('-'):0.0153, ord(' '):1/4.79}
  freq = (.08167, .01492, .02202, .04253, .12702, .02228, .02015, .06094,
          .06966, .00153, .01292, .04025, .02406, .06749, .07507, .01929,
          .00095, .05987, .06327, .09356, .02758, .00978, .02560, .00150,
          .01994, .00077) #a-z/A-Z
  for i, x in enumerate(freq):
    freqs[ord('a') + i] = x
    freqs[ord('A') + i] = x
  l = len(bin)
  freqs = [(i,characterScore(xorBins(bin, bytes([i] * l)), exclude, freqs)) for i in range(256)]
  return list(sorted(filter(lambda x: x[1] != 0, freqs), key=lambda x: x[1], reverse=True)) #max(freqs, key=lambda x: x[1])

def xorRepKeyBins(bin, key):
  keylen = len(key)
  return bytes([bin[i] ^ key[i % keylen] for i in range(len(bin))])

def countSetBits(v):
  #Counting bits set, Brian Kernighan's way
  #https://graphics.stanford.edu/~seander/bithacks.html#CountBitsSetKernighan
  c = 0
  while v != 0:
    v &= v - 1 #if low bit 1, remove it, if low bit 0, remove lowest set bit
    c += 1
  return c

def hammingDistanceByte(bin1, bin2):
  l = len(bin1)
  if l != len(bin2): return None
  dist = 0
  for i in range(l):
    dist += countSetBits(bin1[i] ^ bin2[i])
  return dist
  
def hammingDistance(bin1, bin2):
  if len(bin1) != len(bin2): return None
  return countSetBits(int.from_bytes(bin1, byteorder='big', signed=False) ^ 
                      int.from_bytes(bin2, byteorder='big', signed=False))

def breakRepXorKey(minLen, maxLen, cipherData):
  ciphLen = len(cipherData)
  #1 / (ciphLen / i - 1) / i == (i / (ciphLen - i)) / i == 1 / (ciphLen - i)
  best = min([(i, sum([hammingDistance(cipherData[i * j:i * (j + 1)],
                                       cipherData[i * (j + 1):i * (j + 2)])
                       for j in range(ciphLen // i - 1)]) / (ciphLen - i))
              for i in range(minLen, maxLen + 1)], key=lambda x: x[1])
  return best[0], bytes([getLeastXORCharacterScore(
                  [cipherData[j] for j in range(i, ciphLen, best[0])])[0][0]
               for i in range(best[0])])

#pip install pycryptodome
#pip install pycryptodomex
def decrypt_ecb(key, cipherData):
  from Crypto.Cipher import AES
  from Crypto.Util import Padding
  cipher = AES.new(key, AES.MODE_ECB)
  lastBlockSize = len(cipherData) & 15
  if lastBlockSize != 0:
    cipherData = Padding.pad(cipherData, 16) #padding style does not matter
  return cipher.decrypt(cipherData)

def is_ecb_mode(cipherData):
  l, s = len(cipherData), set()
  rem = l & 15
  for i in range(0, l - rem, 16):
    if cipherData[i:i+16] in s: return True
    s.add(cipherData[i:i+16])
  return False

def pkcs7pad(input, blockSize):
  rem = blockSize - (len(input) % blockSize)
  return input + bytes([rem] * rem)

def encrypt_ecb(key, cipherData):
  from Crypto.Cipher import AES
  from Crypto.Util import Padding
  cipher = AES.new(key, AES.MODE_ECB)
  lastBlockSize = len(cipherData) & 15
  if lastBlockSize != 0:
    cipherData = Padding.pad(cipherData, 16) #padding style does not matter
  return cipher.encrypt(cipherData)

def decrypt_cbc(iv, key, cipherData):
  l = len(cipherData)
  out = bytearray(l)
  rem = l & 15
  for i in range(0, l - rem, 16):
    out[i:i+16] = xorBins(decrypt_ecb(key, cipherData[i:i+16]),
                          iv if i == 0 else cipherData[i-16:i])
  if rem != 0:
    out[l-rem:l] = xorBins(decrypt_ecb(key, cipherData[l-rem:l]),
                           (iv if l < 16 else cipherData[l-rem-16:l-rem])[:rem])
  return out

def encrypt_cbc(iv, key, cipherData):
  l = len(cipherData)
  out = bytearray(l)
  rem = l & 15
  for i in range(0, l - rem, 16):
    out[i:i+16] = encrypt_ecb(key, xorBins(cipherData[i:i+16],
                                           iv if i == 0 else out[i-16:i]))
  if rem != 0:
    out[l-rem:l] = encrypt_ecb(key, xorBins(cipherData[l-rem:l],
                                 (iv if l < 16 else out[l-rem-16:l-rem])[:rem]))
  return out
  
def pkcs7strip(input, blockSize):
  l = len(input)
  if l == 0: return input
  last = input[-1]
  if last >= 1 and last <= blockSize and all([x == last for x in input[-last:]]):
    return input[:l-last]
  raise ValueError()

def pkcs7check(input, blockSize):
  l = len(input)
  if l == 0: return True
  last = input[-1]
  if last >= 1 and last <= blockSize and all([x == last for x in input[-last:]]):
    return True
  return False

def crypt_ctr(nonce, key, input):
  l = len(input)
  o = bytearray(l)
  for ctr in range(0, l, 16):
    #uses little endian order
    rem = min(l - ctr, 16)
    o[ctr:ctr+16] = xorBins(input[ctr:ctr+rem], encrypt_ecb(key, nonce.to_bytes(8, byteorder='little') + (ctr >> 4).to_bytes(8, byteorder='little'))[:rem])
  return o
  
def getLeastXORBiTrigramScoreGen(lastWords):
  punctFreqs = {
           ord('.'):0.0653, ord(','):0.0616, ord(';'):0.0032, ord(':'):0.0034,
           ord('!'):0.0033, ord('?'):0.0056, ord('\''): 0.0243, ord('"'):0.0267,
           ord('-'):0.0153, ord(' '):1/4.79}
  freq = (.08167, .01492, .02202, .04253, .12702, .02228, .02015, .06094,
          .06966, .00153, .01292, .04025, .02406, .06749, .07507, .01929,
          .00095, .05987, .06327, .09356, .02758, .00978, .02560, .00150,
          .01994, .00077) #a-z/A-Z
  totalWords = sum([float(x.split(' ')[1]) for x in readUtilityFile("english_monograms.txt")]) / 4.79
  def gramSplit(l): return l[0], float(l[1])
  bigramFreq = {key: value for key, value in [gramSplit(x.split(' ')) for x in readUtilityFile("english_bigrams.txt")]}
  trigramFreq = {key: value for key, value in [gramSplit(x.split(' ')) for x in readUtilityFile("english_trigrams.txt")]}
  quadgramFreq = {key: value for key, value in [gramSplit(x.split(' ')) for x in readUtilityFile("english_quadgrams.txt")]}
  def getLeastXORBiTrigramScore(p, r, s, t):
    freqs = getLeastXORCharacterScore(t)
    for top in range(len(freqs)):
      score = 0
      for i in range(len(t)):
        nextChar = freqs[top][0] ^ t[i]
        if len(t) <= 2:
          st = "".join([chr(p[i]), chr(r[i]), chr(s[i]), chr(nextChar)])
          if st in lastWords:
            score = lastWords[st]
            break
        if (chr(s[i]) in ".,;:!? " and chr(nextChar) in ".,;:!? " or
            chr(r[i]) in ".,;:!? " and chr(nextChar) in ".,;:!? " or
            str.isalpha(chr(s[i])) and str.isdigit(chr(nextChar)) or
            str.isalpha(chr(s[i])) and str.isupper(chr(nextChar))):
          score = 0
          break
        if str.isalpha(chr(p[i])) and str.isalpha(chr(r[i])) and str.isalpha(chr(s[i])) and str.isalpha(chr(nextChar)):
          st = "".join([chr(p[i]), chr(r[i]), chr(s[i]), chr(nextChar)])
          if not st.upper() in quadgramFreq:
            score = 0
            break
          score += quadgramFreq[st.upper()] / totalWords * 4 * 4 * 4 * 4
        elif str.isalpha(chr(r[i])) and str.isalpha(chr(s[i])) and str.isalpha(chr(nextChar)):
          st = "".join([chr(r[i]), chr(s[i]), chr(nextChar)])
          if not st.upper() in trigramFreq:
            score = 0
            break
          score += trigramFreq[st.upper()] / totalWords * 3 * 3 * 3
        elif str.isalpha(chr(s[i])) and str.isalpha(chr(nextChar)):
          st = "".join([chr(s[i]), chr(nextChar)])
          if not st.upper() in bigramFreq:
            score = 0
            break
          score += bigramFreq[st.upper()] / totalWords * 2 * 2
        elif chr(nextChar) in ".,;:!? ":
          score += punctFreqs[nextChar]
        elif chr(s[i]) in ".,;:!? " and str.isalpha(chr(nextChar)):
          score += freq[nextChar - ord('A')] if str.isupper(chr(nextChar)) else freq[nextChar - ord('a')]
        else:
          score = 0
          break
      freqs[top] = freqs[top][0], score
    return list(sorted(filter(lambda x: x[1] != 0, freqs), key=lambda x: x[1], reverse=True))          
  return getLeastXORBiTrigramScore
  
def bigramHandler(getLeastXORBiTrigramScore, val, lines, i, b, analysis):
  e = list(filter(lambda x: len(x) > i, lines))
  vals = getLeastXORBiTrigramScore([x[i - 3] ^ b[i - 3] for x in e],
    [x[i - 2] ^ b[i - 2] for x in e], [x[i - 1] ^ b[i - 1] for x in e], analysis)
  if len(vals) == 0: pass
  elif len(b) == i + 1 or len(vals) == 1: val = vals[0]
  else:
    e1 = list(filter(lambda x: len(x) > i + 1, e))
    p = [x[i - 2] ^ b[i - 2] for x in e1]
    q = [x[i - 1] ^ b[i - 1] for x in e1]
    s = [x[i + 1] for x in e1]
    e2 = list(filter(lambda x: len(x) > i + 2, e1))
    p1 = [x[i - 1] ^ b[i - 1] for x in e2]
    s1 = [x[i + 2] for x in e2]
    def secondLookAhead(y, x, q1):
      vls = getLeastXORBiTrigramScore(p1, q1, [bts[i + 1] ^ y[0] for bts in e2], s1)
      return x[0], (0 if len(vls) == 0 else vls[0][1] + y[1] + x[1])
    def firstLookAhead(x):
      vs = getLeastXORBiTrigramScore(p, q, [bts[i] ^ x[0] for bts in e1], s)
      if len(b) != i + 2 and len(vs) > 1:
        q1 = [bts[i] ^ x[0] for bts in e2]
        return sorted([secondLookAhead(y, x, q1) for y in vs], key=lambda x: x[1], reverse=True)[0]
      else: return x[0], (0 if len(vs) == 0 else vs[0][1] + x[1])
    val = sorted([firstLookAhead(x) for x in vals], key=lambda x: x[1], reverse=True)[0]
  return val
  
class MersenneTwister:
  def initialize(self, seed):
    self.index = 624
    self.x = [0] * 624
    i = 1
    self.x[0] = seed
    j = 0
    while True:
      a = (i + 1812433253 * (self.x[j] ^ (self.x[j] >> 30))) & 0xFFFFFFFF
      self.x[j + 1] = a
      b = (i + 1812433253 * (a ^ (a >> 30)) + 1) & 0xFFFFFFFF
      i += 2
      self.x[j + 2] = b
      j += 2
      if j >= 0x26C: break
    self.x[0x26C] = 0
    self.x[0x26D] = 0
    self.x[0x26E] = 0
    self.x[0x26F] = 0
  def splice(self, vals):
    self.index = 0
    self.x[0:624] = vals[0:624]
  def twist(self):
    top, l = 397, 623
    j = 0
    while True:
      i = (top - 396) % 624
      c = (self.x[j] ^ (self.x[j] ^ self.x[i]) & 0x7FFFFFFF) >> 1
      if (((self.x[j] ^ (self.x[j] ^ self.x[i])) & 1) != 0):
        c ^= 0x9908B0DF
      f, top = top, top + 1
      out = c ^ self.x[f % 624]
      self.x[j] = out
      j += 1
      l -= 1
      if l == 0: break
    self.index = 0
    return out
  def unextract(value):
    value = value ^ value >> 18 #inverse of x ^ (x >> 18)
    value = value ^ ((value & 0x1DF8C) << 15) #inverse of ((x & 0xFFFFDF8C) << 15) ^ x = (x << 15) & 0xEFC60000 ^ x
    t = value #inverse of ((x & 0xFF3A58AD) << 7) ^ x = ((x << 7) & 0x9D2C5680) ^ x
    t = ((t & 0x0000002D) << 7) ^ value #7 bits
    t = ((t & 0x000018AD) << 7) ^ value #14 bits
    t = ((t & 0x001A58AD) << 7) ^ value #21 bits
    value = ((t & 0x013A58AD) << 7) ^ value #32-7 bits
                                            #inverse of x ^ x >> 11
    top = value & 0xFFE00000
    mid = value & 0x001FFC00
    low = value & 0x000003ff
    return top | ((top >> 11) ^ mid) | ((((top >> 11) ^ mid) >> 11) ^ low)
  def extract(self):
    i = self.index
    if self.index >= 624:
      self.twist()
      i = self.index
    e = self.x[i]
    v = self.x[i] >> 11
    self.index = i + 1
    df = ((((v ^ e) & 0xFF3A58AD) << 7) & 0xFFFFFFFF) ^ v ^ e
    return (((df & 0xFFFFDF8C) << 15) & 0xFFFFFFFF) ^ df ^ (((((df & 0xFFFFDF8C) << 15) & 0xFFFFFFFF) ^ df) >> 18)
  
class SHA1Context:
  def __init__(self):
    self.intermediate_hash = [0] * (SHA1_Algo.hashSize // 4)
    self.length_low = 0
    self.length_high = 0
    self.message_block_index = 0
    self.message_block = bytearray(64)
    self.computed = 0
    self. corrupted = 0
class SHA1_Algo:
  hashSize = 20
  shaSuccess = 0
  shaNull = 1
  shaInputTooLong = 2
  shaStateError = 3
  def resetFromHashLen(context, h, blocks):
    if context is None: return SHA1_Algo.shaNull
    context.length_low = blocks * 64 * 8
    context.length_high = 0
    context.message_block_index = 0
    context.intermediate_hash[0] = int.from_bytes(h[:4], byteorder='big')
    context.intermediate_hash[1] = int.from_bytes(h[4:8], byteorder='big')
    context.intermediate_hash[2] = int.from_bytes(h[8:12], byteorder='big')
    context.intermediate_hash[3] = int.from_bytes(h[12:16], byteorder='big')
    context.intermediate_hash[4] = int.from_bytes(h[16:], byteorder='big')
    context.computed = 0
    context.corrupted = 0
    return SHA1_Algo.shaSuccess
  def pad(message_array, prior_blocks=0):  
    r = len(message_array) % 64
    return message_array + bytes([0x80] + [0] * ((64 if r >= 56 else 0) + 55 - r)) + (len(message_array) * 8 + prior_blocks * 64 * 8).to_bytes(8, 'big')
  def reset(context):
    if context is None: return SHA1_Algo.shaNull
    context.length_low = 0
    context.length_high = 0
    context.message_block_index = 0
    context.intermediate_hash[0] = 0x67452301
    context.intermediate_hash[1] = 0xEFCDAB89
    context.intermediate_hash[2] = 0x98BADCFE
    context.intermediate_hash[3] = 0x10325476
    context.intermediate_hash[4] = 0xC3D2E1F0
    context.computed = 0
    context.corrupted = 0
    return SHA1_Algo.shaSuccess
  def input(context, message_array):
    l = len(message_array)
    if l == 0: return SHA1_Algo.shaSuccess
    if context is None or message_array is None: return SHA1_Algo.shaNull
    if context.computed != 0:
      context.corrupted = SHA1_Algo.shaStateError
    if context.corrupted != 0:
      return context.corrupted
    i = 0
    while l != 0 and context.corrupted == 0:
      l -= 1
      context.message_block[context.message_block_index] = message_array[i] & 0xFF
      context.message_block_index += 1
      context.length_low = (context.length_low + 8) & 0xFFFFFFFF
      if context.length_low == 0:
        context.length_high = (context.length_high + 1) & 0xFFFFFFFF
        if context.length_high == 0:
          context.corrupted = SHA1_Algo.shaInputTooLong
      if context.message_block_index == 64: SHA1_Algo.processMessageBlock(context)
      i += 1
    return SHA1_Algo.shaSuccess
  def processMessageBlock(context):
    k = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6]
    w = [0] * 80
    for t in range(16):
      w[t] = (context.message_block[t * 4] << 24) & 0xFFFFFFFF
      w[t] |= (context.message_block[t * 4 + 1] << 16) & 0xFFFFFFFF
      w[t] |= (context.message_block[t * 4 + 2] << 8) & 0xFFFFFFFF
      w[t] |= (context.message_block[t * 4 + 3]) & 0xFFFFFFFF
    for t in range(16, 80):
      w[t] = SHA1_Algo.circularShift(1, w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16])
    a, b, c, d, e = (context.intermediate_hash[0], context.intermediate_hash[1],
                     context.intermediate_hash[2], context.intermediate_hash[3],
                     context.intermediate_hash[4])
    for t in range(20):
      temp = (SHA1_Algo.circularShift(5, a) + ((b & c) | ((~b) & d)) + e + w[t] + k[0]) & 0xFFFFFFFF
      e, d, c, b, a = d, c, SHA1_Algo.circularShift(30, b), a, temp
    for t in range(20, 40):
      temp = (SHA1_Algo.circularShift(5, a) + (b ^ c ^ d) + e + w[t] + k[1]) & 0xFFFFFFFF
      e, d, c, b, a = d, c, SHA1_Algo.circularShift(30, b), a, temp     
    for t in range(40, 60):
      temp = (SHA1_Algo.circularShift(5, a) + ((b & c) | (b & d) | (c & d)) + e + w[t] + k[2]) & 0xFFFFFFFF
      e, d, c, b, a = d, c, SHA1_Algo.circularShift(30, b), a, temp
    for t in range(60, 80):
      temp = (SHA1_Algo.circularShift(5, a) + (b ^ c ^ d) + e + w[t] + k[3]) & 0xFFFFFFFF
      e, d, c, b, a = d, c, SHA1_Algo.circularShift(30, b), a, temp
    context.intermediate_hash[0] = (context.intermediate_hash[0] + a) & 0xFFFFFFFF
    context.intermediate_hash[1] = (context.intermediate_hash[1] + b) & 0xFFFFFFFF
    context.intermediate_hash[2] = (context.intermediate_hash[2] + c) & 0xFFFFFFFF
    context.intermediate_hash[3] = (context.intermediate_hash[3] + d) & 0xFFFFFFFF
    context.intermediate_hash[4] = (context.intermediate_hash[4] + e) & 0xFFFFFFFF
    context.message_block_index = 0
  def padMessage(context):
    context.message_block[context.message_block_index] = 0x80
    context.message_block_index += 1
    if context.message_block_index > 55:
      while context.message_block_index < 64:
        context.message_block[context.message_block_index] = 0
        context.message_block_index += 1
      SHA1_Algo.processMessageBlock(context)
    while context.message_block_index < 56:
      context.message_block[context.message_block_index] = 0
      context.message_block_index += 1
    context.message_block[56:60] = context.length_high.to_bytes(4, 'big')
    context.message_block[60:64] = context.length_low.to_bytes(4, 'big')
    SHA1_Algo.processMessageBlock(context)
  def result(context, message_digest):
    if context is None or message_digest is None: return SHA1_Algo.shaNull
    if context.corrupted != 0: return context.corrupted
    if context.computed == 0:
      SHA1_Algo.padMessage(context)
      for i in range(64): context.message_block[i] = 0
      context.length_low = 0
      context.length_high = 0
      context.computed = 1
    for i in range(SHA1_Algo.hashSize):
      message_digest[i] = (context.intermediate_hash[i >> 2] >> 8 * (3 - (i & 0x03))) & 0xFF
    return SHA1_Algo.shaSuccess
  def circularShift(bits, word):
    return ((word << bits) & 0xFFFFFFFF) | (word >> (32 - bits))
    
class MD4:
  def __init__(self):
    self.x = [0] * 16
    self.dontInit = False
    self._dontPad = False
    self._bigEndian = False
    self.initialize()
  def initFromHashLen(self, h, blocks):
    self.a = int.from_bytes(h[:4], 'little')
    self.b = int.from_bytes(h[4:8], 'little')
    self.c = int.from_bytes(h[8:12], 'little')
    self.d = int.from_bytes(h[12:], 'little')
    self.bytesProcessed = blocks * 64
    self.dontInit = True
  def pad(message_array, priorBlocks=0):
    r = len(message_array) % 64
    return message_array + bytes([0x80] + [0] * (55 - r)) + (len(message_array) * 8 + priorBlocks * 64 * 8).to_bytes(8, 'little')
  def initialize(self):
    if not self.dontInit:
      self.a = 0x67452301
      self.b = 0xefcdab89
      self.c = 0x98badcfe
      self.d = 0x10325476
      self.bytesProcessed = 0
    else: self.dontInit = False
  def computeHash(self, buffer):
    if buffer is None: return None
    self.hashCore(buffer, 0, len(buffer))
    res = self.hashFinal()
    self.initialize()
    return res
  def hashCore(self, array, offset, length):
    self.processMessage(array[offset:offset+length])
  def hashFinal(self):
    if not self._dontPad: self.processMessage(self.padding())
    res = self.a.to_bytes(4, 'big' if self._bigEndian else 'little') + self.b.to_bytes(4, 'big' if self._bigEndian else 'little') + self.c.to_bytes(4, 'big' if self._bigEndian else 'little') + self.d.to_bytes(4, 'big' if self._bigEndian else 'little')
    self.initialize()
    return res
  def processMessage(self, bytes):
    for b in bytes:
      c = self.bytesProcessed & 63
      i = c >> 2
      s = (c & 3) << 3
      self.x[i] = (self.x[i] & ~(255 << s)) | (b << s)
      if c == 63: self.process16WordBlock()
      self.bytesProcessed += 1
  def padding(self):
    return bytes([0x80] + [0] * (((self.bytesProcessed + 8) & 0x7fffffc0) + 55 - self.bytesProcessed)) + (self.bytesProcessed << 3).to_bytes(8, 'little' if self._bigEndian else 'little')
  def process16WordBlock(self):
    aa, bb, cc, dd = self.a, self.b, self.c, self.d
    for k in [0, 4, 8, 12]:
      aa = MD4.round1Operation(aa, bb, cc, dd, self.x[k], 3)
      dd = MD4.round1Operation(dd, aa, bb, cc, self.x[k + 1], 7)
      cc = MD4.round1Operation(cc, dd, aa, bb, self.x[k + 2], 11)
      bb = MD4.round1Operation(bb, cc, dd, aa, self.x[k + 3], 19)
    for k in [0, 1, 2, 3]:
      aa = MD4.round2Operation(aa, bb, cc, dd, self.x[k], 3)
      dd = MD4.round2Operation(dd, aa, bb, cc, self.x[k + 4], 5)
      cc = MD4.round2Operation(cc, dd, aa, bb, self.x[k + 8], 9)
      bb = MD4.round2Operation(bb, cc, dd, aa, self.x[k + 12], 13)      
    for k in [0, 2, 1, 3]:
      aa = MD4.round3Operation(aa, bb, cc, dd, self.x[k], 3)
      dd = MD4.round3Operation(dd, aa, bb, cc, self.x[k + 8], 9)
      cc = MD4.round3Operation(cc, dd, aa, bb, self.x[k + 4], 11)
      bb = MD4.round3Operation(bb, cc, dd, aa, self.x[k + 12], 15)
    self.a = (self.a + aa) & 0xFFFFFFFF
    self.b = (self.b + bb) & 0xFFFFFFFF
    self.c = (self.c + cc) & 0xFFFFFFFF
    self.d = (self.d + dd) & 0xFFFFFFFF
  def rol(value, numberOfBits):
    return ((value << numberOfBits) & 0xFFFFFFFF) | (value >> (32 - numberOfBits))
  def round1Operation(a, b, c, d, xk, s):
    return MD4.rol((a + ((b & c) | (~b & d)) + xk) & 0xFFFFFFFF, s)
  def round2Operation(a, b, c, d, xk, s):
    return MD4.rol((a + ((b & c) | (b & d) | (c & d)) + xk + 0x5a827999) & 0xFFFFFFFF, s)
  def round3Operation(a, b, c, d, xk, s):
    return MD4.rol((a + (b ^ c ^ d) + xk + 0x6ed9eba1) & 0xFFFFFFFF, s)
  def ror(value, numberOfBits):
    return (value >> numberOfBits) | ((value << (32 - numberOfBits)) & 0xFFFFFFFF)
  def unround1Operation(a, b, c, d, xk, s):
    return (MD4.ror(xk, s) - a - ((b & c) | (~b & d))) % 0x100000000
  def applyWangDifferential(bts):
    x = [0] * 16
    processed = 0
    for b in bts:
      i = processed >> 2
      s = (processed & 3) << 3
      x[i] = (x[i] & ~(255 << s)) | (b << s)
      if processed == 63: break
      processed += 1
    x[1] = (x[1] + (1 << 31)) & 0xFFFFFFFF
    x[2] = (x[2] + (1 << 31) - (1 << 28)) & 0xFFFFFFFF
    x[12] = (x[12] - (1 << 16)) & 0xFFFFFFFF
    return bytes([item for sublist in [y.to_bytes(4, 'little') for y in x] for item in sublist])
  def hasWangsConditions(x, bNaito, stage = 0):
    #stage 0 is first round, stages 1-7 around second round per modification variable, stage 8 is third round
    a0 = 0x67452301
    b0 = 0xefcdab89
    c0 = 0x98badcfe
    d0 = 0x10325476
    a1 = Round1Operation(a0, b0, c0, d0, x[0], 3)
    d1 = Round1Operation(d0, a1, b0, c0, x[1], 7)
    c1 = Round1Operation(c0, d1, a1, b0, x[2], 11)
    b1 = Round1Operation(b0, c1, d1, a1, x[3], 19)
    a2 = Round1Operation(a1, b1, c1, d1, x[4], 3)
    d2 = Round1Operation(d1, a2, b1, c1, x[5], 7)
    c2 = Round1Operation(c1, d2, a2, b1, x[6], 11)
    b2 = Round1Operation(b1, c2, d2, a2, x[7], 19)
    a3 = Round1Operation(a2, b2, c2, d2, x[8], 3)
    d3 = Round1Operation(d2, a3, b2, c2, x[9], 7)
    c3 = Round1Operation(c2, d3, a3, b2, x[10], 11)
    b3 = Round1Operation(b2, c3, d3, a3, x[11], 19)
    a4 = Round1Operation(a3, b3, c3, d3, x[12], 3)
    d4 = Round1Operation(d3, a4, b3, c3, x[13], 7)
    c4 = Round1Operation(c3, d4, a4, b3, x[14], 11)
    b4 = Round1Operation(b3, c4, d4, a4, x[15], 19)
    if (not (((a1 & (1 << 6)) == (b0 & (1 << 6))) and
        (d1 & (1 << 6)) == 0 and (d1 & (1 << 7)) == (a1 & (1 << 7)) and (d1 & (1 << 10)) == (a1 & (1 << 10)) and
        (c1 & (1 << 6)) != 0 and (c1 & (1 << 7)) != 0 and (c1 & (1 << 10)) == 0 and (c1 & (1 << 25)) == (d1 & (1 << 25)) and
        (b1 & (1 << 6)) != 0 and (b1 & (1 << 7)) == 0 and (b1 & (1 << 10)) == 0 and (b1 & (1 << 25)) == 0 and
        (a2 & (1 << 7)) != 0 and (a2 & (1 << 10)) != 0 and (a2 & (1 << 25)) == 0 and (a2 & (1 << 13)) == (b1 & (1 << 13)) and
        (d2 & (1 << 13)) == 0 and (d2 & (1 << 25)) != 0 and (d2 & (1 << 18)) == (a2 & (1 << 18)) and (d2 & (1 << 19)) == (a2 & (1 << 19)) and (d2 & (1 << 20)) == (a2 & (1 << 20)) and (d2 & (1 << 21)) == (a2 & (1 << 21)) and
        (c2 & (1 << 13)) == 0 and (c2 & (1 << 18)) == 0 and (c2 & (1 << 19)) == 0 and (c2 & (1 << 21)) == 0 and (c2 & (1 << 20)) != 0 and (c2 & (1 << 12)) == (d2 & (1 << 12)) and (c2 & (1 << 14)) == (d2 & (1 << 14)) and
        (b2 & (1 << 12)) != 0 and (b2 & (1 << 13)) != 0 and (b2 & (1 << 14)) == 0 and (b2 & (1 << 18)) == 0 and (b2 & (1 << 19)) == 0 and (b2 & (1 << 20)) == 0 and (b2 & (1 << 21)) == 0 and (b2 & (1 << 16)) == (c2 & (1 << 16)) and
        (a3 & (1 << 12)) != 0 and (a3 & (1 << 13)) != 0 and (a3 & (1 << 14)) != 0 and (a3 & (1 << 21)) != 0 and (a3 & (1 << 16)) == 0 and (a3 & (1 << 18)) == 0 and (a3 & (1 << 19)) == 0 and (a3 & (1 << 20)) == 0 and (a3 & (1 << 22)) == (b2 & (1 << 22)) and (a3 & (1 << 25)) == (b2 & (1 << 25)) and
        (d3 & (1 << 16)) == 0 and (d3 & (1 << 19)) == 0 and (d3 & (1 << 22)) == 0 and (d3 & (1 << 12)) != 0 and (d3 & (1 << 13)) != 0 and (d3 & (1 << 14)) != 0 and (d3 & (1 << 20)) != 0 and (d3 & (1 << 21)) != 0 and (d3 & (1 << 25)) != 0 and (d3 & (1 << 29)) == (a3 & (1 << 29)) and
        (c3 & (1 << 19)) == 0 and (c3 & (1 << 20)) == 0 and (c3 & (1 << 21)) == 0 and (c3 & (1 << 22)) == 0 and (c3 & (1 << 25)) == 0 and (c3 & (1 << 16)) != 0 and (c3 & (1 << 29)) != 0 and (c3 & (1 << 31)) == (d3 & (1 << 31)) and
        (b3 & (1 << 20)) != 0 and (b3 & (1 << 21)) != 0 and (b3 & (1 << 25)) != 0 and (b3 & (1 << 19)) == 0 and (b3 & (1 << 29)) == 0 and (b3 & (1 << 31)) == 0 and (b3 & (1 << 22)) == (c3 & (1 << 22)) and
        (a4 & (1 << 29)) != 0 and (a4 & (1 << 22)) == 0 and (a4 & (1 << 25)) == 0 and (a4 & (1 << 31)) == 0 and (a4 & (1 << 26)) == (b3 & (1 << 26)) and (a4 & (1 << 28)) == (b3 & (1 << 28)) and
        (d4 & (1 << 22)) == 0 and (d4 & (1 << 25)) == 0 and (d4 & (1 << 29)) == 0 and (d4 & (1 << 26)) != 0 and (d4 & (1 << 28)) != 0 and (d4 & (1 << 31)) != 0 and
        (c4 & (1 << 26)) == 0 and (c4 & (1 << 28)) == 0 and (c4 & (1 << 29)) == 0 and (c4 & (1 << 22)) != 0 and (c4 & (1 << 25)) != 0 and (c4 & (1 << 18)) == (d4 & (1 << 18)) and
        (b4 & (1 << 25)) != 0 and (b4 & (1 << 26)) != 0 and (b4 & (1 << 28)) != 0 and (b4 & (1 << 18)) == 0 and (b4 & (1 << 29)) == 0 and (b4 & (1 << 25)) == (c4 & (1 << 25)) and (not bNaito or (b4 & (1 << 31)) == (c4 & (1 << 31))))): return False
    if (stage == 0): return True
    a5 = Round2Operation(a4, b4, c4, d4, x[0], 3)
    d5 = Round2Operation(d4, a5, b4, c4, x[4], 5)
    c5 = Round2Operation(c4, d5, a5, b4, x[8], 9)
    b5 = Round2Operation(b4, c5, d5, a5, x[12], 13)
    a6 = Round2Operation(a5, b5, c5, d5, x[1], 3)
    d6 = Round2Operation(d5, a6, b5, c5, x[5], 5)
    c6 = Round2Operation(c5, d6, a6, b5, x[9], 9)
    b6 = Round2Operation(b5, c6, d6, a6, x[13], 13)
    a7 = Round2Operation(a6, b6, c6, d6, x[2], 3)
    d7 = Round2Operation(d6, a7, b6, c6, x[6], 5)
    c7 = Round2Operation(c6, d7, a7, b6, x[10], 9)
    b7 = Round2Operation(b6, c7, d7, a7, x[14], 13)
    a8 = Round2Operation(a7, b7, c7, d7, x[3], 3)
    d8 = Round2Operation(d7, a8, b7, c7, x[7], 5)
    c8 = Round2Operation(c7, d8, a8, b7, x[11], 9)
    b8 = Round2Operation(b7, c8, d8, a8, x[15], 13)
    if (not ((a5 & (1 << 18)) == (c4 & (1 << 18)) and (a5 & (1 << 25)) != 0 and (a5 & (1 << 28)) != 0 and (a5 & (1 << 31)) != 0 and (a5 & (1 << 26)) == 0 and (not bNaito or ((a5 & (1 << 19)) == (b4 & (1 << 19)) and (a5 & (1 << 21)) == (b4 & (1 << 21)))))): return False
    if (stage == 1): return True
    if (not ((d5 & (1 << 18)) == (a5 & (1 << 18)) and (d5 & (1 << 25)) == (b4 & (1 << 25)) and (d5 & (1 << 26)) == (b4 & (1 << 26)) and (d5 & (1 << 28)) == (b4 & (1 << 28)) and
                (d5 & (1 << 31)) == (b4 & (1 << 31)))): return False
    if (stage == 2): return True
    if (not ((c5 & (1 << 25)) == (d5 & (1 << 25)) and (c5 & (1 << 26)) == (d5 & (1 << 26)) and (c5 & (1 << 28)) == (d5 & (1 << 28)) and (c5 & (1 << 29)) == (d5 & (1 << 29)) and (c5 & (1 << 31)) == (d5 & (1 << 31)))): return False
    if (stage == 3): return True
    if (not ((b5 & (1 << 28)) == (c5 & (1 << 28)) and (b5 & (1 << 29)) != 0 and (b5 & (1 << 31)) == 0)): return False
    if (stage == 4): return True
    if (not ((a6 & (1 << 28)) != 0 and (not bNaito or (a6 & (1 << 29)) == 0) and (a6 & (1 << 31)) != 0)): return False
    if (stage == 5): return True
    if (not ((d6 & (1 << 28)) == (b5 & (1 << 28)))): return False
    if (stage == 6): return True
    if (not ((c6 & (1 << 28)) == (d6 & (1 << 28)) and (c6 & (1 << 29)) != (d6 & (1 << 29)) and (c6 & (1 << 31)) != (d6 & (1 << 31)))): return False
    if (stage == 7): return True
    a9 = Round3Operation(a8, b8, c8, d8, x[0], 3)
    d9 = Round3Operation(d8, a9, b8, c8, x[8], 9)
    c9 = Round3Operation(c8, d9, a9, b8, x[4], 11)
    b9 = Round3Operation(b8, c9, d9, a9, x[12], 15)
    a10 = Round3Operation(a9, b9, c9, d9, x[2], 3)
    return ((b9 & (1 << 31)) != 0 and (a10 & (1 << 31)) != 0)
  def verifyConditions2(x, a0, b0, c0, d0, a5, b5, c5, d5, a6, b6, c6, d6, a7, b7, c7, d7, a8, b8, c8, d8):
    a1 = Round1Operation(a0, b0, c0, d0, x[0], 3)
    d1 = Round1Operation(d0, a1, b0, c0, x[1], 7)
    c1 = Round1Operation(c0, d1, a1, b0, x[2], 11)
    b1 = Round1Operation(b0, c1, d1, a1, x[3], 19)
    a2 = Round1Operation(a1, b1, c1, d1, x[4], 3)
    d2 = Round1Operation(d1, a2, b1, c1, x[5], 7)
    c2 = Round1Operation(c1, d2, a2, b1, x[6], 11)
    b2 = Round1Operation(b1, c2, d2, a2, x[7], 19)
    a3 = Round1Operation(a2, b2, c2, d2, x[8], 3)
    d3 = Round1Operation(d2, a3, b2, c2, x[9], 7)
    c3 = Round1Operation(c2, d3, a3, b2, x[10], 11)
    b3 = Round1Operation(b2, c3, d3, a3, x[11], 19)
    a4 = Round1Operation(a3, b3, c3, d3, x[12], 3)
    d4 = Round1Operation(d3, a4, b3, c3, x[13], 7)
    c4 = Round1Operation(c3, d4, a4, b3, x[14], 11)
    b4 = Round1Operation(b3, c4, d4, a4, x[15], 19)
    return (a5 == Round2Operation(a4, b4, c4, d4, x[0], 3) and
        d5 == Round2Operation(d4, a5, b4, c4, x[4], 5) and
        c5 == Round2Operation(c4, d5, a5, b4, x[8], 9) and
        b5 == Round2Operation(b4, c5, d5, a5, x[12], 13) and
        a6 == Round2Operation(a5, b5, c5, d5, x[1], 3) and
        d6 == Round2Operation(d5, a6, b5, c5, x[5], 5) and
        c6 == Round2Operation(c5, d6, a6, b5, x[9], 9) and
        b6 == Round2Operation(b5, c6, d6, a6, x[13], 13) and
        a7 == Round2Operation(a6, b6, c6, d6, x[2], 3) and
        d7 == Round2Operation(d6, a7, b6, c6, x[6], 5) and
        c7 == Round2Operation(c6, d7, a7, b6, x[10], 9) and
        b7 == Round2Operation(b6, c7, d7, a7, x[14], 13) and
        a8 == Round2Operation(a7, b7, c7, d7, x[3], 3) and
        d8 == Round2Operation(d7, a8, b7, c7, x[7], 5) and
        c8 == Round2Operation(c7, d8, a8, b7, x[11], 9) and
        b8 == Round2Operation(b7, c8, d8, a8, x[15], 13))
  def VerifyConditions(x, a0, b0, c0, d0, a1, b1, c1, d1, a2, b2, c2, d2, a3, b3, c3, d3, a4, b4, c4, d4):
    return (a1 == Round1Operation(a0, b0, c0, d0, x[0], 3) and
        d1 == Round1Operation(d0, a1, b0, c0, x[1], 7) and
        c1 == Round1Operation(c0, d1, a1, b0, x[2], 11) and
        b1 == Round1Operation(b0, c1, d1, a1, x[3], 19) and
        a2 == Round1Operation(a1, b1, c1, d1, x[4], 3) and
        d2 == Round1Operation(d1, a2, b1, c1, x[5], 7) and
        c2 == Round1Operation(c1, d2, a2, b1, x[6], 11) and
        b2 == Round1Operation(b1, c2, d2, a2, x[7], 19) and
        a3 == Round1Operation(a2, b2, c2, d2, x[8], 3) and
        d3 == Round1Operation(d2, a3, b2, c2, x[9], 7) and
        c3 == Round1Operation(c2, d3, a3, b2, x[10], 11) and
        b3 == Round1Operation(b2, c3, d3, a3, x[11], 19) and
        a4 == Round1Operation(a3, b3, c3, d3, x[12], 3) and
        d4 == Round1Operation(d3, a4, b3, c3, x[13], 7) and
        c4 == Round1Operation(c3, d4, a4, b3, x[14], 11) and
        b4 == Round1Operation(b3, c4, d4, a4, x[15], 19))
  def wangsAttack(bts, bMulti, bNaito):
    #Naito et al. improvements: Add two sufficient conditions b4,32 = c4,32 and a6,30 = 0 probability 1/4
    #Change the modification method of d5,19 so that both of d5,19 = a5,19 and c5,26 = d5,26 can be corrected probability 7/8
    #wrong correction of c5,29 probability 1/2
    #Change the modification method of c5,32 so that both of c5,32 = d5,32 and c6,32 = d6,32 + 1 can be corrected probability 3/4
    #satisfying condition in 3rd round probability 1/4
    x = [0] * 16
    processed = 0
    #padding can be added for short messages...
    #Enumerable.Repeat((byte)128, 1)
    #.Concat(Enumerable.Repeat((byte)0, (int)(((_bytesProcessed + 8) & 0x7fffffc0) + 55 - _bytesProcessed)))
    #.Concat(BitConverter.GetBytes((ulong)(_bytesProcessed << 3)))
    for b in bts:
      i = processed >> 2
      s = (processed & 3) << 3
      x[i] = (x[i] & ~(255 << s)) | (b << s)
      if (processed == 63): break
      processed += 1
    
    #step 1 - weak message - single step rules 2^25
    a0 = 0x67452301
    b0 = 0xefcdab89
    c0 = 0x98badcfe
    d0 = 0x10325476

    #a1,7 = b0,7
    a1 = MD4.round1Operation(a0, b0, c0, d0, x[0], 3)
    a1 ^= (a1 & (1 << 6)) ^ (b0 & (1 << 6))
    #extra condition to allow correcting d5,19 in 2nd round
    if (bMulti and bNaito): a1 ^= (a1 & (1 << 13)) ^ (b0 & (1 << 13))
    x[0] = MD4.unround1Operation(a0, b0, c0, d0, a1, 3)

    #d1,7 = 0, d1,8 = a1,8, d1,11 = a1,11
    d1 = MD4.round1Operation(d0, a1, b0, c0, x[1], 7)
    d1 &= ~(1 << 6)
    d1 ^= (d1 & (1 << 7)) ^ (a1 & (1 << 7)) ^ (d1 & (1 << 10)) ^ (a1 & (1 << 10))
    #extra condition to allow correcting d5,19 in 2nd round
    if (bMulti and bNaito): d1 &= ~(1 << 13)
    x[1] = MD4.unround1Operation(d0, a1, b0, c0, d1, 7)

    #c1,7 = 1, c1,8 = 1, c1,11 = 0, c1,26 = d1,26
    c1 = MD4.round1Operation(c0, d1, a1, b0, x[2], 11)
    c1 |= (1 << 6) | (1 << 7)
    c1 &= ~(1 << 10)
    c1 ^= (c1 & (1 << 25)) ^ (d1 & (1 << 25))
    #extra condition to allow correcting d5,19 in 2nd round
    if (bMulti and bNaito): c1 &= ~(1 << 13)
    x[2] = MD4.unround1Operation(c0, d1, a1, b0, c1, 11)

    #b1,7 = 1, b1,8 = 0, b1,11 = 0, b1,26 = 0
    b1 = MD4.round1Operation(b0, c1, d1, a1, x[3], 19)
    b1 |= (1 << 6)
    b1 &= ~((1 << 7) | (1 << 10) | (1 << 25))
    #extra condition to allow correcting d5,19 in 2nd round
    if (bMulti and bNaito): b1 &= ~(1 << 13)
    #extra condition to allow correcting a6,29, a6,30, a6,32 in 2nd round
    if (bMulti): b1 |= (1 << 0) | ((1 << 1) if bNaito else 0) | (1 << 3)
    x[3] = MD4.unround1Operation(b0, c1, d1, a1, b1, 19)

    #a2,8 = 1, a2,11 = 1, a2,26 = 0, a2,14 = b1,14
    a2 = MD4.round1Operation(a1, b1, c1, d1, x[4], 3)
    a2 |= (1 << 7) | (1 << 10)
    a2 &= ~(1 << 25)
    a2 ^= (a2 & (1 << 13)) ^ (b1 & (1 << 13))
    #extra condition to allow correcting c5,26, c5,27, c5,29, c5,31 in 2nd round
    if (bMulti): a2 ^= (a2 & (1 << (25 - 9))) ^ (b1 & (1 << (25 - 9))) ^ (a2 & (1 << (26 - 9))) ^ (b1 & (1 << (26 - 9))) ^ ((a2 & (1 << (30 - 9))) ^ (b1 & (1 << (30 - 9))) if bNaito else (a2 & (1 << (28 - 9))) ^ (b1 & (1 << (28 - 9))) ^ (a2 & (1 << (31 - 9))) ^ (b1 & (1 << (31 - 9))))
    x[4] = MD4.unround1Operation(a1, b1, c1, d1, a2, 3)

    #d2,14 = 0, d2,19 = a2,19, d2,20 = a2,20, d2,21 = a2,21, d2,22 = a2,22, d2,26 = 1
    d2 = MD4.round1Operation(d1, a2, b1, c1, x[5], 7)
    d2 &= ~(1 << 13)
    d2 |= (1 << 25)
    d2 ^= (d2 & (1 << 18)) ^ (a2 & (1 << 18)) ^ (d2 & (1 << 19)) ^ (a2 & (1 << 19)) ^ (d2 & (1 << 20)) ^ (a2 & (1 << 20)) ^ (d2 & (1 << 21)) ^ (a2 & (1 << 21))
    #extra condition to allow correcting c5,26, c5,27, c5,29, c5,31 in 2nd round
    #(d2 & (1 << 19)) ^ (a2 & (1 << 19)) conflicts with (1 << (28 - 9))
    #if (bMulti) d2 &= ~((1 << (25 - 9)) | (1 << (26 - 9)) | (0 if bNaito else (1 << (28 - 9)) | (1 << (31 - 9))))
    if (bMulti): d2 &= ~((1 << (25 - 9)) | (1 << (26 - 9)) | (0 if bNaito else (1 << (31 - 9))))
    #extra condition to allow correcting c6,32 in 2nd round
    #(1 << (31 - 9)) conflicts with (d2 & (1 << 22)) ^ (a2 & (1 << 22))
    #unfortunately not knowing whether to correct for c5,32 or d2,32 makes a 3/8 chance of failure not 1/4 because of the additional case of when d2,23!=a2,23
    if (bMulti and bNaito): d2 ^= (d2 & (1 << 22)) ^ (a2 & (1 << 22))
    x[5] = MD4.unround1Operation(d1, a2, b1, c1, d2, 7)

    #c2,13 = d2,13, c2,14 = 0, c2,15 = d2,15, c2,19 = 0, c2,20 = 0, c2,21 = 1, c2,22 = 0
    c2 = MD4.round1Operation(c1, d2, a2, b1, x[6], 11)
    c2 &= ~((1 << 13) | (1 << 18) | (1 << 19) | (1 << 21))
    c2 |= (1 << 20)
    c2 ^= (c2 & (1 << 12)) ^ (d2 & (1 << 12)) ^ (c2 & (1 << 14)) ^ (d2 & (1 << 14))
    #extra condition to allow correcting c5,26, c5,27, c5,29, c5,31 in 2nd round
    if (bMulti): c2 &= ~((1 << (25 - 9)) | (1 << (26 - 9)) | (0 if bNaito else (1 << (28 - 9)) | (1 << (31 - 9))))
    #extra condition to allow correcting c6,32 in 2nd round
    if (bMulti): c2 &= ~(1 << 22)
    x[6] = MD4.unround1Operation(c1, d2, a2, b1, c2, 11)

    #b2,13 = 1, b2,14 = 1, b2,15 = 0, b2,17 = c2,17, b2,19 = 0, b2,20 = 0, b2,21 = 0, b2,22 = 0
    b2 = MD4.round1Operation(b1, c2, d2, a2, x[7], 19)
    b2 |= (1 << 12) | (1 << 13)
    b2 &= ~((1 << 14) | (1 << 18) | (1 << 19) | (1 << 20) | (1 << 21))
    b2 ^= (b2 & (1 << 16)) ^ (c2 & (1 << 16))
    #extra condition to allow correcting c5,26, c5,27, c5,29, c5,31 in 2nd round
    #(b2 & (1 << 16)) ^ (c2 & (1 << 16)) conflicts with (1 << (25 - 9))
    if (bMulti): b2 &= ~((1 << (25 - 9)) | (1 << (26 - 9)) | (0 if bNaito else (1 << (28 - 9)) | (1 << (31 - 9))))
    #extra condition to allow correcting d6,29 in 2nd round
    if (bMulti): b2 |= (1 << 30)
    #extra condition to allow correcting c6,32 in 2nd round
    if (bMulti): b2 &= ~(1 << 22)
    x[7] = MD4.unround1Operation(b1, c2, d2, a2, b2, 19)

    #a3,13 = 1, a3,14 = 1, a3,15 = 1, a3,17 = 0, a3,19 = 0, a3,20 = 0, a3,21 = 0, a3,23 = b2,23, a3,22 = 1, a3,26 = b2,26
    a3 = MD4.round1Operation(a2, b2, c2, d2, x[8], 3)
    a3 |= (1 << 12) | (1 << 13) | (1 << 14) | (1 << 21)
    a3 &= ~((1 << 16) | (1 << 18) | (1 << 19) | (1 << 20))
    a3 ^= (a3 & (1 << 22)) ^ (b2 & (1 << 22)) ^ (a3 & (1 << 25)) ^ (b2 & (1 << 25))
    x[8] = MD4.unround1Operation(a2, b2, c2, d2, a3, 3)

    #d3,13 = 1, d3,14 = 1, d3,15 = 1, d3,17 = 0, d3,20 = 0, d3,21 = 1, d3,22 = 1, d3,23 = 0, d3,26 = 1, d3,30 = a3,30
    d3 = MD4.round1Operation(d2, a3, b2, c2, x[9], 7)
    d3 &= ~((1 << 16) | (1 << 19) | (1 << 22))
    d3 |= (1 << 12) | (1 << 13) | (1 << 14) | (1 << 20 | (1 << 21) | (1 << 25))
    d3 ^= (d3 & (1 << 29)) ^ (a3 & (1 << 29))
    #extra condition to allow correcting b5,29, b5,32 in 2nd round
    if (bMulti): d3 ^= (d3 & (1 << 15)) ^ (a3 & (1 << 15)) ^ (d3 & (1 << 18)) ^ (a3 & (1 << 18))
    x[9] = MD4.unround1Operation(d2, a3, b2, c2, d3, 7)

    #c3,17 = 1, c3,20 = 0, c3,21 = 0, c3,22 = 0, c3,23 = 0, c3,26 = 0, c3,30 = 1, c3,32 = d3,32
    c3 = MD4.round1Operation(c2, d3, a3, b2, x[10], 11)
    c3 &= ~((1 << 19) | (1 << 20) | (1 << 21) | (1 << 22) | (1 << 25))
    c3 |= (1 << 16) | (1 << 29)
    c3 ^= (c3 & (1 << 31)) ^ (d3 & (1 << 31))
    #extra condition to allow correcting b5,29, b5,32 in 2nd round
    if (bMulti): c3 &= ~((1 << 15) | (1 << 18))
    #extra conditions to allow 3rd round corrections in x[11]
    if (bMulti and bNaito): c3 ^= ((c3 & (1 << 0)) ^ (c3 & (1 << 1)) ^ (c3 & (1 << 2)) ^ (c3 & (1 << 3)) ^ (c3 & (1 << 4)) ^ (c3 & (1 << 5)) ^ (c3 & (1 << 6)) ^ (c3 & (1 << 7)) ^ (c3 & (1 << 8)) ^ (c3 & (1 << 9)) ^ (c3 & (1 << 10)) ^ (c3 & (1 << 11)) ^ (c3 & (1 << 12)) ^ (c3 & (1 << 13)) ^ (c3 & (1 << 14)) ^ (c3 & (1 << 17)) ^ (c3 & (1 << 23)) ^ (c3 & (1 << 24)) ^ (c3 & (1 << 30)) ^
                                (d3 & (1 << 0)) ^ (d3 & (1 << 1)) ^ (d3 & (1 << 2)) ^ (d3 & (1 << 3)) ^ (d3 & (1 << 4)) ^ (d3 & (1 << 5)) ^ (d3 & (1 << 6)) ^ (d3 & (1 << 7)) ^ (d3 & (1 << 8)) ^ (d3 & (1 << 9)) ^ (d3 & (1 << 10)) ^ (d3 & (1 << 11)) ^ (d3 & (1 << 12)) ^ (d3 & (1 << 13)) ^ (d3 & (1 << 14)) ^ (d3 & (1 << 17)) ^ (d3 & (1 << 23)) ^ (d3 & (1 << 24)) ^ (d3 & (1 << 30)))
    x[10] = MD4.unround1Operation(c2, d3, a3, b2, c3, 11)

    #b3 uses 7 + 5 = 12 not 13 but b3,29 comes from a4,29 and d4,29 - b3,16, b3,17, b3,19, b3,20, b3,21, b3,22, b3,23, b3,26, b3,27, b3,28, b3,29, b3,30, b3,32
    #b3,20 = 0, b3,21 = 1, b3,22 = 1, b3,23 = c3,23, b3,26 = 1, b3,30 = 0, b3,32 = 0
    b3 = MD4.round1Operation(b2, c3, d3, a3, x[11], 19)
    b3 |= (1 << 20) | (1 << 21) | (1 << 25)
    b3 &= ~((1 << 19) | (1 << 29) | (1 << 31))
    b3 ^= (b3 & (1 << 22)) ^ (c3 & (1 << 22))
    #extra condition to allow correcting b5,29, b5,32 in 2nd round
    if (bMulti): b3 |= (1 << 15) | (1 << 18)
    #extra condition to allow correcting b5,30 in 2nd round
    if (bMulti): b3 &= ~(1 << 16)
    #extra condition to allow correcting c6,29, c6,30 in 2nd round
    if (bMulti): b3 |= (1 << 26) | (1 << 27)
    x[11] = MD4.unround1Operation(b2, c3, d3, a3, b3, 19)

    #a4,23 = 0, a4,26 = 0, a4,27 = b3,27, a4,29 = b3,29, a4,30 = 1, a4,32 = 0
    a4 = MD4.round1Operation(a3, b3, c3, d3, x[12], 3)
    a4 |= (1 << 29)
    a4 &= ~((1 << 22) | (1 << 25) | (1 << 31))
    a4 ^= (a4 & (1 << 26)) ^ (b3 & (1 << 26)) ^ (a4 & (1 << 28)) ^ (b3 & (1 << 28))
    #extra condition to allow correcting b5,29, b5,32 in 2nd round
    if (bMulti): a4 |= (1 << 15) | (1 << 18)
    #extra condition to allow correcting b5,30 in 2nd round
    if (bMulti): a4 &= ~(1 << 16)
    #extra conditions to allow 3rd round corrections in x[11]
    if (bMulti and bNaito): a4 &= ~((1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 8) | (1 << 9) | (1 << 10) | (1 << 11) | (1 << 12) | (1 << 13) | (1 << 14) | (1 << 17) | (1 << 23) | (1 << 24) | (1 << 30))
    x[12] = MD4.unround1Operation(a3, b3, c3, d3, a4, 3)

    #d4,23 = 0, d4,26 = 0, d4,27 = 1, d4,29 = 1, d4,30 = 0, d4,32 = 1
    d4 = MD4.round1Operation(d3, a4, b3, c3, x[13], 7)
    d4 &= ~((1 << 22) | (1 << 25) | (1 << 29))
    d4 |= (1 << 26) | (1 << 28) | (1 << 31)
    #extra condition to allow correcting c5,29, c5,32 in 2nd round
    if (bMulti and bNaito): d4 ^= (d4 & (1 << 19)) ^ (a4 & (1 << 19)) ^ (d4 & (1 << 21)) ^ (a4 & (1 << 21))
    #extra condition to allow correcting b5,30 in 2nd round
    if (bMulti): d4 |= (1 << 16)
    #extra conditions to allow 3rd round corrections in x[11]
    #if (bMulti and bNaito) d4 &= ~((1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 8) | (1 << 9) | (1 << 10) | (1 << 11) | (1 << 12) | (1 << 13) | (1 << 14) | (1 << 17) | (1 << 23) | (1 << 24) | (1 << 30))
    if (bMulti and bNaito): d4 |= ((1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 8) | (1 << 9) | (1 << 10) | (1 << 11) | (1 << 12) | (1 << 13) | (1 << 14) | (1 << 17) | (1 << 23) | (1 << 24) | (1 << 30))
    x[13] = MD4.unround1Operation(d3, a4, b3, c3, d4, 7)

    #c4,19 = d4,19, c4,23 = 1, c4,26 = 1, c4,27 = 0, c4,29 = 0, c4,30 = 0
    c4 = MD4.round1Operation(c3, d4, a4, b3, x[14], 11)
    c4 &= ~((1 << 26) | (1 << 28) | (1 << 29))
    c4 |= (1 << 22) | (1 << 25)
    c4 ^= (c4 & (1 << 18)) ^ (d4 & (1 << 18))
    #extra condition to allow correcting c5,29, c5,32 in 2nd round
    if (bMulti and bNaito): c4 &= ~((1 << 19) | (1 << 21))
    x[14] = MD4.unround1Operation(c3, d4, a4, b3, c4, 11)

    #b4,19 = 0, b4,26 = c4,26 = 1, b4,27 = 1, b4,29 = 1, b4,30 = 0
    b4 = MD4.round1Operation(b3, c4, d4, a4, x[15], 19)
    b4 |= (1 << 25) | (1 << 26) | (1 << 28)
    b4 &= ~((1 << 18) | (1 << 29))
    b4 ^= (b4 & (1 << 25)) ^ (c4 & (1 << 25))
    #newly discovered condition: b4,32 = c4,32
    if (bNaito): b4 ^= (b4 & (1 << 31)) ^ (c4 & (1 << 31))
    #extra condition to allow correcting c5,29, c5,32 in 2nd round
    if (bMulti and bNaito): b4 ^= (b4 & (1 << 19)) ^ (d4 & (1 << 19)) ^ (b4 & (1 << 21)) ^ (d4 & (1 << 21))
    x[15] = MD4.unround1Operation(b3, c4, d4, a4, b4, 19)
    #if (not MD4.verifyConditions(x, a0, b0, c0, d0, a1, b1, c1, d1, a2, b2, c2, d2, a3, b3, c3, d3, a4, b4, c4, d4, bMulti, bNaito)):
    #  raise ValueError

    if (not bMulti):
      return bytes([item for sublist in [y.to_bytes(4, 'little') for y in x] for item in sublist])

    #round/step 2 and 3 - multi-step modification
    #must not "stomp" on the first round conditions
    saveX = x[:]
    n = 0
    while True:
      if (not bNaito and n != 0):
        #return None
        x = saveX[:]
        a1 = MD4.round1Operation(a0, b0, c0, d0, x[0], 3)
        d1 = MD4.round1Operation(d0, a1, b0, c0, x[1], 7)
        c1 = MD4.round1Operation(c0, d1, a1, b0, x[2], 11)
        b1 = MD4.round1Operation(b0, c1, d1, a1, x[3], 19)
        a2 = MD4.round1Operation(a1, b1, c1, d1, x[4], 3)
        d2 = MD4.round1Operation(d1, a2, b1, c1, x[5], 7)
        c2 = MD4.round1Operation(c1, d2, a2, b1, x[6], 11)
        b2 = MD4.round1Operation(b1, c2, d2, a2, x[7], 19)
        a3 = MD4.round1Operation(a2, b2, c2, d2, x[8], 3)
        d3 = MD4.round1Operation(d2, a3, b2, c2, x[9], 7)
        c3 = MD4.round1Operation(c2, d3, a3, b2, x[10], 11)
        b3 = MD4.round1Operation(b2, c3, d3, a3, x[11], 19)
        a4 = MD4.round1Operation(a3, b3, c3, d3, x[12], 3)
        d4 = MD4.round1Operation(d3, a4, b3, c3, x[13], 7)
        x[14] ^= (n & 0xFFFFFFFF)
        x[15] ^= (n >> 32) #deliberate as we need to try to solve b4 condition without waiting 0xFFFFFFFF iterations
        #c4,19 = d4,19, c4,23 = 1, c4,26 = 1, c4,27 = 0, c4,29 = 0, c4,30 = 0
        c4 = MD4.round1Operation(c3, d4, a4, b3, x[14], 11)
        c4 &= ~((1 << 26) | (1 << 28) | (1 << 29))
        c4 |= (1 << 22) | (1 << 25)
        c4 ^= (c4 & (1 << 18)) ^ (d4 & (1 << 18))
        #extra condition to allow correcting c5,29, c5,32 in 2nd round
        #if (bMulti and bNaito) c4 &= ~((1 << 19) | (1 << 21))
        x[14] = MD4.unround1Operation(c3, d4, a4, b3, c4, 11)

        #b4,19 = 0, b4,26 = c4,26 = 1, b4,27 = 1, b4,29 = 1, b4,30 = 0
        b4 = MD4.round1Operation(b3, c4, d4, a4, x[15], 19)
        b4 |= (1 << 25) | (1 << 26) | (1 << 28)
        b4 &= ~((1 << 18) | (1 << 29))
        b4 ^= (b4 & (1 << 25)) ^ (c4 & (1 << 25))
        #newly discovered condition: b4,32 = c4,32
        #if (bNaito) b4 ^= (b4 & (1 << 31)) ^ (c4 & (1 << 31))
        #extra condition to allow correcting c5,29, c5,32 in 2nd round
        #if (bMulti and bNaito): b4 ^= (b4 & (1 << 19)) ^ (d4 & (1 << 19)) ^ (b4 & (1 << 21)) ^ (d4 & (1 << 21))
        x[15] = MD4.unround1Operation(b3, c4, d4, a4, b4, 19)
        #if (not MD4.verifyConditions(x, a0, b0, c0, d0, a1, b1, c1, d1, a2, b2, c2, d2, a3, b3, c3, d3, a4, b4, c4, d4, bMulti, bNaito)):
        #  raise ValueError
      if (not bNaito):
        n += 1
        if (n == 0): return None #nothing found after 2^64 search...
      #a5,19 = c4,19, a5,26 = 1, a5,27 = 0, a5,29 = 1, a5,32 = 1
      #must do these in exact order as arithmetic over and underflows must be handled
      a5 = MD4.round2Operation(a4, b4, c4, d4, x[0], 3)
      #d5 = MD4.round2Operation(d4, a5, b4, c4, x[4], 5)
      #c5 = MD4.round2Operation(c4, d5, a5, b4, x[8], 9)
      #b5 = MD4.round2Operation(b4, c5, d5, a5, x[12], 13)
      #a6 = MD4.round2Operation(a5, b5, c5, d5, x[1], 3)
      #d6 = MD4.round2Operation(d5, a6, b5, c5, x[5], 5)
      #c6 = MD4.round2Operation(c5, d6, a6, b5, x[9], 9)
      #b6 = MD4.round2Operation(b5, c6, d6, a6, x[13], 13)
      #a7 = MD4.round2Operation(a6, b6, c6, d6, x[2], 3)
      #d7 = MD4.round2Operation(d6, a7, b6, c6, x[6], 5)
      #c7 = MD4.round2Operation(c6, d7, a7, b6, x[10], 9)
      #b7 = MD4.round2Operation(b6, c7, d7, a7, x[14], 13)
      #a8 = MD4.round2Operation(a7, b7, c7, d7, x[3], 3)
      #d8 = MD4.round2Operation(d7, a8, b7, c7, x[7], 5)
      #c8 = MD4.round2Operation(c7, d8, a8, b7, x[11], 9)
      #b8 = MD4.round2Operation(b7, c8, d8, a8, x[15], 13)

      a5mods = [18, 19, 21, 25, 26, 28, 31] if bNaito else [18, 25, 26, 28, 31]
      for i in a5mods:
        if (i == 18 and (a5 & (1 << 18)) == (c4 & (1 << 18)) or
            i == 19 and (a5 & (1 << 19)) == (b4 & (1 << 19)) or #extra conditions to allow correcting c5,29, c5,32
            i == 21 and (a5 & (1 << 21)) == (b4 & (1 << 21)) or
            i == 25 and (a5 & (1 << 25)) != 0 or
            i == 26 and (a5 & (1 << 26)) == 0 or
            i == 28 and (a5 & (1 << 28)) != 0 or
            i == 31 and (a5 & (1 << 31)) != 0): continue
        x[0] = (x[0] + (1 << (i - 3)) if ((a1 & (1 << i)) == 0) else x[0] - (1 << (i - 3))) % 0x100000000
        a1 = MD4.round1Operation(a0, b0, c0, d0, x[0], 3)
        x[1] = MD4.unround1Operation(d0, a1, b0, c0, d1, 7)
        x[2] = MD4.unround1Operation(c0, d1, a1, b0, c1, 11)
        x[3] = MD4.unround1Operation(b0, c1, d1, a1, b1, 19)
        x[4] = MD4.unround1Operation(a1, b1, c1, d1, a2, 3)
        a5 = MD4.round2Operation(a4, b4, c4, d4, x[0], 3)
        #if (not MD4.verifyConditions(x, a0, b0, c0, d0, a1, b1, c1, d1, a2, b2, c2, d2, a3, b3, c3, d3, a4, b4, c4, d4, bMulti, bNaito)):
        #  raise ValueError
      #if (not MD4.verifyConditions2(x, a0, b0, c0, d0, a5, b5, c5, d5, a6, b6, c6, d6, a7, b7, c7, d7, a8, b8, c8, d8, bNaito, 1)):
      #  raise ValueError

      #d5,19 = a5,19, d5,26 = b4,26, d5,27 = b4,27, d5,29 = b4,29, d5,32 = b4,32
      d5 = MD4.round2Operation(d4, a5, b4, c4, x[4], 5)
      d5mods = [18, 25, 26, 28, 31]
      for i in d5mods:
        if (i == 18 and (d5 & (1 << 18)) == (a5 & (1 << 18)) or
            i == 25 and (d5 & (1 << 25)) == (b4 & (1 << 25)) or
            i == 26 and (d5 & (1 << 26)) == (b4 & (1 << 26)) or
            i == 28 and (d5 & (1 << 28)) == (b4 & (1 << 28)) or
            i == 31 and (d5 & (1 << 31)) == (b4 & (1 << 31))): continue
        if (bNaito and i == 18):
          #if (not ((d1 & (1 << 13)) == 0 and (a1 & (1 << 13)) == (b0 & (1 << 13)) and (c1 & (1 << 13)) == 0 and (b1 & (1 << 13)) == 0)):
          #  raise ValueError
          x[1] = (x[1] + (1 << 6) if (d1 & (1 << 13)) == 0 else x[1] - (1 << 6)) % 0x100000000
          d1 = MD4.round1Operation(d0, a1, b0, c0, x[1], 7)
          x[4] = (x[4] - (1 << 13)) % 0x100000000
          x[5] = (x[5] - (1 << 13)) % 0x100000000
        else:
          x[4] = (x[4] + (1 << (i - 5)) if ((a2 & (1 << (i - 2))) == 0) else x[4] - (1 << (i - 5))) % 0x100000000
          a2 = MD4.round1Operation(a1, b1, c1, d1, x[4], 3)
          x[5] = MD4.unround1Operation(d1, a2, b1, c1, d2, 7)
          x[6] = MD4.unround1Operation(c1, d2, a2, b1, c2, 11)
          x[7] = MD4.unround1Operation(b1, c2, d2, a2, b2, 19)
          x[8] = MD4.unround1Operation(a2, b2, c2, d2, a3, 3)
        d5 = MD4.round2Operation(d4, a5, b4, c4, x[4], 5)
        #if (not MD4.verifyConditions(x, a0, b0, c0, d0, a1, b1, c1, d1, a2, b2, c2, d2, a3, b3, c3, d3, a4, b4, c4, d4, bMulti, bNaito)):
        #  raise ValueError
      #if (not MD4.verifyConditions2(x, a0, b0, c0, d0, a5, b5, c5, d5, a6, b6, c6, d6, a7, b7, c7, d7, a8, b8, c8, d8, bNaito, 2)):
      #  raise ValueError

      #c5,26 = d5,26, c5,27 = d5,27, c5,29 = d5,29, c5,30 = d5,30, c5,32 = d5,32
      c5 = MD4.round2Operation(c4, d5, a5, b4, x[8], 9)
      c5mods = [25, 26, 28, 29, 30, 31] if bNaito else [25, 26, 28, 29, 31]
      #bContinue = False
      for i in c5mods:
        if (i == 25 and (c5 & (1 << 25)) == (d5 & (1 << 25)) or
            i == 26 and (c5 & (1 << 26)) == (d5 & (1 << 26)) or
            i == 28 and (c5 & (1 << 28)) == (d5 & (1 << 28)) or
            i == 29 and (c5 & (1 << 29)) == (d5 & (1 << 29)) or
            i == 30 and (c5 & (1 << 30)) != 0 or
            i == 31 and (c5 & (1 << 31)) == (d5 & (1 << 31))): continue
        if (i == 29 or i == 30):
          x[8] = (x[8] + (1 << (i - 9)) if ((a3 & (1 << (i - 6))) == 0) else x[8] - (1 << (i - 9))) % 0x100000000
          a3 = MD4.round1Operation(a2, b2, c2, d2, x[8], 3)
          x[9] = MD4.unround1Operation(d2, a3, b2, c2, d3, 7)
          x[10] = MD4.unround1Operation(c2, d3, a3, b2, c3, 11)
          x[11] = MD4.unround1Operation(b2, c3, d3, a3, b3, 19)
          x[12] = MD4.unround1Operation(a3, b3, c3, d3, a4, 3)
        elif ((i == 28 or i == 31) and bNaito):
          #if (i == 28 and not ((c4 & (1 << (i - 9))) == 0 and (d4 & (1 << (i - 9))) == (a4 & (1 << (i - 9))) and (b4 & (1 << (i - 9))) == (d4 & (1 << (i - 9))))):
          #  raise ValueError
          #if (i == 31 and not ((c4 & (1 << (i - 10))) == 0 and (d4 & (1 << (i - 10))) == (a4 & (1 << (i - 10))) and (b4 & (1 << (i - 10))) == (d4 & (1 << (i - 10))))):
          #  raise ValueError
          if (i == 28): x[14] = (x[14] + (1 << (i - 20))) & 0xFFFFFFFF
          else: x[14] = (x[14] + (1 << (i - 21))) & 0xFFFFFFFF
          c4 = MD4.round1Operation(c3, d4, a4, b3, x[14], 11)
          c5 = MD4.round2Operation(c4, d5, a5, b4, x[8], 9)
        else:
          #if (not ((not bNaito and i == 28 or (d2 & (1 << (i - 9))) == 0) and (not bNaito and i == 25 or (a2 & (1 << (i - 9))) == (b1 & (1 << (i - 9)))) and (c2 & (1 << (i - 9))) == 0 and (b2 & (1 << (i - 9))) == 0)):
          #  raise ValueError
          if (not bNaito and i == 28): #c5,29 can break a first round condition and will never succeed if it occurs
            return None
            #bContinue = True
            #break
          x[5] = (x[5] + (1 << (i - 16))) & 0xFFFFFFFF
          #x[5] = (d2 & (1 << (i - 9))) == 0 ? x[5] + (1 << (i - 16)) : x[5] - (1 << (i - 16))
          #x[8] = (d2 & (1 << (i - 9))) == 0 ? x[8] - (1 << (i - 9)) : x[8] + (1 << (i - 9))
          #x[9] = (d2 & (1 << (i - 9))) == 0 ? x[9] - (1 << (i - 9)) : x[9] + (1 << (i - 9))
          d2 = MD4.round1Operation(d1, a2, b1, c1, x[5], 7)
          x[8] = (x[8] - (1 << (i - 9))) % 0x100000000
          x[9] = (x[9] - (1 << (i - 9))) % 0x100000000
          #if i == 25 and d5,19 was corrected, then c2 is broken and c2 != Round1Operation(c1, d2, a2, b1, x[6], 11)
          if (not bNaito and i == 25 and c2 != MD4.round1Operation(c1, d2, a2, b1, x[6], 11)): #not ((a2 & (1 << (i - 9))) == (b1 & (1 << (i - 9))))
            #probability 1/8 that we have to abort and no forgery can be found using Wang's method
            #however if d6,26 is additionally corrected then c2 will be fixed even though Wang did not mention this
            x[6] = MD4.unround1Operation(c1, d2, a2, b1, c2, 11)
            c2 = MD4.round1Operation(c1, d2, a2, b1, x[6], 11)
        c5 = MD4.round2Operation(c4, d5, a5, b4, x[8], 9)
        #if (not MD4.verifyConditions(x, a0, b0, c0, d0, a1, b1, c1, d1, a2, b2, c2, d2, a3, b3, c3, d3, a4, b4, c4, d4, bMulti, bNaito)):
        #  raise ValueError
      #if (bContinue): continue
      #c5,26 when not equal to d5,19 and c5,29 are stomping on first round conditions and must have more modifications to correct
      #if (not MD4.verifyConditions2(x, a0, b0, c0, d0, a5, b5, c5, d5, a6, b6, c6, d6, a7, b7, c7, d7, a8, b8, c8, d8, bNaito, 3)):
      #  raise ValueError

      #b5,29 = c5,29, b5,30 = 1, b5,32 = 0
      b5 = MD4.round2Operation(b4, c5, d5, a5, x[12], 13)
      b5mods = [28, 29, 31]
      for i in b5mods:
        if (i == 28 and (b5 & (1 << 28)) == (c5 & (1 << 28)) or
            i == 29 and (b5 & (1 << 29)) != 0 or
            i == 31 and (b5 & (1 << 31)) == 0): continue
        if (i == 29):
          #if (not ((b3 & (1 << 16)) == 0 and (a4 & (1 << 16)) == 0 and (d4 & (1 << 16)) != 0)):
          #  raise ValueError
          x[11] = (x[11] + (1 << 29)) & 0xFFFFFFFF
          #x[11] = (b3 & (1 << 16)) == 0 ? x[11] + (1 << 29) : x[11] - (1 << 29)
          #x[12] = (b3 & (1 << 16)) == 0 ? x[12] - (1 << 16) : x[12] + (1 << 16)
          #x[15] = (b3 & (1 << 16)) == 0 ? x[15] - (1 << 16) : x[15] + (1 << 16)
          b3 = MD4.round1Operation(b2, c3, d3, a3, x[11], 19)
          x[12] = (x[12] - (1 << 16)) % 0x100000000
          x[15] = (x[15] - (1 << 16)) % 0x100000000
        else:
          #if (not ((c3 & (1 << (i - 13))) == 0 and (d3 & (1 << (i - 13))) == (a3 & (1 << (i - 13))) and (b3 & (1 << (i - 13))) != 0 and (a4 & (1 << (i - 13))) != 0)):
          #  raise ValueError
          x[10] = (x[10] + (1 << (i - 24))) & 0xFFFFFFFF
          #x[10] = (c3 & (1 << (i - 13))) == 0 ? x[10] + (1 << (i - 24)) : x[10] - (1 << (i - 24))
          #x[12] = (c3 & (1 << (i - 13))) == 0 ? x[12] - (1 << (i - 13)) : x[12] + (1 << (i - 13))
          #x[14] = (c3 & (1 << (i - 13))) == 0 ? x[14] - (1 << (i - 13)) : x[14] + (1 << (i - 13))
          c3 = MD4.round1Operation(c2, d3, a3, b2, x[10], 11)
          x[12] = (x[12] - (1 << (i - 13))) % 0x100000000
          x[14] = (x[14] - (1 << (i - 13))) % 0x100000000
        b5 = MD4.round2Operation(b4, c5, d5, a5, x[12], 13)
        #if (not MD4.verifyConditions(x, a0, b0, c0, d0, a1, b1, c1, d1, a2, b2, c2, d2, a3, b3, c3, d3, a4, b4, c4, d4, bMulti, bNaito)):
        #  raise ValueError
      #if (not MD4.verifyConditions2(x, a0, b0, c0, d0, a5, b5, c5, d5, a6, b6, c6, d6, a7, b7, c7, d7, a8, b8, c8, d8, bNaito, 4)):
      #  raise ValueError

      #a6,29 = 1, a6,32 = 1
      #newly discovered condition: a6,30 = 0
      a6 = MD4.round2Operation(a5, b5, c5, d5, x[1], 3)
      a6mods = [28, 29, 31] if bNaito else [28, 31]
      for i in a6mods:
        if (i == 28 and (a6 & (1 << 28)) != 0 or
            i == 29 and (a6 & (1 << 29)) == 0 or
            i == 31 and (a6 & (1 << 31)) != 0): continue
        #if (not ((b1 & (1 << ((i + 4) % 32))) != 0)):
        #  raise ValueError
        x[1] = (x[1] + (1 << (i - 3)) if ((d1 & (1 << ((i + 4) % 32))) == 0) else x[1] - (1 << (i - 3))) % 0x100000000
        d1 = MD4.round1Operation(d0, a1, b0, c0, x[1], 7)
        x[2] = MD4.unround1Operation(c0, d1, a1, b0, c1, 11)
        x[3] = MD4.unround1Operation(b0, c1, d1, a1, b1, 19)
        x[5] = MD4.unround1Operation(d1, a2, b1, c1, d2, 7)
        a6 = MD4.round2Operation(a5, b5, c5, d5, x[1], 3)
        #if (not MD4.verifyConditions(x, a0, b0, c0, d0, a1, b1, c1, d1, a2, b2, c2, d2, a3, b3, c3, d3, a4, b4, c4, d4, bMulti, bNaito)):
        #  raise ValueError
      #if (not MD4.verifyConditions2(x, a0, b0, c0, d0, a5, b5, c5, d5, a6, b6, c6, d6, a7, b7, c7, d7, a8, b8, c8, d8, bNaito, 5)):
      #  raise ValueError

      #d6,29 = b5,29
      d6 = MD4.round2Operation(d5, a6, b5, c5, x[5], 5)
      if ((d6 & (1 << 28)) != (b5 & (1 << 28))):
        #if (not ((b2 & (1 << 30)) != 0)):
        #  raise ValueError
        x[5] = (x[5] + (1 << 23) if ((d2 & (1 << 30)) == 0) else x[5] - (1 << 23)) % 0x100000000
        d2 = MD4.round1Operation(d1, a2, b1, c1, x[5], 7)
        d6 = MD4.round2Operation(d5, a6, b5, c5, x[5], 5)
        x[6] = MD4.unround1Operation(c1, d2, a2, b1, c2, 11)
        x[7] = MD4.unround1Operation(b1, c2, d2, a2, b2, 19)
        x[9] = MD4.unround1Operation(d2, a3, b2, c2, d3, 7)
      #if (not MD4.verifyConditions(x, a0, b0, c0, d0, a1, b1, c1, d1, a2, b2, c2, d2, a3, b3, c3, d3, a4, b4, c4, d4, bMulti, bNaito)):
      #  raise ValueError
      #if (not MD4.verifyConditions2(x, a0, b0, c0, d0, a5, b5, c5, d5, a6, b6, c6, d6, a7, b7, c7, d7, a8, b8, c8, d8, bNaito, 6)):
      #  raise ValueError

      #c6,29 = d6,29, c6,30 = d6,30 + 1, c6,32 = d6,32 + 1
      c6 = MD4.round2Operation(c5, d6, a6, b5, x[9], 9)
      c6mods = [28, 29]
      for i in c6mods:
        if (i == 28 and (c6 & (1 << 28)) == (d6 & (1 << 28)) or
            i == 29 and (c6 & (1 << 29)) != (d6 & (1 << 29))): continue
        #if (not ((b3 & (1 << (i - 2))) != 0)):
        #  raise ValueError
        x[9] = (x[9] + (1 << (i - 9)) if ((d3 & (1 << (i - 2))) == 0) else x[9] - (1 << (i - 9))) % 0x100000000
        d3 = MD4.round1Operation(d2, a3, b2, c2, x[9], 7)
        x[10] = MD4.unround1Operation(c2, d3, a3, b2, c3, 11)
        x[11] = MD4.unround1Operation(b2, c3, d3, a3, b3, 19)
        x[13] = MD4.unround1Operation(d3, a4, b3, c3, d4, 7)
        c6 = MD4.round2Operation(c5, d6, a6, b5, x[9], 9)
        #if (not MD4.verifyConditions(x, a0, b0, c0, d0, a1, b1, c1, d1, a2, b2, c2, d2, a3, b3, c3, d3, a4, b4, c4, d4, bMulti, bNaito)):
        #  raise ValueError
      if ((c6 & (1 << 31)) == (d6 & (1 << 31))):
        #if (not ((c2 & (1 << 22)) == 0 and (not bNaito or (d2 & (1 << 22)) == (a2 & (1 << 22))) and (b2 & (1 << 22)) == 0)):
        #  raise ValueError
        if (not bNaito and not ((d2 & (1 << 22)) == (a2 & (1 << 22)))):
          #if c5,32 and c6,32 are both corrected, an error will occur need to detect and return...
          return None
          #continue
        x[6] = (x[6] + (1 << 11) if (c2 & (1 << 22)) == 0 else x[6] - (1 << 11)) % 0x100000000
        c2 = MD4.round1Operation(c1, d2, a2, b1, x[6], 11)
        x[9] = (x[9] - (1 << 22)) % 0x100000000
        c6 = MD4.round2Operation(c5, d6, a6, b5, x[9], 9)
        x[10] = (x[10] - (1 << 22)) % 0x100000000
      #if (not MD4.verifyConditions(x, a0, b0, c0, d0, a1, b1, c1, d1, a2, b2, c2, d2, a3, b3, c3, d3, a4, b4, c4, d4, bMulti, bNaito)):
      #  raise ValueError

      b6 = MD4.round2Operation(b5, c6, d6, a6, x[13], 13)
      a7 = MD4.round2Operation(a6, b6, c6, d6, x[2], 3)
      d7 = MD4.round2Operation(d6, a7, b6, c6, x[6], 5)
      c7 = MD4.round2Operation(c6, d7, a7, b6, x[10], 9)
      b7 = MD4.round2Operation(b6, c7, d7, a7, x[14], 13)
      a8 = MD4.round2Operation(a7, b7, c7, d7, x[3], 3)
      d8 = MD4.round2Operation(d7, a8, b7, c7, x[7], 5)
      c8 = MD4.round2Operation(c7, d8, a8, b7, x[11], 9)
      b8 = MD4.round2Operation(b7, c8, d8, a8, x[15], 13)
      a9 = MD4.round3Operation(a8, b8, c8, d8, x[0], 3)
      d9 = MD4.round3Operation(d8, a9, b8, c8, x[8], 9)
      c9 = MD4.round3Operation(c8, d9, a9, b8, x[4], 11)
      b9 = MD4.round3Operation(b8, c9, d9, a9, x[12], 15)
      a10 = MD4.round3Operation(a9, b9, c9, d9, x[2], 3)
      #if (not MD4.verifyConditions2(x, a0, b0, c0, d0, a5, b5, c5, d5, a6, b6, c6, d6, a7, b7, c7, d7, a8, b8, c8, d8, bNaito, 7)):
      #  raise ValueError

      if ((bNaito or (b4 & (1 << 31)) == (c4 & (1 << 31)) and ((a6 & (1 << 29)) == 0)) and ((b9 & (1 << 31)) != 0 and (a10 & (1 << 31)) != 0)):
        return bytes([item for sublist in [y.to_bytes(4, 'little') for y in x] for item in sublist])
      if bNaito: break
    if bNaito:
      #...round 3 modifications for exact collision not known how to hold without stomping on rounds 1 and 2
      #for all values except b3,20, b3,21, b3,22, b3,23, b3,26, b3,27, b3,28, b3,29, b3,30, b3,32 + b3,16, b3,17, b3,19
      #cannot stomp on these first round bit positions either: 10, 12, 29 + 7, 9, 10, 28, 31 + 0, 3, 7, 9, 12, 29
      permutebits = [4, 5, 11, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 30] #b3 free bit indexes: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 17, 23, 24, 30]
      b3save, x11save, x15save = b3, x[11], x[15]
      #if (not ((c3 & ((1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 8) | (1 << 9) | (1 << 10) | (1 << 11) | (1 << 12) | (1 << 13) | (1 << 14) | (1 << 17) | (1 << 23) | (1 << 24) | (1 << 30))) ==
      #     (d3 & ((1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 8) | (1 << 9) | (1 << 10) | (1 << 11) | (1 << 12) | (1 << 13) | (1 << 14) | (1 << 17) | (1 << 23) | (1 << 24) | (1 << 30))) and
      #     (a4 & ((1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 8) | (1 << 9) | (1 << 10) | (1 << 11) | (1 << 12) | (1 << 13) | (1 << 14) | (1 << 17) | (1 << 23) | (1 << 24) | (1 << 30))) == 0 and
      #     (d4 & ((1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 8) | (1 << 9) | (1 << 10) | (1 << 11) | (1 << 12) | (1 << 13) | (1 << 14) | (1 << 17) | (1 << 23) | (1 << 24) | (1 << 30))) != 0)):
      #  raise ValueError
      for i in range(1, 1 << 19):
        for c in range(19):
          if ((i & (1 << c)) != 0):
            #if (not ((c3 & (1 << ((19 + permutebits[c]) % 32))) == (d3 & (1 << ((19 + permutebits[c]) % 32))) and (a4 & (1 << ((19 + permutebits[c]) % 32))) == 0 and (d4 & (1 << ((19 + permutebits[c]) % 32))) != 0)):
            #  raise ValueError
            x[11] = (x[11] + (1 << (permutebits[c])) if (b3 & (1 << ((19 + permutebits[c]) % 32))) == 0 else x[11] - (1 << (permutebits[c]))) % 0x100000000
            b3 = MD4.round1Operation(b2, c3, d3, a3, x[11], 19)
            #c4 = ROL(c3 + ((d4 & a4) | (~d4 & b3)) + x[14], 11) //d4 should be set not unset like the paper shows or this will fail
            #c4 = Round1Operation(c3, d4, a4, b3, x[14], 11)
            x[15] = MD4.unround1Operation(b3, c4, d4, a4, b4, 19)
        c8 = MD4.round2Operation(c7, d8, a8, b7, x[11], 9)
        b8 = MD4.round2Operation(b7, c8, d8, a8, x[15], 13)
        #if (not MD4.verifyConditions(x, a0, b0, c0, d0, a1, b1, c1, d1, a2, b2, c2, d2, a3, b3, c3, d3, a4, b4, c4, d4, bMulti, bNaito) or
        #    not MD4.verifyConditions2(x, a0, b0, c0, d0, a5, b5, c5, d5, a6, b6, c6, d6, a7, b7, c7, d7, a8, b8, c8, d8, bNaito, 7)):
        #  raise ValueError
        a9 = MD4.round3Operation(a8, b8, c8, d8, x[0], 3)
        d9 = MD4.round3Operation(d8, a9, b8, c8, x[8], 9)
        c9 = MD4.round3Operation(c8, d9, a9, b8, x[4], 11)
        #b9,32 = 1
        b9 = MD4.round3Operation(b8, c9, d9, a9, x[12], 15)
        #a10,32 = 1
        a10 = MD4.round3Operation(a9, b9, c9, d9, x[2], 3)
        if (((b9 & (1 << 31)) != 0 and (a10 & (1 << 31)) != 0)):
          return bytes([item for sublist in [y.to_bytes(4, 'little') for y in x] for item in sublist])
        b3 = b3save
        x[11] = x11save
        x[15] = x15save
    return None

#RFC 2104 HMAC(k,m)=H((K' xor opad) || H((K' xor ipad) || m))
def hmac(key, message):
  import hashlib
  sha1 = hashlib.sha1()
  if len(key) > 64:
    sha1.update(key)
    key = m.digest()
  else:
    key = bytearray(key)
    key.extend(bytearray(64 - len(key)))
  sha1 = hashlib.sha1()
  sha1.update(bytearray([a ^ 0x36 for a in key]) + message)
  b = sha1.digest()
  sha1 = hashlib.sha1()
  sha1.update(bytearray([a ^ 0x5C for a in key]) + b)
  return b

def posRemainder(dividend, divisor):
  if (dividend >= 0 and dividend < divisor): return dividend
  r = dividend % divisor
  return r + divisor if r < 0 else r

#Extended Euclid GCD of 1
def modInverse(a, n):
  i, v, d = n, 0, 1
  if (a < 0): a = a % n
  while (a > 0):
    t, x = i // a, a;
    a = i % x
    i = x
    x = d
    d = v - t * x
    v = x
  v %= n
  if (v < 0): v = (v + n) % n
  return v

def kangF(y, k):
  return 1 << (y % k)
  
def pollardKangaroo(a, b, k, g, p, y):
  xT = 0
  yT = pow(g, b, p)
  #N is then derived from f -take the mean of all possible outputs of f and multiply it by a small constant, e.g. 4.
  #N = (1 << (k >> 1)) * 4
  N = ((1 << (k + 1)) - 1) * 4 // k
  #make the constant bigger to better your chances of finding a collision at the(obvious) cost of extra computation.
  for i in range(1, N + 1):
    KF = kangF(yT, k) % p
    xT = xT + KF
    yT = (yT * pow(g, KF, p)) % p
  #now yT = g^(b + xT)
  #print("yT = " + HexEncode(yT.ToByteArray()) + " g^(b + xT) = " + HexEncode(pow(g, b + xT, p).ToByteArray()));
  xW = 0
  yW = y
  while (xW < (b - a + xT)):
    KF = kangF(yW, k) % p
    xW = xW + KF
    yW = (yW * pow(g, KF, p)) % p
    if (yW == yT):
      return b + xT - xW
  return 0
  
def getBitSize(num): return num.bit_length()
def isSqrt(n, root):
  lowerBound = root * root
  return n >= lowerBound and n <= lowerBound + root + root
def sqrt(n):
  if (n == 0): return 0
  if (n > 0):
    bitLength = getBitSize(n)
    root = 1 << (bitLength >> 1)
    while not isSqrt(n, root):
      root += n // root
      root >>= 1
    return root
  return float('nan') #raise ArithmeticException("NaN")
def isPrime(n):
  mx = sqrt(n)
  for i in range(2, mx + 1):
    if (n % i == 0): return False
  return True
  
def nextPrime(n):
  if (n == 2): return 3
  while True:
    n += 2;
    if isPrime(n): break
  return n
def getPrimes(n): #sieve of Eratosthenes
  a = [False] * (n - 2 + 1)
  mx = sqrt(n)
  for i in range(2, mx + 1):
    if (not a[i - 2]):
      for j in range(i * i, n + 1, i):
        a[j - 2] = True
  return list(filter(lambda x: x != -1, [i + 2 if not b else -1 for i, b in enumerate(a)]))

def addPolyRing(a, b, gf):
  alen, blen = len(a), len(b)
  c = [0] * max(alen, blen)
  clen = len(c)
  for i in range(0, clen):
    aoffs, boffs, coffs = alen - 1 - i, blen - 1 - i, clen - 1 - i
    if (i >= alen): c[coffs] = b[boffs]
    elif (i >= blen): c[coffs] = a[aoffs]
    elif (a[aoffs] >= 0 and a[aoffs] < gf and b[boffs] >= 0 and b[boffs] >= 0 and b[boffs] < gf):
      c[coffs] = a[aoffs] + b[boffs]
      if (c[coffs] >= gf): c[coffs] -= gf
    else: c[coffs] = posRemainder(a[aoffs] + b[boffs], gf)
  import itertools
  return c if clen == 0 or c[0] != 0 else list(itertools.dropwhile(lambda cr: cr == 0, c))

def combineBigIntegers(nums, bits):
  nlen = len(nums)
  b = new byte[((nums.Length * bits + 7) >> 3) + (((nums.Length * bits) & 7) == 0 ? 1 : 0)] #+1 for avoiding negatives
  curBit = 0
  for i in range(nlen):
    curByte, bit = curBit >> 3, curBit & 7
    if (bit != 0):
      byte[] src = (nums[i] << bit).ToByteArray()
      b[curByte] |= src[0]
      Array.Copy(src, 1, b, curByte + 1, src.Length - 1)
    else:
      byte[] src = nums[i].ToByteArray()
      Array.Copy(src, 0, b, curByte, src.Length)
    curBit += bits
  return b

def multiSplitBigInteger(num, bits, size):
  c = [0] * size
  if (bits == 0): return c #impossible split size
  bytes = num.to_bytes((num.bit_length() + 7) // 8, byteorder='little')
  blen = len(bytes)
  if (blen == 0): return c
  curbits, count, startByte = 0, 0, 0
  while (count < size):
    lastByte = (curbits + bits + 7) >> 3
    rembits = (curbits + bits) & 7
    if (blen < lastByte): lastByte, rembits = blen, 0
    taken = bytearray(lastByte - startByte + (1 if (bytes[lastByte - 1] & 0x80) != 0 else 0))
    Array.Copy(bytes, startByte, taken, 0, lastByte - startByte)
    if (rembits != 0): taken[lastByte - startByte - 1] &= ((1 << rembits) - 1)
    if ((curbits & 7) != 0): c[count] = new BigInteger(taken) >> (curbits & 7);
    else: c[count] = new BigInteger(taken);
    if (blen < (curbits + bits + 7) >> 3): break
    startByte = lastByte - (1 if rembits != 0 else 0)
    curbits += bits
    count += 1
  return c
  
def mulKaratsuba(num1, num2, num1bits, num2bits):
  m = min(num1bits, num2bits)
  m2 = m >> 1
  m2shift = (1 << m2) - 1
  low1 = num1 & m2shift
  low2 = num2 & m2shift
  high1 = num1 >> m2
  high2 = num2 >> m2
  z0 = doBigMul(low1, low2, m2, m2)
  lowhigh1, lowhigh2 = low1 + high1, low2 + high2
  z1 = doBigMul(lowhigh1, lowhigh2, num1bits - m2 + 1, num2bits - m2 + 1)
  z2 = doBigMul(high1, high2, num1bits - m2, num2bits - m2)
  return ((z2 << (m2 << 1)) | z0) + ((z1 - z0 - z2) << m2)

def doBigMul(num1, num2, num1bits, num2bits):
  if (num1 <= 0xFFFFFFFF and num2 <= 0xFFFFFFFF):
    return num1 * num2
  if (num1 <= 0xFFFFFFFF or num2 <= 0xFFFFFFFF or
      num1bits <= 4096 or num2bits <= 4096): return num1 * num2; #experimentally determined threshold 8192 is next best
                                                                #if (num1bits >= 1728 * 64 && num2bits >= 1728 * 64)
                                                                #return mulSchonhageStrassen(num1, num2, num1bits, num2bits)
  return mulKaratsuba(num1, num2, num1bits, num2bits)

def bigMul(num1, num2):
  signum = (-1 if num1 < 0 else 1) * (-1 if num2 < 0 else 1)
  if (num1 < 0): num1 = -num1
  if (num2 < 0): num2 = -num2
  res = doBigMul(num1, num2, getBitSize(num1), getBitSize(num2))
  return -res if signum < 0 else res

#Kronecker substitution
#https://en.wikipedia.org/wiki/Kronecker_substitution
#https://web.maths.unsw.edu.au/~davidharvey/talks/kronecker-talk.pdf
def mulPolyRingKronecker(a, b, gf):
  alen, blen = len(a), len(b)
  packSize = (getBitSize(gf) << 1) + getBitSize(max(alen, blen)) #coefficients are bounded by 2^(2*GetBitSize(GF))*n where n is degree+1 of A, B
  #evaluate at 2^(2*getBitSize(gf)+UpperBound(log2(n)))
  Apack = combineBigIntegers(list(reversed([posRemainder(nm, GF) if nm < 0 else nm for nm in a])), packSize)
  Bpack = combineBigIntegers(list(reversed([posRemainder(nm, GF) if nm < 0 else nm for nm in b])), packSize);
  Cpack = doBigMul(Apack, Bpack, packSize * alen, packSize * blen);
  p = reversed([posRemainder(nm, GF) for nm in multiSplitBigInteger(Cpack, packSize, alen + blen - 1)])
  import itertools
  return list(itertools.dropwhile(lambda c: c == 0, p))

def mulPolyRing(a, b, gf):
  alen, blen = len(a), len(b)
  if (getBitSize(gf) * min(alen, blen) > 16384): return mulPolyRingKronecker(a, b, gf)
  if (alen == 0): return a
  if (blen == 0): return b
  p = [0] * (alen + blen - 1)
  for i in range(0, blen):
    if (b[i] == 0): continue
    for j in range(0, alen):
      if (a[j] == 0): continue
      ijoffs = i + j
      #if (posRemainder(a[j] * b[i], gf) != posRemainder(mulKaratsuba(A[j] < 0 ? posRemainder(A[j], GF) : A[j], B[i] < 0 ? posRemainder(B[i], GF) : B[i]), GF)) throw new ArgumentException();
      #p[ijoffs] += posRemainder(mulKaratsuba(A[j] < 0 ? posRemainder(A[j], GF) : A[j], B[i] < 0 ? posRemainder(B[i], GF) : B[i]), GF);
      #p[ijoffs] += modmul(a[j], b[i], gf)
      #p[ijoffs] += posRemainder(a[j] * b[i], gf)
      #if (p[ijoffs] >= GF) p[ijoffs] -= gf
      if (b[i] == -1): p[ijoffs] += (gf - a[j])
      elif (a[j] == -1): p[ijoffs] += (gf - b[i])
      else: p[ijoffs] += a[j] * b[i]
  #while (not all([c == 0 for c in a])):
  #  if (a[0] != 0): p = posRemainder(p + b, gf)
  #  a, b = a[1:], b + [0]
  #if (mulPolyRingKronecker(A, B, GF) != [posRemainder(x, gf) for x in itertools.dropwhile(lambda c: c == 0, p)]):
  #  raise ValueError
  #return p if len(p) == 0 or p[0] != 0 else list(itertools.dropwhile(lambda c: c == 0, p))
  import itertools
  return [posRemainder(x, gf) for x in itertools.dropwhile(lambda c: c == 0, p)]

#https://en.wikipedia.org/wiki/Polynomial_long_division#Pseudo-code
def divmodPolyRing(a, b, gf):
  #if (len(b) == 0) raise ValueError
  alen, blen = len(a), len(b)
  q, r = [0] * alen, a
  binv = modInverse(b[0], gf)
  bneg = mulPolyRing(b, [-1], gf)
  rlen = len(r)
  d = (rlen - 1) - (blen - 1)
  while (rlen != 0 and d >= 0):
    aoffs = alen - d - 1
    q[aoffs] = posRemainder(r[0] * binv, gf)
    if (q[aoffs] == 0): break
    #r = addPolyRing(r, mulPolyRing(bneg, q[aoffs:], gf), gf)
    r = addPolyRing(r, mulPolyRing(bneg, [q[aoffs]], gf) + q[aoffs+1:], gf)
    rlen = len(r)
    d = (rlen - 1) - (blen - 1)
  import itertools
  return list(itertools.dropwhile(lambda c: c == 0, q)), r

#https://github.com/sagemath/sage/blob/master/src/sage/libs/ntl/ntlwrap_impl.h
#https://github.com/sagemath/sage/blob/develop/src/sage/rings/polynomial/polynomial_quotient_ring_element.py
#https://github.com/sagemath/sage/blob/develop/src/sage/rings/polynomial/polynomial_quotient_ring.py
def remainderPolyRingSparsePow2(a, b, gf):
  #note that (B%2^p)*(B%2^(p-1))=B%2^(2p-1)
  #NTL in lzz_pX for integer field univariate polynomial implements rem with rem21 using the FFT method
  #however in this case we can just do the classic modular exponentiation which works in log n and always keeps a reduced polynomial
  m = len(b) - 1
  remainder = [0] * m #m-1 terms
  for elem in a:
    exp = elem[0]
    result = [1]
    bmul = [1, 0]
    while (exp > 0):
      if ((exp & 1) == 1):
        result = divmodPolyRing(mulPolyRing(result, bmul, gf), b, gf)[1]
      exp >>= 1
      bmul = divmodPolyRing(mulPolyRing(bmul, bmul, gf), b, gf)[1]
    result = mulPolyRing(result, [elem[1]], gf)
    remainder = addPolyRing(result, remainder, gf)
  import itertools
  return list(itertools.dropwhile(lambda c: c == 0, remainder))

def substitutePolyRing(a, b, divpoly, gf):
  result = [0]
  alen = len(a)
  for i in range(alen):
    if (i == alen - 1):
      result = addPolyRing(result, [a[i]], gf)
    else:
      result = addPolyRing(result, mulPolyRing(modexpPolyRing(b, alen - i - 1, divpoly, gf), [A[i]], gf), gf)
  return result

#https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Pseudocode
#https://en.wikipedia.org/wiki/Polynomial_greatest_common_divisor#Bézout's_identity_and_extended_GCD_algorithm
def gcdPolyRing(a, b, gf):
  r, ro = a, b
  s, so = [0], [1]
  t, to = [1], [0]
  while (len(r) != 0):
    if (r[0] != 1):
      #must be monic or division will not be correct!
      multiplier = modInverse(r[0], gf)
      r = mulPolyRing(r, [multiplier], gf)
    quot = mulPolyRing(divmodPolyRing(ro, r, gf)[0], [-1], gf)
    swap = ro
    ro, r = r, addPolyRing(swap, mulPolyRing(quot, r, gf), gf)
    swap = so
    so, s = s, addPolyRing(swap, mulPolyRing(quot, s, gf), gf)
    swap = to
    to, t = t, addPolyRing(swap, mulPolyRing(quot, t, gf), gf)
  return ro

#Extended Euclid GCD of 1
def modInversePolyRing(a, n, gf):
  i, v, d = n, [0], [1]
  while (len(a) > 0):
    t, x = divmodPolyRing(i, a, gf)[0], a
    a = divmodPolyRing(i, x, gf)[1]
    i = x
    x = d
    d = addPolyRing(v, mulPolyRing(mulPolyRing(t, x, gf), [-1], gf), gf)
    v = x
  if (len(i) > 1): return None #no modular inverse exists if degree more than 0...
  v = mulPolyRing([modInverse(i[0], gf)], v, gf)
  v = divmodPolyRing(v, n, gf)[1]
  #if (v < 0): v = (v + n) % n
  return v

def modexpPolyRing(x, m, f, gf):
  d = [1]
  bs = getBitSize(m)
  for i in range(bs, 0, -1):
    if (((1 << (bs - i)) & m) != 0):
      d = divmodPolyRing(mulPolyRing(d, x, gf), f, gf)[1]
    x = divmodPolyRing(mulPolyRing(x, x, gf), f, gf)[1]
  return d

def invertECPolyRing(p, gf):
  return (p[0], mulPolyRing(p[1], [-1], gf))

def addECPolyRing(p1, p2, a, gf, divpoly, f):
  o = ([0], [1])
  if (p1[0] == o[0] and p1[1] == o[1]): return p2
  if (p2[0] == o[0] and p2[1] == o[1]): return p1
  inv = invertECPolyRing(p2, gf)
  if (p1[0] == inv[0] and p1[1] == inv[1]): return ([0], [1])
  x1, y1, x2, y2 = p1[0], p1[1], p2[0], p2[1]
  if (p1[0] == p2[0] and p1[1] == p2[1]):
    factor = divmodPolyRing(mulPolyRing(mulPolyRing([2], y1, gf), f, gf), divpoly, gf)[1]
    div = modInversePolyRing(factor, divpoly, gf)
    if (div is None): return (None, factor)
    m = divmodPolyRing(mulPolyRing(addPolyRing(mulPolyRing([3], mulPolyRing(x1, x1, gf), gf), [a], gf), div, gf), divpoly, gf)[1]
  else:
    factor = divmodPolyRing(addPolyRing(x2, mulPolyRing(x1, [-1], gf), gf), divpoly, gf)[1]
    div = modInversePolyRing(factor, divpoly, gf)
    if (div is None): return (None, factor)
    m = divmodPolyRing(mulPolyRing(addPolyRing(y2, mulPolyRing(y1, [-1], gf), gf), div, gf), divpoly, gf)[1]
  x3 = divmodPolyRing(addPolyRing(addPolyRing(mulPolyRing(f, mulPolyRing(m, m, gf), gf), mulPolyRing(x1, [-1], gf), gf), mulPolyRing(x2, [-1], gf), gf), divpoly, gf)[1]
  return (x3, divmodPolyRing(addPolyRing(mulPolyRing(m, addPolyRing(x1, mulPolyRing(x3, [-1], gf), gf), gf), mulPolyRing(y1, [-1], gf), gf), divpoly, gf)[1])

def scaleECPolyRing(x, k, a, gf, divpoly, f):
  result = ([0], [1])
  while (k > 0):
    if (k & 1) != 0:
      result = addECPolyRing(result, x, a, gf, divpoly, f)
      if (result[0] is None): return result #division by zero case
    x = addECPolyRing(x, x, a, gf, divpoly, f)
    if (x[0] is None): return x #division by zero case
    k = k >> 1
  return result

def scaleECDivPoly(x, k, gf, divpolys, divpoly, f):
  ysub = mulPolyRing(f, [4], gf) #2*y or 4*y^2 really
  num = mulPolyRing(mulPolyRing(divpolys[k + 1], divpolys[k - 1], gf), [-1], gf)
  ynum = divpolys[2 * k] #this is even so need to divide out a y...
  denom = mulPolyRing(divpolys[k], divpolys[k], gf)
  ydenom = mulPolyRing(mulPolyRing(denom, denom, gf), [2], gf)
  if ((k & 1) != 0):
    num = divmodPolyRing(num, ysub, GF)[0]
  else:
    denom = divmodPolyRing(denom, ysub, GF)[0]
    ydenom = divmodPolyRing(ydenom, mulPolyRing(ysub, ysub, GF), GF)[0]
  modinv = modInversePolyRing(denom, divpoly, gf)
  rx = addPolyRing([1, 0], num if modinv is None else divmodPolyRing(mulPolyRing(num, modinv, gf), divpoly, gf)[1], gf)
  ymodinv = modInversePolyRing(divmodPolyRing(ydenom, divpoly, GF)[1], divpoly, GF);
  ry = ynum if ymodinv is None else divmodPolyRing(mulPolyRing(ynum, ymodinv, gf), divpoly, gf)[1] #this likely needs a modInverse to make the y coefficient in the numerator
  yinv = modInversePolyRing(divmodPolyRing(mulPolyRing(f, mulPolyRing(x[1], [2], gf), gf), divpoly, gf)[1], divpoly, gf) #divide by y
  #yinv = modInversePolyRing(ysub, divpoly, gf) #divide by y
  return (substitutePolyRing(rx, x[0], divpoly, gf), divmodPolyRing(mulPolyRing(substitutePolyRing(ry, x[0], divpoly, gf), yinv, gf), divpoly, gf)[1])

def getDivPolys(curDivPolys, l, ea, eb, f, gf):
  ysub = mulPolyRing([2], f, gf)
  #ysquared = mulPolyRing(ysub, ysub, gf)
  b6sqr = mulPolyRing([2 * 2], mulPolyRing(ysub, ysub, gf), gf)
  #b6sqrinv = modInverse(2 * 2 * y * y * 2 * 2 * y * y, gf); //(4y^2)^2
  divPolys = [[0], [1], mulPolyRing([2], ysub, gf),
    [3, 0, 6 * ea, 12 * eb, -ea * ea], #-ea * ea, 12 * eb, 6 * ea, 0, 3
      mulPolyRing(mulPolyRing([4], ysub, gf), [1, 0, 5 * ea, 20 * eb, -5 * ea * ea, -4 * ea * eb, -8 * eb * eb - ea * ea * ea ], gf) #-8 * eb * eb - ea * ea * ea, -4 * ea * eb, -5 * ea * ea, 20 * eb, 5 * ea, 0, 1
    ] if curDivPolys is None else curDivPolys
  while (len(divPolys) <= l):
    m = len(divPolys) // 2 #m >= 2
                           #even ones in odd psis need adjustment by b6^2=(2*y)^2=4y^2
    if ((m & 1) == 0):
      divPolys.append(addPolyRing(divmodPolyRing(mulPolyRing(mulPolyRing(mulPolyRing(divPolys[m + 2], divPolys[m], gf), divPolys[m], gf), divPolys[m], gf), b6sqr, gf)[0], mulPolyRing(mulPolyRing(mulPolyRing(mulPolyRing(divPolys[m - 1], divPolys[m + 1], gf), divPolys[m + 1], gf), divPolys[m + 1], gf), [-1], gf), gf))
    else:
      divPolys.append(addPolyRing(mulPolyRing(mulPolyRing(mulPolyRing(divPolys[m + 2], divPolys[m], gf), divPolys[m], gf), divPolys[m], gf), mulPolyRing(divmodPolyRing(mulPolyRing(mulPolyRing(mulPolyRing(divPolys[m - 1], divPolys[m + 1], gf), divPolys[m + 1], gf), divPolys[m + 1], gf), b6sqr, gf)[0], [-1], gf), gf))
    #divPolys.append(addPolyRing(mulPolyRing(mulPolyRing(mulPolyRing(divPolys[m + 2], divPolys[m], gf), divPolys[m], gf), divPolys[m], gf), mulPolyRing(mulPolyRing(mulPolyRing(mulPolyRing(divPolys[m - 1], divPolys[m + 1], gf), divPolys[m + 1], gf), divPolys[m + 1], gf), [-1], gf), gf))
    m += 1 #m >= 3
    divPolys.append(divmodPolyRing(mulPolyRing(divPolys[m], addPolyRing(mulPolyRing(mulPolyRing(divPolys[m + 2], divPolys[m - 1], gf), divPolys[m - 1], gf), mulPolyRing(mulPolyRing(mulPolyRing(divPolys[m - 2], divPolys[m + 1], gf), divPolys[m + 1], gf), [-1], gf), gf), gf), mulPolyRing([2], ysub, gf), gf)[0])
  return divPolys

def getSchoofRemainder(ea, eb, gf, l, divPolys, f):
  divPolys = getDivPolys(divPolys, l * 2, ea, eb, f, gf) #l * 2 required for fast variant of point multiplication algorithm
  tl = 0
  divpoly = divPolys[l] #even ones need to be divided by 2*y
  if (l == 2):
    #www.grantjenks.com/docs/sortedcontainers/
    xp = []
    xp.append((gf, 1)) #gcd should return 1
    gcdres = addPolyRing(gcdPolyRing(remainderPolyRingSparsePow2(xp, f, gf), f, gf), mulPolyRing([1, 0], [-1], gf), gf)
    if (len(gcdres) == 1 and gcdres[0] == 1): tl = 1
  else:
    pl = posRemainder(gf, l)
    if (pl >= l // 2): pl -= l
    #xp = []
    #xp.append((gf, 1))
    while True:
      #remainderPolyRingSparse(xp, divpoly, gf)
      #divmodPolyRingSparse(xp, divpoly, gf)
      #modinv = modInversePolyRing([1, 0], divpoly, gf)
      #divmodPolyRing(mulPolyRing(modinv, [1, 0], gf), divpoly, gf)[1]
      #xprem = remainderPolyRingSparsePow2(xp, divpoly, gf)
      xprem = modexpPolyRing([1, 0], gf, divpoly, gf)
      yprem = modexpPolyRing(f, (gf - 1) // 2, divpoly, gf)
      #correct method of squaring is to substitute x value of prior fields into x, y of itself with the y multiplied by the original y
      #xpsquared = divmodPolyRing(substitutePolyRing(xprem, xprem, divpoly, GF), divpoly, GF)[1]
      xpsquared = modexpPolyRing(xprem, gf, divpoly, gf)
      #ypsquared = divmodPolyRing(mulPolyRing(substitutePolyRing(yprem, xprem, divpoly, GF), yprem, GF), divpoly, GF)[1]
      #ypsquared calculation can be delayed by computing the x' of S using alternate equation and then computing it only if needed
      #ypsquared = modexpPolyRing(mulPolyRing(substitutePolyRing(f, xprem, divpoly, GF), f, GF), (GF - 1) / 2, divpoly, GF);
      ypsquared = modexpPolyRing(yprem, gf + 1, divpoly, gf)
      #using identity element with x and y as 1 but this will not suffice in comparisons with x^p or x^p^2
      Q = scaleECPolyRing(([1, 0], [1]), abs(pl), ea, gf, divpoly, f)
      #use identity element since factoring y out of this and making it a function r(x) * y which means r(x)==1 for simple (x, y)
      #Q = scaleECPolyRing(([1, 0], f), abs(pl), ea, gf, divpoly, f)
      #Q = scaleECDivPoly(([1, 0], [1]), abs(pl), gf, divPolys, divpoly, f)
      #if (Q[0] != qalt[0]): raise ValueError
      #if (Q[1] != qalt[1]): raise ValueError
      m = 1
      if (not Q[0] is None):
        if (pl < 0): Q = (Q[0], mulPolyRing(Q[1], [-1], gf))
        #if (Q[0] != xpsquared or Q[1] != ypsquared) {
        S = addECPolyRing((xpsquared, ypsquared), Q, ea, gf, divpoly, f)
        if (S[0] is None): Q = S #also can check xpsquared == Q[0]
        elif (S[0] != [0] or S[1] != [1]):
          #redundant with last check
          modinv = modInversePolyRing(addPolyRing(xpsquared, mulPolyRing(Q[0], [-1], gf), gf), divpoly, gf)
          if (not modinv is None):
            #xpsquared != qalt[0]
            diffsqr = divmodPolyRing(mulPolyRing(addPolyRing(ypsquared, mulPolyRing(Q[1], [-1], gf), gf),
                modinv, gf), divpoly, gf)[1];
            xprime = addPolyRing(addPolyRing(divmodPolyRing(mulPolyRing(mulPolyRing(diffsqr, diffsqr, gf), f, gf), divpoly, gf)[1],
                mulPolyRing(xpsquared, [-1], gf), gf), mulPolyRing(Q[0], [-1], gf), gf); #need to remember to multiply by y^2
            if (xprime != S[0]): raise ValueError
            #xprime + yprime/lambda = xpsquared - ypsquared/lambda, or yprime = xpsquared*lambda - ypsquared - xprime*lambda
            #lambda=(ypsquared-ypl)/(xpsquared-xpl)
            yprime = addPolyRing(divmodPolyRing(mulPolyRing(addPolyRing(xpsquared, mulPolyRing(xprime, [-1], gf), gf), diffsqr, gf), divpoly, gf)[1], mulPolyRing(ypsquared, [-1], gf), gf)
            if (yprime != S[1]): raise ValueError
          #limited by 1 in y, and (l^2 - 3) / 2 in x
          P = (xprem, yprem)
          while True:
            if (len(addPolyRing(S[0], mulPolyRing(P[0], [-1], gf), gf)) == 0):
              tl = m if len(addPolyRing(S[1], mulPolyRing(P[1], [-1], gf), gf)) == 0 else l - m
              break
            if (m == (l - 1) / 2): break
            #P = scaleECDivPoly((xprem, yprem), m + 1, gf, divPolys, divpoly, f)
            P = addECPolyRing(P, (xprem, yprem), ea, gf, divpoly, f)
            #if (P[0] != palt[0]): raise ValueError
            #if (P[1] != palt[1]): raise ValueError
            if (P[0] is None):
              Q = P
              break
            m += 1
        #else tl = 0
      #else: m = (l - 1) // 2
      if (Q[0] is None): divpoly = gcdPolyRing(divpoly, Q[1], gf)
      else: break
      if (Q[0] is None or m > (l - 1) // 2):
        #one thing to do here is factor the division polynomial since we have hit a root in the point arithmetic
        #quadratic non-residue of x^2 === GF (mod l) === pl
        #since l is prime, do not need to deal with composite or prime power cases
        #instead of Tonelli-Shanks, can show non-residue by excluding 1 root (GF === 0 (mod l)), and 2 roots (gcd(GF, l) == 1) and is residue
        #but easier to just use Legendre symbol is -1 and prove non-residue = GF ^ ((l - 1) / 2) (mod l)
        #if (pow(GF, (l - 1) / 2, l) == -1): tl = 0
        #if (pl != 0  and math.gcd(GF, l) != 1): tl = 0
        w = tonelliShanks(posRemainder(gf, l), l) #since we need result anyway might as well compute unless non-residue very common and much faster other methods
        if (w == 0): tl = 0 #no square root, or one square root if posRemainder(GF, l) == 0 but zero either way...
        else:
          #posRemainder(gf, l) != 0 //so there are 2 square roots
          #w = l - w; //l - w is also square root //both roots should give same result though
          #xyw = scaleECPolyRing(([1, 0], [1]), w, ea, gf, divpoly, f)
          xyw = scaleECDivPoly(([1, 0], [1]), w, GF, divPolys, divpoly, f)
          #if (xprem != xyw[0])
          if (gcdPolyRing(addPolyRing(xprem, xyw[0], GF), divpoly, GF) != [1]): tl = 0
          #else: tl = posRemainder((yprem == xyw[1] ? 2 : -2) * w, l);
          else: tl = posRemainder((2 if gcdPolyRing(addPolyRing(yprem, xyw[1], GF), divpoly, GF) == [1] else -2) * w, l)
        break #no need to continue using reduced polynomial since this method is certainly better and faster
  return tl

#https://en.wikipedia.org/wiki/Schoof%27s_algorithm
def schoof(ea, eb, gf, expectedBase):
  realT = gf + 1 - expectedBase
  #sqrtp = tonelliShanks(gf, gf)
  sqrtGF = sqrt(16 * gf)
  sqrtp4 = sqrtGF + (1 if sqrtGF * sqrtGF < 16 * gf else 0) #64-bit square root, can bump this up by one if less than lower bound if that is needed
  #getPrimes(1024)
  l = 2
  prodS = 1
  #https://en.wikipedia.org/wiki/Division_polynomials
  #y=2*y^2 where y^2=x^3+ax+b
  #ysub = 2 * (x * x * x + ea * x + eb)
  f = [1, 0, ea, eb] #eb, ea, 0, 1
  divPolys = None
  ts = []
  t = 0
  while (prodS < sqrtp4): #log2(GF) primes required on average
    tl = getSchoofRemainder(ea, eb, gf, l, divPolys, f)
    print("%d %d %d" % (l, tl, posRemainder(realT, l)))
    #posRemainder(realT, l) == tl
    ts.append((tl, l))
    a = prodS * modInverse(prodS, l)
    b = l * modInverse(l, prodS)
    prodS *= l
    t = posRemainder(a * tl + b * t, prodS)
    l = nextPrime(l)
  #getBitSize(gf) == int(math.ceil(math.log(GF, 2))); //128-bit field
  #t = 0
  #chinese remainder theorem (CRT) on ts while |t| < 2*sqrt(gf)
  if (t > sqrt(4 * gf)):
    t -= prodS
  return GF + 1 - t

def testUtility():
  def testHexPartToInt():
    for i in range(0, 256):
      import binascii
      part = hexPartToInt(chr(i))
      if part != None and part != int.from_bytes(
                        codecs.decode('0' + chr(i), "hex"), byteorder='little'):
        return False
      elif part == None:
        try:
          codecs.decode('0' + chr(i), "hex")
          return False
        except ValueError: pass
        except binascii.Error: pass        
    return True
  def testHexStrToBin():
    for i in range(0, 256):
      if hexStrToBin("%0.2X" % i) != codecs.decode("%0.2X" % i, "hex"):
        return False
    return True
  def testBinToBase64():
    #Vanilla Ice - Ice Ice Baby
    testStr = b"I'm killing your brain like a poisonous mushroom"
    for i in range(0, len(testStr)):
      if binToBase64(testStr[:-i]) != codecs.encode(testStr[:-i],"base64")[:-1]:
        return False
    return True
  testSet = [(testHexPartToInt, "hexPartToInt"),
             (testHexStrToBin, "hexStrToBin"),
             (testBinToBase64, "binToBase64")]
  bPassAll = True
  for s in testSet:
    if not s[0]():
      bPassAll = False
      print("Failed %s" % s[1])
  if bPassAll: print("All utility tests passed")
  
def readUtilityFile(fileName):
  with open(os.path.join(curDir, fileName), "r") as f:
    return f.readlines()
  return []