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
  def verifyConditions2(x, a0, b0, c0, d0, a5, b5, c5, d5, a6, b6, c6, d6, a7, b7, c7, d7, a8, b8, c8, d8, bNaito, stage):
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
    c4 = MD4.round1Operation(c3, d4, a4, b3, x[14], 11)
    b4 = MD4.round1Operation(b3, c4, d4, a4, x[15], 19)
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
    if (not (a5 == MD4.round2Operation(a4, b4, c4, d4, x[0], 3) and
        d5 == MD4.round2Operation(d4, a5, b4, c4, x[4], 5) and
        c5 == MD4.round2Operation(c4, d5, a5, b4, x[8], 9) and
        b5 == MD4.round2Operation(b4, c5, d5, a5, x[12], 13) and
        a6 == MD4.round2Operation(a5, b5, c5, d5, x[1], 3) and
        d6 == MD4.round2Operation(d5, a6, b5, c5, x[5], 5) and
        c6 == MD4.round2Operation(c5, d6, a6, b5, x[9], 9) and
        b6 == MD4.round2Operation(b5, c6, d6, a6, x[13], 13) and
        a7 == MD4.round2Operation(a6, b6, c6, d6, x[2], 3) and
        d7 == MD4.round2Operation(d6, a7, b6, c6, x[6], 5) and
        c7 == MD4.round2Operation(c6, d7, a7, b6, x[10], 9) and
        b7 == MD4.round2Operation(b6, c7, d7, a7, x[14], 13) and
        a8 == MD4.round2Operation(a7, b7, c7, d7, x[3], 3) and
        d8 == MD4.round2Operation(d7, a8, b7, c7, x[7], 5) and
        c8 == MD4.round2Operation(c7, d8, a8, b7, x[11], 9) and
        b8 == MD4.round2Operation(b7, c8, d8, a8, x[15], 13))): return False
    return ((c6 & (1 << 28)) == (d6 & (1 << 28)) and (c6 & (1 << 29)) != (d6 & (1 << 29)) and (c6 & (1 << 31)) != (d6 & (1 << 31)))
  def verifyConditions(x, a0, b0, c0, d0, a1, b1, c1, d1, a2, b2, c2, d2, a3, b3, c3, d3, a4, b4, c4, d4, bMulti, bNaito):
    if (not (a1 == MD4.round1Operation(a0, b0, c0, d0, x[0], 3) and
        d1 == MD4.round1Operation(d0, a1, b0, c0, x[1], 7) and
        c1 == MD4.round1Operation(c0, d1, a1, b0, x[2], 11) and
        b1 == MD4.round1Operation(b0, c1, d1, a1, x[3], 19) and
        a2 == MD4.round1Operation(a1, b1, c1, d1, x[4], 3) and
        d2 == MD4.round1Operation(d1, a2, b1, c1, x[5], 7) and
        c2 == MD4.round1Operation(c1, d2, a2, b1, x[6], 11) and
        b2 == MD4.round1Operation(b1, c2, d2, a2, x[7], 19) and
        a3 == MD4.round1Operation(a2, b2, c2, d2, x[8], 3) and
        d3 == MD4.round1Operation(d2, a3, b2, c2, x[9], 7) and
        c3 == MD4.round1Operation(c2, d3, a3, b2, x[10], 11) and
        b3 == MD4.round1Operation(b2, c3, d3, a3, x[11], 19) and
        a4 == MD4.round1Operation(a3, b3, c3, d3, x[12], 3) and
        d4 == MD4.round1Operation(d3, a4, b3, c3, x[13], 7) and
        c4 == MD4.round1Operation(c3, d4, a4, b3, x[14], 11) and
        b4 == MD4.round1Operation(b3, c4, d4, a4, x[15], 19))): return False
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
        (b4 & (1 << 25)) != 0 and (b4 & (1 << 26)) != 0 and (b4 & (1 << 28)) != 0 and (b4 & (1 << 18)) == 0 and (b4 & (1 << 29)) == 0 and (b4 & (1 << 25)) == (c4 & (1 << 25)))): return False
    return True
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