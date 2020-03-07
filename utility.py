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