"""
"%ProgramFiles%\Python38\python.exe"
exec(open(os.path.join(curDir, '1.py')).read())
"""

curDir = 'D:\\Source\\Repos\\cryptopals\\'
import os
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

def characterScore(bin):
  freq = (.082, .015, .028, .043, .127, .022, .020, .061, .070, .002,
          .008, .040, .024, .067, .075, .019, .001, .060, .063, .091,
          .028, .010, .023, .001, .020, .001) #a-z/A-Z
  #30% weight for space or a false positives with high weighted letters can win
  #can improve by negative weight for certain bad characters...
  spaceFreq, d = 0.3, dict()
  for i in bin: #group by frequency
    if i in d: d[i] += 1
    else: d[i] = 1
  return (spaceFreq * (d[ord(' ')] if ord(' ') in d else 0) +
          sum([j * ((d[ord('a') + i] if (ord('a') + i) in d else 0) +
                    (d[ord('A') + i] if (ord('A') + i) in d else 0))
                    for i, j in enumerate(freq)])) * 100

def getLeastXORCharacterScore(bin):
  l = len(bin)
  freqs = [(i,characterScore(xorBins(bin, bytes([i] * l)))) for i in range(256)]
  return max(freqs, key=lambda x: x[1])

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

#pip install pycryptodome
#pip install pycryptodomex
def decrypt_ecb(key, cipherData):
  from Crypto.Cipher import AES
  from Crypto.Util import Padding
  cipher = AES.new(key, AES.MODE_ECB)
  lastBlockSize = len(cipherData) & 15
  if lastBlockSize != 0:
    cipherData = Padding(cipherData, 16) #padding style does not matter
  plainText = cipher.decrypt(cipherData)
  return plainText if lastBlockSize == 0 else plainText[:-(16-lastBlockSize)]

def is_ecb_mode(cipherData):
  l, s = len(cipherData), set()
  for i in range(0, l, 16):
    if cipherData[i:i+16] in s: return True
    s.add(cipherData[i:i+16])
  return False

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

def runSet(setNum, curSet):
  bPassAll = True
  for s in curSet:
    bRes = s[0]()
    if not bRes: bPassAll = False
    print("%s challenge %s.%s" % ("Passed" if bRes else "Failed", setNum, s[1]))
  if bPassAll: print("All challenges passed in set %s" % setNum)

#https://cryptopals.com/sets/1/challenges/1
def challenge1():
  passResult = ("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBs"
                "aWtlIGEgcG9pc29ub3VzIG11c2hyb29t")
  str = ("49276d206b696c6c696e6720796f757220627261696e206c"
         "696b65206120706f69736f6e6f7573206d757368726f6f6d")
  #result = hexToBase64Alt(str)
  #print(hexStrToBin(str))
  result = hexToBase64(str)
  bSame = result == passResult
  if not bSame: print("%s != %s" % (result, passResult))
  return bSame
  
#https://cryptopals.com/sets/1/challenges/2
def challenge2():
  str1 = "1c0111001f010100061a024b53535009181c"
  str2 = "686974207468652062756c6c277320657965"
  passResult = "746865206b696420646f6e277420706c6179"
  res = xorBins(hexStrToBin(str1), hexStrToBin(str2)).hex()
  return res == passResult

def challenge3():
  str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
  passKey = 88 #could be worked out painstakingly by hand
  passString = "Cooking MC's like a pound of bacon" #Vanilla Ice - Ice Ice Baby
  bin = hexStrToBin(str)
  key = getLeastXORCharacterScore(bin)[0]
  res = xorBins(bin, [key] * len(bin)).decode("utf-8")
  return key == passKey and res == passString

def challenge4():
  passLine, passKey, passString = 170, 53, "Now that the party is jumping\n"
  f = open(os.path.join(curDir, '4.txt'), "r")
  lines = f.readlines()
  f.close()
  bestFreqs = [(i, getLeastXORCharacterScore(hexStrToBin(j.rstrip())))
               for i, j in enumerate(lines)]
  best = max(bestFreqs, key=lambda x: x[1][1])
  bestLine = hexStrToBin(lines[best[0]].rstrip())
  res = xorBins(bestLine, [best[1][0]] * len(bestLine)).decode("utf-8")
  return best[0] == passLine and best[1][0] == passKey and res == passString

def challenge5():
  #Vanilla Ice - Ice Ice Baby
  str = ("Burning 'em, if you ain't quick and nimble\n"
         "I go crazy when I hear a cymbal")
  passResult = (
   "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
   "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
  key = "ICE"
  res = xorRepKeyBins(bytes(str, "utf-8"), bytes(key, "utf-8")).hex()  
  return res == passResult
  
def challenge6and7pass():
  return ( #Vanilla Ice - Play That Funky Music
    "I'm back and I'm ringin' the bell \n"
    "A rockin' on the mike while the fly girls yell \n"
    "In ecstasy in the back of me \n"
    "Well that's my DJ Deshay cuttin' all them Z's \n"
    "Hittin' hard and the girlies goin' crazy \n"
    "Vanilla's on the mike, man I'm not lazy. \n\n"
    "I'm lettin' my drug kick in \n"
    "It controls my mouth and I begin \n"
    "To just let it flow, let my concepts go \n"
    "My posse's to the side yellin', Go Vanilla Go! \n\n"
    "Smooth 'cause that's the way I will be \n"
    "And if you don't give a damn, then \n"
    "Why you starin' at me \n"
    "So get off 'cause I control the stage \n"
    "There's no dissin' allowed \n"
    "I'm in my own phase \n"
    "The girlies sa y they love me and that is ok \n"
    "And I can dance better than any kid n' play \n\n"
    "Stage 2 -- Yea the one ya' wanna listen to \n"
    "It's off my head so let the beat play through \n"
    "So I can funk it up and make it sound good \n"
    "1-2-3 Yo -- Knock on some wood \n"
    "For good luck, I like my rhymes atrocious \n"
    "Supercalafragilisticexpialidocious \n"
    "I'm an effect and that you can bet \n"
    "I can take a fly girl and make her wet. \n\n"
    "I'm like Samson -- Samson to Delilah \n"
    "There's no denyin', You can try to hang \n"
    "But you'll keep tryin' to get my style \n"
    "Over and over, practice makes perfect \n"
    "But not if you're a loafer. \n\n"
    "You'll get nowhere, no place, no time, no girls \n"
    "Soon -- Oh my God, homebody, you probably eat \n"
    "Spaghetti with a spoon! Come on and say it! \n\n"
    "VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \n"
    "Intoxicating so you stagger like a wino \n"
    "So punks stop trying and girl stop cryin' \n"
    "Vanilla Ice is sellin' and you people are buyin' \n"
    "'Cause why the freaks are jockin' like Crazy Glue \n"
    "Movin' and groovin' trying to sing along \n"
    "All through the ghetto groovin' this here song \n"
    "Now you're amazed by the VIP posse. \n\n"
    "Steppin' so hard like a German Nazi \n"
    "Startled by the bases hittin' ground \n"
    "There's no trippin' on mine, I'm just gettin' down \n"
    "Sparkamatic, I'm hangin' tight like a fanatic \n"
    "You trapped me once and I thought that \n"
    "You might have it \n"
    "So step down and lend me your ear \n"
    "'89 in my time! You, '90 is my year. \n\n"
    "You're weakenin' fast, YO! and I can tell it \n"
    "Your body's gettin' hot, so, so I can smell it \n"
    "So don't be mad and don't be sad \n"
    "'Cause the lyrics belong to ICE, You can call me Dad \n"
    "You're pitchin' a fit, so step back and endure \n"
    "Let the witch doctor, Ice, do the dance to cure \n"
    "So come up close and don't be square \n"
    "You wanna battle me -- Anytime, anywhere \n\n"
    "You thought that I was weak, Boy, you're dead wrong \n"
    "So come on, everybody and sing this song \n\n"
    "Say -- Play that funky music Say, go white boy, go white boy go \n"
    "play that funky music Go white boy, go white boy, go \n"
    "Lay down and boogie and play that funky music till you die. \n\n"
    "Play that funky music Come on, Come on, let me hear \n"
    "Play that funky music white boy you say it, say it \n"
    "Play that funky music A little louder now \n"
    "Play that funky music, white boy Come on, Come on, Come on \n"
    "Play that funky music \n")

def challenge6():
  #Public Enemy - Bring the Noise featuring record scratching by DJ Terminator X
  passKeyLen, passKey = 29, b'Terminator X: Bring the noise'
  passResult = challenge6and7pass()
  f = open(os.path.join(curDir, '6.txt'), "r")
  cipherData = b''.join([codecs.decode(bytes(x, "utf-8"), "base64")
                         for x in f.readlines()])
  f.close()
  if hammingDistance(bytes("this is a test", "utf-8"),
                     bytes("wokka wokka!!!", "utf-8")) != 37: return False
  ciphLen = len(cipherData)
  #1 / (ciphLen / i - 1) / i == (i / (ciphLen - i)) / i == 1 / (ciphLen - i)
  best = min([(i, sum([hammingDistance(cipherData[i * j:i * (j + 1)],
                                       cipherData[i * (j + 1):i * (j + 2)])
                       for j in range(ciphLen // i - 1)]) / (ciphLen - i))
              for i in range(2, 41)], key=lambda x: x[1])
  key = bytes([getLeastXORCharacterScore(
                  [cipherData[j] for j in range(i, ciphLen, best[0])])[0]
               for i in range(best[0])])
  return (best[0] == passKeyLen and key == passKey and
          xorRepKeyBins(cipherData, key).decode("utf-8") == passResult)

def challenge7():
  passResult = challenge6and7pass() + "\x04\x04\x04\x04"
  key = "YELLOW SUBMARINE"
  f = open(os.path.join(curDir, '7.txt'), "r")
  cipherData = b''.join([codecs.decode(bytes(x, "utf-8"), "base64")
                         for x in f.readlines()])
  f.close()
  res = decrypt_ecb(bytes(key, "utf-8"), cipherData).decode("utf-8")
  return res == passResult

def challenge8():
  passResult = ['d880619740a8a19b7840a8a31c810a3d08649af70dc06f4f'
                'd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb57'
                '08649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d465'
                '97949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd283'
                '97a93eab8d6aecd566489154789a6b0308649af70dc06f4f'
                'd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0'
                'ab51b29933f2c123c58386b06fba186a']
  f = open(os.path.join(curDir, '8.txt'), "r")
  cipherLines = [codecs.decode(x[:-1], "hex") for x in f.readlines()]
  f.close()
  ecbLines = []
  for cipherLine in cipherLines:
    if is_ecb_mode(cipherLine): ecbLines.append(cipherLine)
  return [x.hex() for x in ecbLines] == passResult

set1 = [(challenge1, 1), (challenge2, 2), (challenge3, 3), (challenge4, 4),
        (challenge5, 5), (challenge6, 6), (challenge7, 7), (challenge8, 8)]

testUtility()
runSet(1, set1)