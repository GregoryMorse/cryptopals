#https://cryptopals.com/sets/2/challenges/9
def challenge9():
  passResult = "YELLOW SUBMARINE\x04\x04\x04\x04"
  str = "YELLOW SUBMARINE"
  res = pkcs7pad(bytes(str, "utf-8"), 20).decode("utf-8")
  return res == passResult

def challenge10():
  passResult = pkcs7pad(bytes(challenge6and7pass(), "utf-8"), 16)
  key = bytes("YELLOW SUBMARINE", "utf-8")
  cipherData = b''.join([codecs.decode(bytes(x.rstrip(), "utf-8"), "base64")
                         for x in readChallengeFile('10.txt')])
  res = decrypt_cbc(bytes([0] * 16), key, cipherData)
  if (encrypt_cbc(bytes([0] * 16), key, res) != cipherData): return False
  return res == passResult

import random
def encryption_oracle(cipherData):
  key = random.getrandbits(128).to_bytes(16, 'little')
  first, last = random.randint(5, 10), random.randint(5, 10)
  cipherData = (random.getrandbits(first << 3).to_bytes(first, 'little') +
                cipherData +
                random.getrandbits(last << 3).to_bytes(last, 'little'))
  cipherData = pkcs7pad(cipherData, 16)
  if random.randint(0, 1) == 1: return True, encrypt_ecb(key, cipherData)
  else: return False, encrypt_cbc(random.getrandbits(128).to_bytes(16, 'little'), key, cipherData)

def challenge11():
  cipherData = b''.join([codecs.decode(bytes(x.rstrip(), "utf-8"), "base64")
                         for x in readChallengeFile('10.txt')])
  key = bytes("YELLOW SUBMARINE", "utf-8")
  o = decrypt_cbc(bytes([0] * 16), key, cipherData)
  #important note: if the plain text does not have a repeated 16-byte block
  #starting between offsets 0 to 4 and 10 to 16 inclusive then this will not be
  #a useful detector since 5+5=10 and (10+10)%16=4
  for i in range(1024):
    oracle_ecb, res = encryption_oracle(o)
    if oracle_ecb != is_ecb_mode(bytes(res)): return False
  return True

def encryption_oracle_with_key(key_data, input):
  return encrypt_ecb(key_data[0], input + key_data[1])

def challenge12():  
  passBlockSize = 16
  passResult = ("Rollin' in my 5.0\n" #Vanilla Ice - Ice Ice Baby
                "With my rag-top down so my hair can blow\n"
                "The girlies on standby waving just to say hi\n"
                "Did you stop? No, I just drove by")
  plainText = codecs.decode(bytes(
    "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
    "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
    "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
    "YnkK", "utf-8"), "base64")
  oracle_key_data = (random.getrandbits(128).to_bytes(16, 'little'), plainText)
  startLen = len(encryption_oracle_with_key(oracle_key_data, bytes()))
  ct = 1 #when output size increases, difference will be one block
  while startLen == len(encryption_oracle_with_key(oracle_key_data, bytes([0] * ct))):
    ct += 1
  blockSize = len(encryption_oracle_with_key(oracle_key_data, bytes([0] * ct))) - startLen
  if blockSize != passBlockSize: return False
  #ECB mode check
  if not is_ecb_mode(encryption_oracle_with_key(oracle_key_data, bytes([0] * 32))): return False
  l = startLen - ct
  res = bytearray(l)
  for i in range(0, l):
    start = ((1 + i) // blockSize) * blockSize
    prefix = bytes([0] * (blockSize - ((1 + i) % blockSize)))
    sample = encryption_oracle_with_key(oracle_key_data, prefix)[start:start+blockSize]
    d = dict()
    for ct in range(0, 256): #alphanumeric and whitespace would be a shortcut
      ciph = encryption_oracle_with_key(oracle_key_data, prefix + res[:i] + bytes([ct]))[start:start+blockSize]
      d[ciph] = ct
    res[i] = d[sample]
  return res.decode("utf-8") == passResult

def parseCookie(cookie):
  d = dict()
  for s in cookie.split("&"):
    keyVals = s.split("=")
    if len(keyVals) != 2: return dict()
    val = keyVals[1].strip()
    if val.isdigit(): d[keyVals[0]] = int(val)
    else: d[keyVals[0]] = val
  return d
   
def profile_for(name):
  name = name.replace("&", "%" + ("%0.2X" % ord("&"))).replace("=", "%" + ("%0.2X" % ord("=")))
  profileDict = {"foo@bar.com":(10, "user")}
  if not name in profileDict: profileDict[name] = (10, "user")
  entry = profileDict[name]
  profile = {"email":name, "uid":entry[0], "role":entry[1]}
  encodeOrder = ["email", "uid", "role"]
  encode, bFirst = "", True
  for s in encodeOrder:
    if not bFirst: encode += "&"
    else: bFirst = False
    encode += s + "=" + str(profile[s])
  return encode

def profile_for_enc(key, name):
  return encrypt_ecb(key, pkcs7pad(bytes(profile_for(name), "utf-8"), 16))

def profile_for_dec(key, data):
  try:
    stripped = pkcs7strip(decrypt_ecb(key, data), 16)
  except ValueError: return dict()
  return parseCookie(stripped.decode("utf-8"))

def challenge13():
  test = parseCookie("foo=bar&baz=qux&zap=zazzle")
  passTest = {'foo':'bar', 'baz':'qux', 'zap':'zazzle'}
  if test != passTest: return False
  p = profile_for("foo@bar.com")
  #testProf = {'email':'foo@bar.com', 'uid':10, 'role':'user'}
  testProf = "email=foo@bar.com&uid=10&role=user"
  if p != testProf: return False
  key = random.getrandbits(128).to_bytes(16, 'little')
  b = profile_for_enc(key, "foo@bar.com")
  testDict = {"email":"foo@bar.com", "uid":10, "role":"user"}
  if (profile_for_dec(key, b) != testDict): return False
  adminBytes = pkcs7pad(bytes("admin", "utf-8"), 16)
  #adjust = ((profile_for("foo@bar.com").find("&role=") + len("&role=")) & 15) - len("email=")
  #fixEncode = profile_for_enc(key, "".join([" "] * (16 - len("email="))) + adminBytes.decode("utf-8") + "foo@bar.com" + "".join([" "] * (16 - adjust)))
  testDict["role"] = "admin"
  #if we cannot exploit due to trim occurring,
  #and it checks email address validity on decoding, then 16 emails
  #would be needed to exploit this and additional loop to try them
  #if we cannot exploit invalid emails on encoding as it is checked,
  #then 256 email addresses need to be added
  #including ones with PKCS7 encoding in them
  #if not sure about 2nd block being the right one,
  #would need to try all middle blocks
  for i in range(0, 16):
    for j in range(0, 16):
      fixEncode = profile_for_enc(key, "".join([" "] * i) + adminBytes.decode("utf-8") + "foo@bar.com" + "".join([" "] * j))
      modEncode = fixEncode[:16] + fixEncode[32:len(fixEncode) - 16] + fixEncode[16:32]
      if profile_for_dec(key, modEncode) == testDict: return True
  return False
  
def encryption_oracle_with_key_pre(key_data, prefix, input):
  return encryption_oracle_with_key(key_data, prefix + input)

def challenge14():
  passBlockSize = 16
  passResult = ("Rollin' in my 5.0\n" #Vanilla Ice - Ice Ice Baby
                "With my rag-top down so my hair can blow\n"
                "The girlies on standby waving just to say hi\n"
                "Did you stop? No, I just drove by")
  plainText = codecs.decode(bytes(
    "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
    "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
    "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
    "YnkK", "utf-8"), "base64")
  oracle_key_data = (random.getrandbits(128).to_bytes(16, 'little'), plainText)
  randCount = random.randint(1, 31)
  r = random.getrandbits(randCount << 3).to_bytes(randCount, 'little')
  startLen = len(encryption_oracle_with_key_pre(oracle_key_data, r, bytes()))
  ct = 1 #when output size increases, difference will be one block
  while startLen == len(encryption_oracle_with_key_pre(oracle_key_data, r, bytes([0] * ct))):
    ct += 1
  blockSize = len(encryption_oracle_with_key_pre(oracle_key_data, r, bytes([0] * ct))) - startLen
  if blockSize != passBlockSize: return False
  #ECB mode check
  #need 3 (or in keysize cases 2) identical blocks makes at least 2 aligned blocks when randomly prefixed
  output = encryption_oracle_with_key_pre(oracle_key_data, r, bytes([0] * 48));
  if not is_ecb_mode(output): return False
  startBlock = 0
  while (output[startBlock * blockSize:(startBlock + 1) * blockSize] != 
         output[(startBlock + 1) * blockSize:(startBlock + 2) * blockSize]): startBlock += 1
  startInBlock = 0
  while (output[(startBlock - 1) * blockSize:startBlock * blockSize] !=
         encryption_oracle_with_key_pre(oracle_key_data, r, bytes([0] * startInBlock))[(startBlock - 1) * blockSize:startBlock * blockSize]):
    startInBlock += 1
  if startInBlock != 0 and startInBlock % blockSize != 0:
    startBlock -= 1
    startInBlock = 16 - startInBlock
  l = startLen - ct - startBlock * blockSize - startInBlock
  res = bytearray(l)
  for i in range(0, l):
    start = (startBlock + (1 + i + startInBlock) // blockSize) * blockSize
    prefix = bytes([0] * (blockSize - (1 + i + startInBlock) % blockSize))
    sample = encryption_oracle_with_key_pre(oracle_key_data, r, prefix)[start:start+blockSize]
    d = dict()
    for ct in range(0, 256): #alphanumeric and whitespace would be a shortcut
      ciph = encryption_oracle_with_key_pre(oracle_key_data, r, prefix + res[:i] + bytes([ct]))[start:start+blockSize]
      d[ciph] = ct
    res[i] = d[sample]
  return res.decode("utf-8") == passResult
  
def challenge15():
  if pkcs7strip(bytes("ICE ICE BABY\x04\x04\x04\x04", "utf-8"), 16).decode("utf-8") != "ICE ICE BABY": return False
  try:
    pkcs7strip(bytes("ICE ICE BABY\x05\x05\x05\x05", "utf-8"), 16)
    return False
  except ValueError: pass
  try:
    pkcs7strip(bytes("ICE ICE BABY\x01\x02\x03\x04", "utf-8"), 16)
    return False
  except ValueError: pass 
  return True
  
def encryption_oracle_with_key_cbc(iv, key, prefix, input, extra):
  input = input.replace(";", "%" + ("%0.2X" % ord(";"))).replace("=", "%" + ("%0.2X" % ord("=")))
  return encrypt_cbc(iv, key, pkcs7pad(prefix + bytes(input, "utf-8") + extra, 16))
  
def challenge16():
  key = random.getrandbits(128).to_bytes(16, 'little')
  iv = random.getrandbits(128).to_bytes(16, 'little')
  o = "".join([" "] * 64)
  b = encryption_oracle_with_key_cbc(iv, key, bytes("comment1=cooking%20MCs;userdata=", "utf-8"), o, bytes(";comment2=%20like%20a%20pound%20of%20bacon", "utf-8"))
  if ";admin=true;" in pkcs7strip(decrypt_cbc(iv, key, b), 16).decode("utf-8"): return False
  #first send a block with all 0's to let us determine the output of the next stage
  #output = decrypt_cbc(iv, key, Enumerable.Concat(Enumerable.Concat(b.Take(32), Enumerable.Repeat((byte)0, 16)), b.Skip(48)).ToArray());
  return ";admin=true;" in pkcs7strip(decrypt_cbc(iv, key, b[:32] + xorBins(bytes(o[16:32], "utf-8"), xorBins(b[32:48], bytes(";admin=true;    ", "utf-8"))) + b[48:]), 16).decode("utf-8", "ignore")
