def edit(input, key, offset, plaintext):
  o = crypt_ctr(0, key, input)
  o[offset:offset+len(plaintext)] = plaintext
  return crypt_ctr(0, key, o)
  
def challenge25():
  passResult = challenge6and7pass() + "\x04\x04\x04\x04"
  key = random.getrandbits(128).to_bytes(16, 'little')
  b = bytes([item for sublist in [codecs.decode(bytes(x, "utf-8"), "base64") for x in readChallengeFile("25.txt")] for item in sublist])
  o = decrypt_ecb(bytes("YELLOW SUBMARINE", "utf-8"), b)
  b = crypt_ctr(0, key, o)
  editValue = random.getrandbits(len(b) * 8).to_bytes(len(b), 'little')
  return xorBins(xorBins(edit(b, key, 0, editValue), b), editValue).decode("utf-8") == passResult

def encryption_oracle_with_key_ctr(nonce, key, prefix, input, extra):
  input = input.replace(";", "%" + ("%0.2X" % ord(";"))).replace("=", "%" + ("%0.2X" % ord("=")))
  return crypt_ctr(nonce, key, pkcs7pad(prefix + bytes(input, "utf-8") + extra, 16))
  
def challenge26():
  key = random.getrandbits(128).to_bytes(16, 'little')
  o = "".join([' '] * 32)
  b = encryption_oracle_with_key_ctr(0, key, bytes("comment1=cooking%20MCs;userdata=", "utf-8"), o, bytes(";comment2=%20like%20a%20pound%20of%20bacon", "utf-8"))
  if ";admin=true;" in crypt_ctr(0, key, b).decode("utf-8"): return False
  return ";admin=true;" in crypt_ctr(0, key, b[:32] + xorBins(bytes(o[:16], "utf-8"), xorBins(b[32:48], bytes(";admin=true;    ", "utf-8"))) + b[48:]).decode("utf-8")

def challenge27():
  key = random.getrandbits(128).to_bytes(16, 'little')
  b = encryption_oracle_with_key_cbc(key, key, bytes("comment1=cooking%20MCs;userdata=", "utf-8"), "".join([' '] * 32), bytes(";comment2=%20like%20a%20pound%20of%20bacon", "utf-8"))
  o = decrypt_cbc(key, key, b[:16] + bytes([0] * 16) + b[:16])
  return key == xorBins(o[:16], o[32:48])
  
def challenge28():
  key = bytes("YELLOW SUBMARINE", "utf-8")
  sc = SHA1Context()
  SHA1_Algo.reset(sc)
  b = bytes("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon", "utf-8")
  SHA1_Algo.input(sc, key + b)
  o = bytearray(SHA1_Algo.hashSize)
  SHA1_Algo.result(sc, o)
  import hashlib
  m = hashlib.sha1()
  m.update(key + b)
  if o.hex() != m.digest().hex(): return False
  return o.hex() == "08cb9f974e3141954f5b09a648fac55f20427d57"

def challenge29():
  key = bytes("YELLOW SUBMARINE", "utf-8")
  o = bytearray(SHA1_Algo.hashSize)
  b = bytes("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon", "utf-8")
  sc = SHA1Context()
  SHA1_Algo.reset(sc)
  SHA1_Algo.input(sc, key + b)
  SHA1_Algo.result(sc, o)
  pad = SHA1_Algo.pad(key + b)
  blocks = len(pad) // 64
  SHA1_Algo.resetFromHashLen(sc, o, blocks)
  extra = bytes(";admin=true", "utf-8")
  SHA1_Algo.input(sc, extra)
  md = bytearray(SHA1_Algo.hashSize)
  SHA1_Algo.result(sc, md)
  SHA1_Algo.reset(sc)
  SHA1_Algo.input(sc, pad + extra)
  SHA1_Algo.result(sc, o)
  return md == o
  
def challenge30():
  key = bytes("YELLOW SUBMARINE", "utf-8")
  b = bytes("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon", "utf-8")
  extra = bytes(";admin=true", "utf-8")
  md4 = MD4()
  o = md4.computeHash(key + b)
  import hashlib
  m = hashlib.new("md4", key + b)
  if o.hex() != m.digest().hex(): return False
  pad = MD4.pad(key + b)
  md4.initFromHashLen(o, len(pad) // 64)
  md = md4.computeHash(extra)
  o = md4.computeHash(pad + extra)
  return md == o

def challenge31():
  pass
  
def challenge32():
  pass