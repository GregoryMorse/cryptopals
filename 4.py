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
  pass

def challenge29():
  pass
  
def challenge30():
  pass
  
def challenge31():
  pass
  
def challenge32():
  pass