def challenge17():
  rndStrs = [
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"]
  rndStrs = [codecs.decode(bytes(x, "utf-8"), "base64") for x in rndStrs]
  key = random.getrandbits(128).to_bytes(16, 'little')
  iv = random.getrandbits(128).to_bytes(16, 'little')
  ct = random.randint(0, len(rndStrs) - 1)
  b = encrypt_cbc(iv, key, pkcs7pad(rndStrs[ct], 16))
  output = decrypt_cbc(iv, key, b)
  if (pkcs7strip(output, 16) != rndStrs[ct]): return False
  b = bytearray(iv + b)
  for startBlock in range(len(b) // 16 - 1, 0, -1):
    data = bytearray(16)
    for startInBlock in range(15, -1, -1):
      for j in range(15, startInBlock, -1):
        b[(startBlock - 1) * 16 + j] ^= data[j] ^ (16 - startInBlock)
      for i in range(255, -1, -1):
        b[(startBlock - 1) * 16 + startInBlock] ^= i ^ (16 - startInBlock)
        if pkcs7check(decrypt_cbc(iv, key, b[:(startBlock + 1) * 16]), 16):
          b[(startBlock - 1) * 16 + startInBlock] ^= i ^ (16 - startInBlock)
          data[startInBlock] = i
          break
        b[(startBlock - 1) * 16 + startInBlock] ^= i ^ (16 - startInBlock)
      for j in range(15, startInBlock, -1):
        b[(startBlock - 1) * 16 + j] ^= data[j] ^ (16 - startInBlock)
    b[startBlock * 16:(startBlock + 1) * 16] = data
  return pkcs7strip(b[16:], 16) == rndStrs[ct]

def challenge18():
  passResult = "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "
  str = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
  key = bytes("YELLOW SUBMARINE", "utf-8")
  if crypt_ctr(0, key, codecs.decode(bytes(str, "utf-8"), "base64")).decode("utf-8") != passResult: return False
  #test encrypt-decrypt returns same result
  return str == codecs.encode(crypt_ctr(0, key, crypt_ctr(0, key, codecs.decode(bytes(str, "utf-8"), "base64"))), "base64")[:-1].decode("utf-8")
  
def challenge19():
  pass
  
def challenge20():
  pass
  
def challenge21():
  pass
  
def challenge22():
  pass
  
def challenge23():
  pass
  
def challenge24():
  pass
