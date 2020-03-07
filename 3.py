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
  getLeastXORBiTrigramScore = getLeastXORBiTrigramScoreGen(
    {"turn":float("inf"), "urn,":float("inf")})
  key = random.getrandbits(128).to_bytes(16, 'little')
  rndStrs = [ "SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
              "Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
              "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
              "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
              "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
              "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
              "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
              "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
              "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
              "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
              "VG8gcGxlYXNlIGEgY29tcGFuaW9u",
              "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
              "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
              "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
              "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
              "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
              "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
              "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
              "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
              "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
              "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
              "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
              "U2hlIHJvZGUgdG8gaGFycmllcnM/",
              "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
              "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
              "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
              "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
              "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
              "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
              "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
              "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
              "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
              "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
              "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
              "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
              "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
              "SW4gdGhlIGNhc3VhbCBjb21lZHk7",
              "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
              "VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
              "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4="]
  passResult = [codecs.decode(bytes(x, "utf-8"), "base64").decode("utf-8") for x in rndStrs]
  lines = [crypt_ctr(0, key, codecs.decode(bytes(x, "utf-8"), "base64")) for x in rndStrs]
  m = max([len(l) for l in lines])
  b = bytearray(m)
  for i in range(len(b)):
    analysis = [s[i] for s in filter(lambda x: len(x) > i, lines)]
    vals = getLeastXORCharacterScore(analysis)
    val = vals[0]
    if i == 0 and val[1] == vals[1][1]:
      if (len(list(filter(lambda x: str.isupper(chr(x)), xorBins(analysis, [vals[1][0]] * len(analysis))))) >
          len(list(filter(lambda x: str.isupper(chr(x)), xorBins(analysis, [val[0]] * len(analysis)))))):
        val = vals[1]
    if i > 3 and (len(analysis) <= 13 or val[1] <= 80):
      val = bigramHandler(getLeastXORBiTrigramScore, val, lines, i, b, analysis)
    b[i] = val[0]
  for i in range(len(lines)):
    if xorBins(lines[i], b[:len(lines[i])]).decode("utf-8") != passResult[i]:
      print(passResult[i])
      print(xorBins(lines[i], b[:len(lines[i])]).decode("utf-8"))
  return all([xorBins(lines[i], b[:len(lines[i])]).decode("utf-8") == passResult[i] for i in range(len(lines))])
  
def challenge20():
  getLeastXORBiTrigramScore = getLeastXORBiTrigramScoreGen(
    {" who":float("inf"), "he m":float("inf"),
     " sce":float("inf"), "nery":float("inf")})
  key = random.getrandbits(128).to_bytes(16, 'little')
  passResult = [codecs.decode(bytes(x, "utf-8"), "base64") for x in readChallengeFile("20.txt")]
  lines = [crypt_ctr(0, key, x) for x in passResult]
  m = max([len(l) for l in lines])
  b = bytearray(m)
  mn = min([len(l) for l in lines])
  keyLen, firstBytes = breakRepXorKey(2, m, [item for sublist in [x[:mn] for x in lines] for item in sublist])
  b[:mn] = firstBytes
  for i in range(mn, m):
    analysis = [s[i] for s in filter(lambda x: len(x) > i, lines)]
    vals = getLeastXORCharacterScore(analysis)
    val = vals[0]
    if i > 3 and (len(analysis) <= 13 or val[1] <= 80):
      val = bigramHandler(getLeastXORBiTrigramScore, val, lines, i, b, analysis)
    b[i] = val[0]
  for i in range(len(lines)):
    if xorBins(lines[i], b[:len(lines[i])]).decode("utf-8") != passResult[i].decode("utf-8"):
      print(passResult[i].decode("utf-8"))
      print(xorBins(lines[i], b[:len(lines[i])]).decode("utf-8"))
  return all([xorBins(lines[i], b[:len(lines[i])]).decode("utf-8") == passResult[i].decode("utf-8") for i in range(len(lines))])

def challenge21():
  pass
  
def challenge22():
  pass
  
def challenge23():
  pass
  
def challenge24():
  pass
