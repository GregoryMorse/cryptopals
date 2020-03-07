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
  key = getLeastXORCharacterScore(bin)[0][0]
  res = xorBins(bin, [key] * len(bin)).decode("utf-8")
  return key == passKey and res == passString

def challenge4():
  passLine, passKey, passString = 170, 53, "Now that the party is jumping\n"
  lines = readChallengeFile('4.txt')
  firstOfList = lambda x: (0, 0) if len(x) == 0 else x[0]
  bestFreqs = [(i, firstOfList(getLeastXORCharacterScore(hexStrToBin(j.rstrip()))))
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
  cipherData = b''.join([codecs.decode(bytes(x.rstrip(), "utf-8"), "base64")
                         for x in readChallengeFile('6.txt')])
  if hammingDistance(bytes("this is a test", "utf-8"),
                     bytes("wokka wokka!!!", "utf-8")) != 37: return False
  keyLen, key = breakRepXorKey(2, 40, cipherData)
  return (keyLen == passKeyLen and key == passKey and
          xorRepKeyBins(cipherData, key).decode("utf-8") == passResult)

def challenge7():
  passResult = challenge6and7pass() + "\x04\x04\x04\x04"
  key = "YELLOW SUBMARINE"
  cipherData = b''.join([codecs.decode(bytes(x.rstrip(), "utf-8"), "base64")
                         for x in readChallengeFile('7.txt')])
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
  cipherLines = [codecs.decode(x.rstrip(), "hex")
                 for x in readChallengeFile('8.txt')]
  ecbLines = []
  for cipherLine in cipherLines:
    if is_ecb_mode(cipherLine): ecbLines.append(cipherLine)
  return [x.hex() for x in ecbLines] == passResult