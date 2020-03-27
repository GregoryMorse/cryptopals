def challenge57():
  p = 7199773997391911030609999317773941274322764333428698921736339643928346453700085358802973900485592910475480089726140708102474957429903531369589969318716771
  g = 4565356397095740655436854503483826832136106141639563487732438195343690437606117828318042418238184896212352329118608100083187535033402010599512641674644143
  q = 236234353446506858198510045061214171961
  j = (p - 1) // q
  m = "crazy flamboyant for the rap enjoyment"
  rs = []
  for i in range(2, 1 << 16):
      quot, rem = divmod(j, i)
      if rem == 0:
          rs.append(i)
          while True:
              j = quot;
              quot, rem = divmod(j, i)
              if rem != 0: break
  import secrets
  while True:
      x = secrets.randbelow(q)
      if x > 1: break
  #print("Secret key generated: " + str(x))
  curr, rcum = 0, 1
  bs = []
  while True:
      while True:
          while True:
              rand = secrets.randbelow(p)
              if rand > 1: break
          h = pow(rand, (p - 1) // rs[curr], p)
          if h != 1: break
      K = pow(h, x, p)
      t = hmac(K.to_bytes((K.bit_length() + 7) // 8, byteorder='little'), m.encode('ascii'))
      for i in range(0, rs[curr]):
          testK = pow(h, i, p);
          if t == hmac(testK.to_bytes((testK.bit_length() + 7) // 8, byteorder='little'), m.encode('ascii')):
              bs.append(i)
              break
      rcum *= rs[curr]
      curr += 1
      if rcum > q: break
  RecX = 0
  for i in range(0, curr):
      curcum = rcum // rs[i]
      RecX += bs[i] * curcum * pow(curcum, rs[i] - 2, rs[i])
  #print("8.57 Secret key recovered: " + str(RecX % rcum))
  return (RecX % rcum) == x
  
def challenge58():
  m = "crazy flamboyant for the rap enjoyment"
  p = 11470374874925275658116663507232161402086650258453896274534991676898999262641581519101074740642369848233294239851519212341844337347119899874391456329785623
  q = 335062023296420808191071248367701059461
  j = (p - 1) // q
  g = 622952335333961296978159266084741085889881358738459939978290179936063635566740258555167783009058567397963466103140082647486611657350811560630587013183357
  y = 7760073848032689505395005705677365876654629189298052775754597607446617558600394076764814236081991643094239886772481052254010323780165093955236429914607119
  passY = 705485
  yRes = pollardKangaroo(0, 1 << 20, 7, g, p, y)
  #print(bytes(reversed(yRes.to_bytes((yRes.bit_length() + 7) // 8, byteorder='little'))).hex())
  if passY != yRes: return False
  y = 9388897478013399550694114614498790691034187453089355259602614074132918843899833277397448144245883225611726912025846772975325932794909655215329941809013733  
  passY = 359579674340
  yRes = pollardKangaroo(0, 1 << 40, 23, g, p, y)
  #print(bytes(reversed(yRes.to_bytes((yRes.bit_length() + 7) // 8, byteorder='little'))).hex())
  if passY != yRes: return False
  import secrets
  while True:
    x = secrets.randbelow(q)
    if x > 1: break #Bob's secret key
  y = pow(g, x, p)
  rs = []
  for i in range(2, 1 << 16):
    quot, rem = divmod(j, i)
    if rem == 0:
      rs.append(i)
      while True:
        j = quot
        quot, rem = divmod(j, i) #reduce powers of factors:
        #(Friendly tip: maybe avoid any repeated factors. They only complicate things.)
        if rem != 0: break
  curr = 0
  rcum = 1
  bs = []
  while True:
    while True:
      while True:
        rand = secrets.randbelow(p) #random number between 1..p
        if rand > 1: break
      h = pow(rand, (p - 1) // rs[curr], p) #There is no x such that h = g^x mod p
      if h != 1: break  
    K = pow(h, x, p)
    t = hmac(K.to_bytes((K.bit_length() + 7) // 8, byteorder='little'), m.encode('ascii'))
    for i in range(rs[curr]):
      testK = pow(h, i, p)
      if (t == hmac(testK.to_bytes((testK.bit_length() + 7) // 8, byteorder='little'), m.encode('ascii'))):
        bs.append(i)
        break
    rcum *= rs[curr]
    curr += 1
    if curr >= len(rs): break #rcum > q
  #Chinese Remainder Theorem - arbitrary size by interpolation
  #K = b1 (mod h1), K = b_n (mod r_n)
  RecX = 0
  for i in range(curr):
    curcum = rcum // rs[i]
    RecX += bs[i] * curcum * modInverse(curcum, rs[i])
  RecX = RecX % rcum
  #print("CRT recovered: " + RecX.to_bytes((RecX.bit_length() + 7) // 8, byteorder='little').hex())
  #[0, (q-1)/r]
  #x = n mod r, x = n + m * r therefore transform
  #y = g^x=g^(n+m*r)=g^n*g^(m*r)
  #y' = y * g^(-n)=g^(m*r), g'=g^r, y'=(g')^m
  Gprime = pow(g, rcum, p)
  Yprime = (y * modInverse(pow(g, RecX, p), p)) % p
  Mprime = pollardKangaroo(0, (p - 1) // rcum, 23, Gprime, p, Yprime) #(p - 1) / rcum is 40 bits in this case, 23 could also be good
  res = (RecX + Mprime * rcum) % (p - 1)
  #print("8.58 Secret key recovered: " + res.to_bytes((res.bit_length() + 7) // 8, byteorder='little').hex())
  return res == x
  
def challenge59():
  ea, eb = -95051, 11279326
  gx, gy, gf, bpOrd = 182, 85518893674295321206118380980485522083, 233970423115425145524320034830162017933, 29246302889428143187362802287225875743
  ord = bpOrd * 2 * 2 * 2
  #if ord != schoofElkiesAtkin(ea, eb, gf, True, ord): return False
  #if ord != schoofElkiesAtkin(ea, eb, gf, False, ord): return False
  #if ord != schoof(ea, eb, gf, ord): return False
  pickGys = [eb, 210, 504, 727]
  ords = [ord, 233970423115425145550826547352470124412, #2^2 * 3 * 11 * 23 * 31 * 89 * 4999 * 28411 * 45361 * 109138087 * 39726369581
               233970423115425145544350131142039591210, #2 * 5 * 7 * 11 * 61 * 12157 * 34693 * 11810604523200031240395593
               233970423115425145545378039958152057148] #2^2 * 7 * 23 * 37 * 67 * 607 * 1979 * 13327 * 13799 * 663413139201923717
  #if ords[1] != schoofElkiesAtkin(ea, pickGys[1], gf, True, ords[1]): return False
  #if ords[1] != schoofElkiesAtkin(ea, pickGys[1], gf, False, ords[1]): return False
  #if ords[1] != schoof(ea, pickGys[1], gf, ords[1]): return False
  #if ords[2] != schoofElkiesAtkin(ea, pickGys[2], gf, True, ords[2]): return False
  #if ords[2] != schoofElkiesAtkin(ea, pickGys[2], gf, False, ords[2]): return False
  #if ords[2] != schoof(ea, pickGys[2], gf, ords[2]): return False
  #if ords[3] != schoofElkiesAtkin(ea, pickGys[3], gf, True, ords[3]): return False
  #if ords[3] != schoofElkiesAtkin(ea, pickGys[3], gf, False, ords[3]): return False
  #if ords[3] != schoof(ea, pickGys[3], gf, ords[3]): return False
  
def challenge60():
  pass
  
def challenge61():
  pass
  
def challenge62():
  pass
  
def challenge63():
  pass

def challenge64():
  pass