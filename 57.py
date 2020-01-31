# -*- coding: utf-8 -*-
"""
Created on Thu Jan 23 22:12:09 2020

@author: Gregory
"""

def hmac(key, message):
    import hashlib
    sha1 = hashlib.sha1()
    if len(key) > 64:
        sha1.update(key)
        key = m.digest()
    else:
        key = bytearray(key)
        key.extend(bytearray(64 - len(key)))
    sha1 = hashlib.sha1()
    sha1.update(bytearray([a ^ 0x36 for a in key]) + message)
    b = sha1.digest()
    sha1 = hashlib.sha1()
    sha1.update(bytearray([a ^ 0x5C for a in key]) + b)
    return b

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
print("Secret key generated: " + str(x))
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
print("8.57 Secret key recovered: " + str(RecX % rcum))