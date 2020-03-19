"""
"%ProgramFiles%\Python38\python.exe"
import os
curDir = 'D:\\Source\\Repos\\cryptopals\\'
exec(open(os.path.join(curDir, 'sets.py')).read())
"""

import pathlib
import importlib.util
import os
curDir = 'D:\\Source\\Repos\\cryptopals\\'

exec(open(os.path.join(curDir, 'utility.py')).read())
exec(open(os.path.join(curDir, '1.py')).read())
exec(open(os.path.join(curDir, '2.py')).read())
exec(open(os.path.join(curDir, '3.py')).read())
exec(open(os.path.join(curDir, '4.py')).read())
exec(open(os.path.join(curDir, '5.py')).read())
exec(open(os.path.join(curDir, '6.py')).read())
exec(open(os.path.join(curDir, '7.py')).read())
exec(open(os.path.join(curDir, '8.py')).read())
exec(open(os.path.join(curDir, '9.py')).read())

#def loadImp(name):
#  import imp
#  imp.load_source(name, os.path.join(curDir, name = ".py"))

#def loadMod(name):
#  spec = importlib.util.spec_from_file_location(name, os.path.join(curDir, name + ".py"))
#  mod = importlib.util.module_from_spec(spec)
#  spec.loader.exec_module(mod)
#  return mod

def readChallengeFile(fileName):
  with open(os.path.join(curDir, fileName), "r") as f:
    return f.readlines()
  return []

def runSet(setNum, curSet):
  bPassAll = True
  for s in curSet:
    bRes = s[0]()
    if not bRes: bPassAll = False
    print("%s challenge %s.%s" % ("Passed" if bRes else "Failed", setNum, s[1]))
  if bPassAll: print("All challenges passed in set %s" % setNum)
  
#util, s1, s2 = loadMod("utility"), loadMod("1"), loadMod("2")

set1 = [(challenge1, 1), (challenge2, 2), (challenge3, 3), (challenge4, 4),
        (challenge5, 5), (challenge6, 6), (challenge7, 7), (challenge8, 8)]
        
set2 = [(challenge9, 9),   (challenge10, 10), (challenge11, 11),
        (challenge12, 12), (challenge13, 13), (challenge14, 14),
        (challenge15, 15), (challenge16, 16)]

set3 = [(challenge17, 17), (challenge18, 18), (challenge19, 19),
        (challenge20, 20), (challenge21, 21), (challenge22, 22),
        (challenge23, 23), (challenge24, 24)]

set4 = [(challenge25, 25), (challenge26, 26), (challenge27, 27),
        (challenge28, 28), (challenge29, 29), (challenge30, 30),
        (challenge31, 31), (challenge32, 32)]

set5 = [(challenge33, 33), (challenge34, 34), (challenge35, 35),
        (challenge36, 36), (challenge37, 37), (challenge38, 38),
        (challenge39, 39), (challenge40, 40)]

set6 = [(challenge41, 41), (challenge42, 42), (challenge43, 43),
        (challenge44, 44), (challenge45, 45), (challenge46, 46),
        (challenge47, 47), (challenge48, 48)]

set7 = [(challenge49, 49), (challenge50, 50), (challenge51, 51),
        (challenge52, 52), (challenge53, 53), (challenge54, 54),
        (challenge55, 55), (challenge56, 56)]

set8 = [(challenge57, 57), (challenge58, 58), (challenge59, 59),
        (challenge60, 60), (challenge61, 61), (challenge62, 62),
        (challenge63, 63), (challenge64, 64)]

set9 = [(challenge65, 65), (challenge66, 66)]

testUtility()
#runSet(1, set1)
#runSet(2, set2)
#runSet(3, set3)
#runSet(4, set4)
#runSet(5, set5)
#runSet(6, set6)
#runSet(7, set7)
#runSet(8, set8)
challenge59()
#runSet(9, set9)
