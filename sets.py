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

testUtility()
#runSet(1, set1)
#runSet(2, set2)
#runSet(3, set3)
runSet(4, set4)
