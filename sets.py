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
spec = importlib.util.spec_from_file_location("utility", os.path.join(curDir, "utility.py"))
util = importlib.util.module_from_spec(spec)
spec.loader.exec_module(util)
spec = importlib.util.spec_from_file_location("1", os.path.join(curDir, "1.py"))
set1 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(set1)

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
  
set1 = [(challenge1, 1), (challenge2, 2), (challenge3, 3), (challenge4, 4),
        (challenge5, 5), (challenge6, 6), (challenge7, 7), (challenge8, 8)]

testUtility()
runSet(1, set1)