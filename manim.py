#!/usr/bin/env python

from manimlib.imports import *

#install sox, MikTex, extract ffmpeg
#set PATH=%PATH%;C:\Users\Gregory\Documents\ffmpeg-20200315-c467328-win64-static\bin;C:\program files\MiKTeX 2.9\miktex\bin\x64
#https://www.lfd.uci.edu/~gohlke/pythonlibs/#pycairo
##pip install https://download.lfd.uci.edu/pythonlibs/s2jqpv5t/pycairo-1.19.1-cp37-cp37m-win32.whl
#pip install https://download.lfd.uci.edu/pythonlibs/s2jqpv5t/pycairo-1.19.1-cp37-cp37m-win_amd64.whl
#pip install pyreadline
#pip install manimlib
#manim -h
#overwrite %ProgramFiles%\Python37\lib\site-packages\manimlib with master of: https://github.com/Elteoremadebeethoven/Manim-TB
#need to modify tex_mobject.py to have a dont_strip option in both places stripping occurs to get colorization working
#modify config.py to remove projects.ext reference
#scripts\manim %userprofile%\downloads\example_scenes.py SquareToCircle -pl
#CD /D D:\Source\Repos\cryptopals
#-a option for quality, m for medium is 720p
#"%ProgramFiles%\Python37\scripts\manim" manim.py Challenge1 -pl -am

def getPyColors(source):
  from io import BytesIO
  import keyword, token, tokenize
  _KEYWORD = token.NT_OFFSET + 1
  _TEXT    = token.NT_OFFSET + 2
  _colors = {
      token.NUMBER:       '#FFCD22',
      token.OP:           '#E8E2B7',
      token.STRING:       '#EC7600',
      tokenize.COMMENT:   '#66747B',
      token.NAME:         '#678CB1',
      token.ERRORTOKEN:   '#FF8080',
      _KEYWORD:           '#93C763',
      _TEXT:              '#E0E2E4',
  }
  lines, pos = [], 0
  while True:
    pos = source.find('\n', pos) + 1
    if not pos: break
    lines.append(pos)
  lines.append(len(source))
  res = []
  for toktype, toktext, s, e, line in tokenize.tokenize(BytesIO(source.encode('utf-8')).readline):
    (srow,scol), (erow,ecol) = s, e
    if srow == 0 and scol == 0 or srow == 1 and scol == 1: continue
    newpos = lines[srow - 2] + scol
    pos = newpos + len(toktext)
    # handle newlines
    if toktype in [token.NEWLINE, tokenize.NL]:
      continue
    # skip indenting tokens
    if toktype in [token.INDENT, token.DEDENT]:
      continue
    # map token type to a color group
    if token.LPAR <= toktype and toktype <= token.OP:
      toktype = token.OP
    elif toktype == token.NAME and keyword.iskeyword(toktext):
      toktype = _KEYWORD
    color = _colors.get(toktype, _colors[_TEXT])
    #if toktype == token.ERRORTOKEN:
    res.append((newpos, pos, color))     
  return res
  
def getTexFromPyCode(code):
  pretag = "\\begin{lstlisting}[language=Python,style=basic,numbers=none,showtabs=false]\n"
  posttag = "\n\\end{lstlisting}"
  clrs = getPyColors(code)
  #basel = Listings(pretag + code + posttag, 
   #substrings_to_isolate= [code[start:end] for (start, end, _) in clrs if start != end],
   #tex_to_color_map= {code[start:end]: clr for (start, end, clr) in clrs if start != end})
  #basel = Listings(pretag, code, posttag)
  idx, curloc = 0, 0
  codes = []
  while idx != len(clrs):
    if idx == len(clrs) - 1:
      codes.append(code[curloc])
    else:
      codes.append(code[curloc:clrs[idx][1]])
    curloc = clrs[idx][1]
    idx += 1
  codes = [x.replace("|", "|\\textbar|") for x in codes]
  basel = SimpleListings(*codes, arg_separator='', dont_strip=True,
    template_tex_file_body=TEMPLATE_TEXT_FILE_BODY_LISTINGS.replace("\nYourTextHere\n", pretag + "\nYourTextHere\n" + posttag))
  #for (start, end, clr) in clrs:
    #if start != end: basel[start:end].set_color(clr)
    #print(start, end, clr)
    #basel.set_color_by_tex(code[start:end], clr)
    #print(code[start:end], start, end, clr)
  for i, (_start, _end, clr) in enumerate(clrs[:-1]):
    basel[i].set_color(clr)
  return basel
  
def getPyDisplay(title, fileName, code):
  titleobj = TextMobject(title)
  file = TextMobject("\\begin{tabular}{|c|}\\hline\n" + fileName + "\\\\\\hline\\end{tabular}")
  file.set_color("#FAAA3C")
  basel = getTexFromPyCode(code)
  VGroup(titleobj, file, basel).arrange(DOWN)
  return titleobj, file, basel
  
#def replaceTex(str):
#  if str == '(': return '$($'
#  elif str == ')': return '$)$'
#  elif str == ':': return '$:$'
#  else: return str
  
class Challenge1(Scene):
  def construct(self):
    code = """
#https://cryptopals.com/sets/1/challenges/1
def challenge1():
  passResult = ("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBs"
                "aWtlIGEgcG9pc29ub3VzIG11c2hyb29t")
  s = ("49276d206b696c6c696e6720796f757220627261696e206c"
       "696b65206120706f69736f6e6f7573206d757368726f6f6d")
  result = hexToBase64(s)
  bSame = result == passResult
  if not bSame: print("%s != %s" % (result, passResult))
  return bSame
"""
    title, file, basel = getPyDisplay("cryptopals crypto challenge Set 1 Challenge 1", "set1.py", code)
    self.play(
        Write(title), Write(file),
        FadeInFrom(basel, UP),
    )
    self.wait(10)
    self.remove(title, file, basel)
    base64table = ("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                   "abcdefghijklmnopqrstuvwxyz0123456789+/")
    tbl = [TextMobject("\\begin{tiny}\\begin{tabular}{|c|c|c|}\\hline\nIndex & Binary & Char\\\\\n\\hline\n" +
                       ''.join([("{:d} & {:06b} & " + x + "\\\\\n\\hline\n").format(j * 16 + i, j * 16 + i)
                                for i, x in enumerate(base64table[j*16:j*16+16])]) + "\\end{tabular}\\end{tiny}")
           for j in range(0, 4)]
    #TextMobject("Padding: '', '=' or '=='")
    tbl[0].to_edge(LEFT)
    tbl[1].next_to(tbl[0], RIGHT)
    tbl[2].next_to(tbl[1], RIGHT)
    tbl[3].next_to(tbl[2], RIGHT)
    self.add(*tbl)
    self.wait(10)
    self.play(ApplyMethod(tbl[0].next_to, tbl[0], LEFT),
              ApplyMethod(tbl[1].to_edge, LEFT),
              ApplyMethod(tbl[2].next_to, tbl[0], RIGHT),
              ApplyMethod(tbl[3].next_to, tbl[1], RIGHT))
    self.wait(5)
    padtbltex = r"""{\fontsize{1}{4} \selectfont
Given: 1 byte $\equiv$ 1 octet $\equiv$ 8 bits and 1 sextet $\equiv$ 6 bits\\
3 bytes * 8$\frac{bits}{byte}$=24 bits\\
4 sextets * 6$\frac{bits}{sextet}$=24 bits\\
Consider: every 3 bytes, whose bits are $B_0..B_{23}$\\
3 padding possibilities:
\renewcommand{\arraystretch}{2}
\setlength\tabcolsep{0.25 pt}
\vspace{-2em}
\begin{table}[]
\centering
\caption{No padding}
\begin{tabular}{|l|l|l|l|l|l|l|l|l|l|l|l|l|l|l|l|l|l|l|l|l|l|l|l|}
\hline
\multicolumn{8}{|c|}{First Byte} & \multicolumn{8}{c|}{Second Byte} & \multicolumn{8}{c|}{Third Byte}\\
\hline
$B_0$ & $B_1$ & $B_2$ & $B_3$ & $B_4$ & $B_5$ & $B_6$ & $B_7$ & $B_8$ & $B_9$ & $B_{10}$ & $B_{11}$ & $B_{12}$ & $B_{13}$ & $B_{14}$ & $B_{15}$ & $B_{16}$ & $B_{17}$ & $B_{18}$ & $B_{19}$ & $B_{20}$ & $B_{21}$ & $B_{22}$ & $B_{23}$\\
\hline
\multicolumn{6}{|c|}{First Sextet} & \multicolumn{6}{c|}{Second Sextet} & \multicolumn{6}{c|}{Third Sextet} & \multicolumn{6}{c|}{Fourth Sextet}\\
\hline
\end{tabular}
\end{table}
\vspace{-4em}
\setlength\tabcolsep{1.5 pt}
\begin{table}[]
\centering
\caption{Single padding `='}
\begin{tabular}{|l|l|l|l|l|l|l|l|l|l|l|l|l|l|l|l|l|l|l|l|l|l|l|l|}
\hline
\multicolumn{8}{|c|}{First Byte} & \multicolumn{8}{c|}{Second Byte} & \multicolumn{8}{c|}{}\\
\hline
$B_0$ & $B_1$ & $B_2$ & $B_3$ & $B_4$ & $B_5$ & $B_6$ & $B_7$ & $B_8$ & $B_9$ & $B_{10}$ & $B_{11}$ & $B_{12}$ & $B_{13}$ & $B_{14}$ & $B_{15}$ & 0 & 0 & & & & & &\\
\hline
\multicolumn{6}{|c|}{First Sextet} & \multicolumn{6}{c|}{Second Sextet} & \multicolumn{6}{c|}{Third Sextet} & \multicolumn{6}{c|}{`='}\\
\hline
\end{tabular}
\end{table}
\vspace{-4em}
\begin{table}[]
\centering
\caption{Double padding `=='}
\begin{tabular}{|l|l|l|l|l|l|l|l|l|l|l|l|l|l|l|l|l|l|l|l|l|l|l|l|}
\hline
\multicolumn{8}{|c|}{First Byte} & \multicolumn{16}{c|}{}\\
\hline
$B_0$ & $B_1$ & $B_2$ & $B_3$ & $B_4$ & $B_5$ & $B_6$ & $B_7$ & 0 & 0 & 0 & 0 & & & & & & & & & & & &\\
\hline
\multicolumn{6}{|c|}{First Sextet} & \multicolumn{6}{c|}{Second Sextet} & \multicolumn{6}{c|}{`='} & \multicolumn{6}{c|}{`='}\\
\hline
\end{tabular}
\end{table}
}
"""    
    padtbl = TextMobject(padtbltex)
    self.remove(*tbl)
    self.add(padtbl)
    self.wait(10)
    self.remove(padtbl)
    
    fileName = "utility.py"
    code = """
import codecs
def hexToBase64(str):
  #base64 encoding leaves extra new line at end so it is trimmed
  return codecs.encode(codecs.decode(str, "hex"), "base64")[:-1].decode()
"""
    title, file, basel = getPyDisplay("Python 3 built in codecs library solution", fileName, code)
    self.play(
        Write(title), Write(file),
        FadeInFrom(basel, UP),
    )
    self.wait(10)
    self.remove(title, file, basel)

    code = """
#test cases are: all characters from 0 to 255
#in production code: ord('0'), ord('A'), ord('a') should be cached, reused
def hexPartToInt(char):
  return (ord(char) - ord('0') if char >= '0' and char <= '9' else
          ord(char) - ord('A')+10 if char >= 'A' and char <= 'F' else
          ord(char) - ord('a')+10 if char >= 'a' and char <= 'f' else None)
"""
    title, file, basel = getPyDisplay("4-bit hex ASCII character decoder", fileName, code)
    self.play(
        Write(title), Write(file),
        FadeInFrom(basel, UP),
    )
    self.wait(10)
    self.remove(title, file, basel)

    code = """
#test cases are: empty string, odd length string, invalid characters
#   in string, all hex characters 00-FF in string
#in production code: a cached dictionary lookup
def hexStrToBin(str):
  l, res = len(str), []
  if l & 1: return None #cannot decode odd length string
  for i in range(0, l, 2):
    u, v = hexPartToInt(str[i]), hexPartToInt(str[i + 1])
    if u == None or v == None: return None #illegal character encountered
    res.append((u << 4) | v)
  return bytes(res)
"""
    title, file, basel = getPyDisplay("Hex string to bytes", fileName, code)
    self.play(
        Write(title), Write(file),
        FadeInFrom(basel, UP),
    )
    self.wait(10)
    self.remove(title, file, basel)

    code = """
#https://en.wikipedia.org/wiki/Base64
#test cases are: empty string, single byte, two bytes, three bytes
#in production code: base64table and padChar should be cached
#  also specific cases for i%24 in [0,6,12,18] should be done directly
#  not generally as is done here where the code is adapted to any base
def binToBase64(bin):
  base64table = ("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                 "abcdefghijklmnopqrstuvwxyz0123456789+/")
  padChar = ord('=')
  bitLen, res = len(bin) << 3, []
  for i in range(0, bitLen, 6):
    startByte, startBit = i >> 3, i & 7
    val = bin[startByte] & ((1 << (8 - startBit)) - 1) #trim left bits
    if startBit > 2:
      val <<= startBit - 2 #shift to left-most position
      if ((startByte + 1) << 3) < bitLen: #another byte available
        # 10 - startBit comes from 8 - (startBit + 6 - 8)
        val |= bin[startByte + 1] >> (10 - startBit) #shift right, add on
    else: val = (val >> (2 - startBit)) #shift to right-most position
    res.append(ord(base64table[val]))
  remBits = bitLen % 24
  if remBits <= 18 and remBits != 0: res.append(padChar)
  if remBits <= 12 and remBits != 0: res.append(padChar)
  return bytes(res)
"""
    title, file, basel = getPyDisplay("Bytes to Base64 encoding", fileName, code)
    title.to_edge(TOP)
    file.next_to(title, BOTTOM)
    basel.next_to(file, BOTTOM)
    self.add(title, file, basel)
    self.wait(10)
    self.play(ApplyMethod(title.next_to, title, TOP),
              ApplyMethod(file.next_to, title, TOP),
              ApplyMethod(basel.next_to, title, BOTTOM))
    self.wait(5)
    self.remove(title, file, basel)
    
    code = """
def hexToBase64Alt(str):
  res = hexStrToBin(str)
  if res == None: return res
  return binToBase64(res).decode("utf-8")
"""
    title, file, basel = getPyDisplay("Putting it all together\\\\Hex string to Base64 encoding", fileName, code)
    self.play(
        Write(title), Write(file),
        FadeInFrom(basel, UP),
    )
    self.wait(10)
    self.remove(title, file, basel)
    