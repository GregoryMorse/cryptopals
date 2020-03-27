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
#modify C:\Program Files\Python37\Lib\site-packages\manimlib\tex_template.tex to add \usepackage{listings} and \lstloadlanguages{Python}, \lstset{defaultdialect=Python}
#scripts\manim %userprofile%\downloads\example_scenes.py SquareToCircle -pl
#CD /D D:\Source\Repos\cryptopals
#"%ProgramFiles%\Python37\scripts\manim" manim.py Challenge1 -pl

class Challenge1(Scene):
  def construct(self):
    title = TextMobject("cryptopals crypto challenge Set 1 Challenge 1")
    code1 = """
\\begin{lstlisting}[language=Python,style=basic,numbers=none,showtabs=false]
def challenge1():
  passResult = ("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBs"
                "aWtlIGEgcG9pc29ub3VzIG11c2hyb29t")
  s = ("49276d206b696c6c696e6720796f757220627261696e206c"
       "696b65206120706f69736f6e6f7573206d757368726f6f6d")
\\end{lstlisting}
"""
    basel = TextMobject(code1)
    VGroup(title, basel).arrange(DOWN)
    self.play(
        Write(title),
        FadeInFrom(basel, UP),
    )
    self.wait()