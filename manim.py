#!/usr/bin/env python

from manimlib.imports import *

#install sox, MikTex, extract ffmpeg
#set PATH=%PATH%;C:\Users\Gregory\Desktop\Apps\ffmpeg-20200315-c467328-win64-static\bin;C:\program files\MiKTeX 2.9\miktex\bin\x64
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
#--low_quality, --medium_quality, --high_quality or -p[l|m|h] for preview at various quality
#testing with preview and low quality: "%ProgramFiles%\Python37\scripts\manim" manim.py Challenge1 -pl
#preview with medium quality: "%ProgramFiles%\Python37\scripts\manim" manim.py Challenge1 -pm
#preview with high quality: "%ProgramFiles%\Python37\scripts\manim" manim.py Challenge1 -ph
#preview with production quality: "%ProgramFiles%\Python37\scripts\manim" manim.py Challenge1 -pp


TEMPLATE_TEXT_FILE_BODY_TABULAR = TEMPLATE_TEXT_FILE_BODY.replace("\\usepackage[english]{babel}\n", "\\usepackage[english]{babel}\n\\usepackage{caption}\n\\usepackage{multicol}\n\\usepackage{multirow}\n")
class TextMobjectUTF(TextMobject):
  CONFIG = {
      "template_tex_file_body": TEMPLATE_TEXT_FILE_BODY.replace("\\usepackage[english]{babel}\n", "\\usepackage[utf8]{inputenc}\n\\usepackage[T1]{fontenc}\n"),
      "alignment": r"\centering",
  }

TEMPLATE_TEXT_FILE_BODY_LISTINGS = TEMPLATE_TEX_FILE_BODY.replace("\\usepackage{amsmath}\n", "\\usepackage{amsmath}\n\\usepackage{listings}\n\\usepackage{abraces}\n").replace("\n\n" + r"\begin{document}", r"""
\lstdefinestyle{basic}
{  
	basicstyle=\scriptsize\ttfamily,
	tabsize=4, % tab space width
	showtabs=true,
	showstringspaces=false, % don't mark spaces in strings
	numbers=left, % display line numbers on the left
	frame=single,
	numbers=left,
	numbersep=10pt,
	showstringspaces=false,
	breakatwhitespace=false,                 
	captionpos=t,abovecaptionskip=0pt,
	columns=fullflexible,    
	keepspaces=true,
	xleftmargin=10pt,
	framexleftmargin=17pt,
	framexrightmargin=0pt,
	framexbottommargin=0pt,
	framextopmargin=0pt,
	mathescape=false,escapechar=|,%
	framerule=0pt,
	breaklines=false,
}

\begin{document}""").replace("\\begin{align*}\nYourTextHere\n\\end{align*}", "\\begin{lstlisting}[language=Python,style=basic,numbers=none,showtabs=false]\nYourTextHere\n\\end{lstlisting}")

class SingleStringTexMobjectColor(SingleStringTexMobject):
  def get_modified_expression(self, tex_string):
    result = self.alignment + " " + tex_string
    if not self.dont_strip: result = result.strip()
    result = self.modify_special_strings(result)
    return result

class SimpleListings(TexMobject):
  CONFIG={
    "template_tex_file_body": TEMPLATE_TEXT_FILE_BODY_LISTINGS,
    "arg_separator": " ",
    "substrings_to_isolate": [],
    "tex_to_color_map": {},
    "dont_strip": False,
  }
  def __init__(self, *tex_strings, **kwargs):
    digest_config(self, kwargs)
    tex_strings = self.break_up_tex_strings(tex_strings)
    self.tex_strings = tex_strings
    SingleStringTexMobjectColor.__init__(
      self, self.arg_separator.join(tex_strings), **kwargs
    )
    self.break_up_by_substrings()
    self.set_color_by_tex_to_color_map(self.tex_to_color_map)

    if self.organize_left_to_right:
      self.organize_submobjects_left_to_right()

  def get_modified_expression(self, tex_string):
    result = self.alignment + " " + tex_string
    if not self.dont_strip: result = result.strip()
    result = self.modify_special_strings(result)
    return result

  def break_up_tex_strings(self, tex_strings):
    substrings_to_isolate = op.add(
        self.substrings_to_isolate,
        list(self.tex_to_color_map.keys())
    )
    split_list = split_string_list_to_isolate_substrings(
        tex_strings, *substrings_to_isolate
    )
    if not self.dont_strip: split_list = [str(x).strip() for x in split_list]
    #split_list = list(map(str.strip, split_list))
    split_list = [s for s in split_list if s != '']
    return split_list

class SVGMobjectString(SVGMobject):
  def __init__(self, svg_str=None, **kwargs):
    digest_config(self, kwargs)
    self.svg_str = svg_str or self.svg_str
    VMobject.__init__(self, **kwargs)
    self.move_into_position()

  def generate_points(self):
    doc = minidom.parseString(self.svg_str)
    self.ref_to_element = {}
    for svg in doc.getElementsByTagName("svg"):
      mobjects = self.get_mobjects_from(svg)
      if self.unpack_groups:
        self.add(*mobjects)
      else:
        self.add(*mobjects[0].submobjects)
    doc.unlink()

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
  codes = [x.replace("|", r"|\textbar|") for x in codes]
  basel = SimpleListings(*codes, arg_separator='', dont_strip=True)
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
  file = TextMobject(r"\begin{tabular}{|c|}\hline" + "\n" + fileName + r"\\\hline\end{tabular}")
  file.set_color("#FAAA3C")
  basel = getTexFromPyCode(code)
  g = VGroup(titleobj, file, basel)
  g.arrange(DOWN)
  return g

def runCodeShowResult(code, filename):
  import ast
  import copy
  code_ast = ast.parse(code)
  init_ast = copy.deepcopy(code_ast)
  init_ast.body = code_ast.body[:-1]
  last_ast = copy.deepcopy(code_ast)
  last_ast.body = code_ast.body[-1:]
  exec(compile(init_ast, "<ast>", "exec"), globals())
  if type(last_ast.body[0]) == ast.Expr:
    last_ast.body[0].lineno = 0
    last_ast.body[0].col_offset = 0    
    return eval(compile(ast.Expression(last_ast.body[0].value, lineno=0, col_offset=0), "<ast>", "eval"), globals())
  else: exec(compile(last_ast, "<ast>", "exec"), globals())
  #codeObj = compile(code, filename, 'exec')
  #exec(codeObj)
  #eval(expression)
  
def encodeTex(str):
  #\textasciicircum is also valid for ^
  return str.replace("\\", r"\textbackslash").replace("#", r"\#").replace("$", r"\$").replace("%", r"\%").replace("&", r"\&").replace("^", r"\^{}").replace("_", r"\_").replace("{", r"\{").replace("}", r"\}").replace("|", r"\textbar").replace("~", r"\textasciitilde")
  
infinitysym = """<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<!-- Created with Inkscape (http://www.inkscape.org/) -->
<svg
   xmlns:dc="http://purl.org/dc/elements/1.1/"
   xmlns:cc="http://web.resource.org/cc/"
   xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
   xmlns:svg="http://www.w3.org/2000/svg"
   xmlns="http://www.w3.org/2000/svg"
   xmlns:sodipodi="http://inkscape.sourceforge.net/DTD/sodipodi-0.dtd"
   xmlns:inkscape="http://www.inkscape.org/namespaces/inkscape"
   id="svg2"
   sodipodi:version="0.32"
   inkscape:version="0.43"
   width="420"
   height="475"
   sodipodi:docbase="E:\"
   sodipodi:docname="Infinity symbol.svg"
   version="1.0">
  <metadata
     id="metadata7">
    <rdf:RDF>
      <cc:Work
         rdf:about="">
        <dc:format>image/svg+xml</dc:format>
        <dc:type
           rdf:resource="http://purl.org/dc/dcmitype/StillImage" />
      </cc:Work>
    </rdf:RDF>
  </metadata>
  <defs
     id="defs5" />
  <sodipodi:namedview
     inkscape:window-height="719"
     inkscape:window-width="1272"
     inkscape:pageshadow="2"
     inkscape:pageopacity="0.0"
     borderopacity="1.0"
     bordercolor="#666666"
     pagecolor="#ffffff"
     id="base"
     inkscape:zoom="1.0025097"
     inkscape:cx="373.70514"
     inkscape:cy="222.95123"
     inkscape:window-x="0"
     inkscape:window-y="0"
     inkscape:current-layer="svg2"
     inkscape:document-units="m" />
  <g
     id="g1348"
     transform="translate(-3.556579,7.120096)">
    <path
       id="text1306"
       d="M 107.79123,277.25711 C 111.87444,284.59051 116.70777,290.13217 122.29123,293.88211 C 127.87443,297.63216 134.16609,299.50716 141.16623,299.50711 C 149.58274,299.50716 156.45773,296.71549 161.79123,291.13211 C 167.12439,285.46551 169.79105,278.25718 169.79123,269.50711 C 169.79105,261.09053 167.33272,254.09054 162.41623,248.50711 C 157.4994,242.92388 151.33274,240.13222 143.91623,240.13211 C 137.08275,240.13222 130.87442,242.96555 125.29123,248.63211 C 119.7911,254.21554 113.95777,263.75719 107.79123,277.25711 M 92.541229,263.88211 C 88.4578,256.54887 83.624472,251.04887 78.041229,247.38211 C 72.54115,243.71555 66.249489,241.88222 59.166229,241.88211 C 50.666172,241.88222 43.749512,244.63221 38.416229,250.13211 C 33.166189,255.6322 30.541192,262.79886 30.541229,271.63211 C 30.541192,280.04884 32.999523,287.04884 37.916229,292.63211 C 42.832846,298.21549 48.999507,301.00716 56.416229,301.00711 C 63.249492,301.00716 69.457819,298.17383 75.041229,292.50711 C 80.624475,286.8405 86.457802,277.29885 92.541229,263.88211 M 101.41623,286.75711 C 95.582793,298.00716 89.374466,306.29882 82.791229,311.63211 C 76.291146,316.88214 69.124486,319.50714 61.291229,319.50711 C 49.957839,319.50714 40.416182,314.88214 32.666229,305.63211 C 24.916197,296.29883 21.041201,284.71551 21.041229,270.88211 C 21.041201,256.29887 24.499531,244.50721 31.416229,235.50711 C 38.416184,226.50723 47.499508,222.00724 58.666229,222.00711 C 66.582822,222.00724 73.707815,224.63223 80.041229,229.88211 C 86.457802,235.13222 92.66613,243.50721 98.666229,255.00711 C 104.33278,243.50721 110.45778,235.04889 117.04123,229.63211 C 123.62443,224.13223 130.95776,221.38224 139.04123,221.38211 C 150.20774,221.38224 159.70773,226.09056 167.54123,235.50711 C 175.37438,244.84055 179.29104,256.46553 179.29123,270.38211 C 179.29104,284.96551 175.79105,296.71549 168.79123,305.63211 C 161.87439,314.54881 152.83274,319.00714 141.66623,319.00711 C 133.83276,319.00714 126.7911,316.54881 120.54123,311.63211 C 114.37444,306.63215 107.99945,298.34049 101.41623,286.75711"
       style="font-size:256px;font-style:normal;font-variant:normal;font-weight:normal;font-stretch:normal;text-align:start;line-height:100%;writing-mode:lr-tb;text-anchor:start;fill:#000000;fill-opacity:1;stroke:none;stroke-width:1px;stroke-linecap:butt;stroke-linejoin:miter;stroke-opacity:1;font-family:Bitstream Vera Sans" />
  </g>
</svg>"""

emptysetsym = """<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<!-- Created with Inkscape (http://www.inkscape.org/) -->
<svg
   xmlns:dc="http://purl.org/dc/elements/1.1/"
   xmlns:cc="http://web.resource.org/cc/"
   xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
   xmlns:svg="http://www.w3.org/2000/svg"
   xmlns="http://www.w3.org/2000/svg"
   xmlns:sodipodi="http://sodipodi.sourceforge.net/DTD/sodipodi-0.dtd"
   xmlns:inkscape="http://www.inkscape.org/namespaces/inkscape"
   width="400"
   height="400"
   id="svg2"
   sodipodi:version="0.32"
   inkscape:version="0.45"
   sodipodi:modified="true"
   version="1.0">
  <defs
     id="defs4" />
  <sodipodi:namedview
     id="base"
     pagecolor="#ffffff"
     bordercolor="#666666"
     borderopacity="1.0"
     gridtolerance="10000"
     guidetolerance="10"
     objecttolerance="10"
     inkscape:pageopacity="0.0"
     inkscape:pageshadow="2"
     inkscape:zoom="1.3025"
     inkscape:cx="200"
     inkscape:cy="201.25772"
     inkscape:document-units="px"
     inkscape:current-layer="layer1"
     width="400px"
     height="400px"
     showgrid="true"
     inkscape:window-width="1024"
     inkscape:window-height="719"
     inkscape:window-x="-4"
     inkscape:window-y="-4" />
  <metadata
     id="metadata7">
    <rdf:RDF>
      <cc:Work
         rdf:about="">
        <dc:format>image/svg+xml</dc:format>
        <dc:type
           rdf:resource="http://purl.org/dc/dcmitype/StillImage" />
      </cc:Work>
    </rdf:RDF>
  </metadata>
  <g
     inkscape:label="Layer 1"
     inkscape:groupmode="layer"
     id="layer1">
    <path
       style="font-size:12px;font-style:normal;font-weight:normal;fill:#000000;fill-opacity:1;stroke:none;stroke-width:1px;stroke-linecap:butt;stroke-linejoin:miter;stroke-opacity:1;font-family:Bitstream Vera Sans"
       d="M 377.24609,39.84375 L 328.41797,88.671875 C 356.4124,120.4104 370.40979,157.60112 370.41016,200.24414 C 370.40979,247.28202 353.72686,287.44311 320.36133,320.72754 C 286.99516,354.01206 246.79337,370.65429 199.75586,370.6543 C 157.27523,370.65429 120.08452,356.81967 88.183594,329.15039 L 39.84375,377.24609 L 22.753906,360.15625 L 71.337891,312.30469 C 43.343055,280.07821 29.345674,242.72473 29.345703,200.24414 C 29.345674,153.20659 45.98791,113.0455 79.272461,79.760742 C 112.55685,46.476556 152.71795,29.83432 199.75586,29.833984 C 242.39885,29.83432 279.58956,43.831702 311.32813,71.826172 L 360.40039,22.753906 L 377.24609,39.84375 z M 294.23828,88.671875 C 267.21978,65.397436 235.72568,53.760078 199.75586,53.759766 C 159.55388,53.760078 125.08939,68.12367 96.362305,96.850586 C 67.635023,125.57804 53.271431,160.04252 53.271484,200.24414 C 53.271431,236.21432 64.908789,267.70843 88.183594,294.72656 L 294.23828,88.671875 z M 346.24023,200.24414 C 346.23989,164.27429 334.60253,132.78018 311.32813,105.76172 L 105.27344,311.81641 C 132.29153,335.09118 163.78564,346.72853 199.75586,346.72852 C 239.95744,346.72853 274.42193,332.36494 303.14941,303.6377 C 331.8763,274.91057 346.23989,240.44609 346.24023,200.24414 L 346.24023,200.24414 z "
       id="text2160" />
  </g>
</svg>"""

cautionsym = """<?xml version="1.0" encoding="iso-8859-1"?>
<!-- Generator: Adobe Illustrator 18.1.1, SVG Export Plug-In . SVG Version: 6.00 Build 0)  -->
<svg version="1.1" id="Capa_1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" x="0px" y="0px"
	 viewBox="0 0 197.143 197.143" style="enable-background:new 0 0 197.143 197.143;" xml:space="preserve">
<g>
	<g>
		<path style="fill:#010002;" d="M195.031,166.074l-85.592-148.24c-2.226-3.89-6.403-6.306-10.89-6.306
			c-4.477,0-8.65,2.412-10.894,6.292L1.68,166.747c-2.24,3.876-2.24,8.689,0,12.565c2.24,3.887,6.413,6.302,10.887,6.302h172.01
			c6.929,0,12.565-5.644,12.565-12.58C197.143,170.447,196.377,167.956,195.031,166.074z M184.577,178.324H12.571
			c-1.882,0-3.643-1.009-4.585-2.645c-0.945-1.636-0.948-3.665,0-5.3L93.961,21.456c0.941-1.628,2.698-2.645,4.588-2.645
			c1.882,0,3.654,1.016,4.592,2.645l85.764,148.537c0.626,0.895,0.966,1.943,0.966,3.046
			C189.871,175.952,187.491,178.324,184.577,178.324z"/>
		<polygon style="fill:#010002;" points="102.504,134.938 104.486,67.255 89.709,67.255 91.681,134.938 		"/>
		<path style="fill:#010002;" d="M97.096,144.637c-5.146,0-8.879,3.905-8.879,9.28c0,5.39,3.733,9.294,8.879,9.294
			c5.229,0,8.886-3.815,8.886-9.294C105.982,148.452,102.328,144.637,97.096,144.637z"/>
	</g>
</g>
</svg>"""
laptopsym = """<?xml version="1.0" encoding="utf-8"?>
<!-- Svg Vector Icons : http://www.onlinewebfonts.com/icon -->
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" x="0px" y="0px" viewBox="0 0 1000 1000" enable-background="new 0 0 1000 1000" xml:space="preserve">
<metadata> Svg Vector Icons : http://www.onlinewebfonts.com/icon </metadata>
<g><g transform="translate(0.000000,511.000000) scale(0.100000,-0.100000)"><path d="M1934.1,3060.2l-63.2-55.5l-5.7-1793.9c-5.8-1958.5-7.7-1889.6,103.4-1941.3c34.5-15.3,846.2-21.1,3051.7-21.1H8026l61.3,55.5l63.2,55.5v1822.6v1822.6l-63.2,55.5l-61.3,55.5H5010.7H1995.3L1934.1,3060.2z M7738.8,1182.1V-349.5H5010.7H2282.5v1531.6v1531.6h2728.1h2728.1V1182.1z"/><path d="M2743.9,1551.6c0-719.8,0-723.7,34.5-618.4c90,283.3,252.7,539.9,488.2,777.3c247,245.1,478.6,388.6,825.1,507.3l153.2,53.6l-750.5,1.9H2742L2743.9,1551.6z"/><path d="M1838.3-843.4c-19.1-7.7-417.4-382.9-886.4-834.7C176.6-2424.8,100-2503.3,100-2558.8c0-105.3,55.5-254.6,109.1-296.7l49.8-40.2h4751.8h4753.7l47.9,57.4c53.6,63.2,101.5,239.3,84.2,308.2C9883-2476.5,8240.4-887.4,8163.8-853c-40.2,17.2-779.2,23-3172.3,23C3276.1-830,1855.6-837.7,1838.3-843.4z M2433.8-994.7c-105.3-139.7-103.4-139.7-331.2-139.7H1892l84.2,86.2l84.2,86.2h199.1C2447.2-962.1,2458.7-964,2433.8-994.7z M3100-1042.5l-47.9-82.3l-214.4-5.7c-118.7-1.9-210.6,1.9-206.8,9.6c1.9,7.7,26.8,47.9,53.6,86.2l47.9,72.8h208.7h206.8L3100-1042.5z M3800.7-1048.3l-28.7-86.2h-208.7c-120.6,0-208.7,7.7-208.7,19.1c0,9.6,15.3,47.9,32.5,86.2l32.5,67h204.9h206.8L3800.7-1048.3z M4511-1023.4c-5.7-34.5-13.4-74.6-19.1-86.2c-3.8-19.1-65.1-24.9-218.3-24.9c-193.4,0-212.5,3.8-202.9,34.5c5.7,17.2,15.3,55.5,23,86.2l11.5,51.7h208.7h208.7L4511-1023.4z M5211.7-1048.3v-86.2h-210.6h-210.6v86.2v86.2h210.6h210.6V-1048.3z M5899-1004.2c51.7-141.7,67-130.2-178.1-130.2c-218.2,0-222.1,0-222.1,44c0,23-5.7,61.3-11.5,86.2c-11.5,42.1-9.6,42.1,191.4,42.1C5872.2-962.1,5883.7-964,5899-1004.2z M6609.3-1038.7c21-40.2,38.3-80.4,38.3-86.2s-93.8-9.6-208.7-9.6h-208.7l-30.6,76.6c-17.2,42.1-30.6,82.3-30.6,86.2c0,5.7,90,9.6,201,9.6h201L6609.3-1038.7z M7304.2-1023.4c84.2-116.8,91.9-111-137.8-111h-212.5l-47.9,76.6c-26.8,42.1-47.9,80.4-47.9,86.2c0,5.7,90,9.6,199.1,9.6h201L7304.2-1023.4z M8010.7-1032.9c40.2-38.3,72.7-78.5,72.7-86.2c0-7.6-91.9-15.3-204.9-15.3h-206.8l-49.8,63.2c-90,113-93.8,109.1,118.7,109.1h197.2L8010.7-1032.9z M2205.9-1264.6c0-9.6-30.6-57.4-68.9-105.3l-70.8-90h-225.9c-126.4,0-227.8,5.7-227.8,13.4c0,7.6,40.2,55.5,90,105.3l90,91.9h206.8C2112.1-1249.3,2205.9-1257,2205.9-1264.6z M2969.8-1262.7c0-9.6-24.9-53.6-53.6-101.5l-51.7-86.2L2631-1456c-128.3-1.9-233.6,0-233.6,5.7c0,5.7,30.6,51.7,68.9,105.3l68.9,95.7h218.3C2874.1-1249.3,2971.7-1255,2969.8-1262.7z M3718.4-1272.3c0-13.4-17.2-61.3-38.3-105.3l-36.4-82.3h-231.7c-126.4,0-229.7,3.8-229.7,9.6c0,5.7,21.1,53.6,47.9,105.3l47.9,95.7h220.2C3660.9-1249.3,3718.4-1255,3718.4-1272.3z M4465-1295.2c0-24.9-5.7-72.8-11.5-105.3l-11.5-59.3h-227.8c-254.6,0-247-3.8-206.8,139.8l19.1,70.8h218.3C4463.1-1249.3,4465-1249.3,4465-1295.2z M5227-1358.4l5.7-101.5H5003h-231.7v91.9c0,51.7,5.7,99.6,13.4,107.2c7.7,5.7,109.1,9.6,224,7.6l212.5-5.7L5227-1358.4z M5975.6-1283.7c9.6-17.2,23-65.1,30.6-105.3l13.4-70.8h-231.7c-126.3,0-231.6,5.7-231.6,15.3c-1.9,7.7-9.6,49.8-17.2,93.8c-9.6,44-11.5,86.2-5.7,91.9c5.7,5.7,103.4,9.6,216.3,9.6C5927.7-1249.3,5960.2-1253.1,5975.6-1283.7z M6768.2-1354.6l51.7-105.3h-237.4h-237.4l-30.6,90c-17.2,49.8-30.6,95.7-30.6,105.3c0,7.6,97.6,15.3,216.3,15.3h216.3L6768.2-1354.6z M8418.4-1473.3c114.9-124.4,229.7-248.9,256.5-277.6l47.9-53.6h-260.4H8204l-132.1,170.4l-132.1,172.3h-396.3l-398.2,1.9l-47.9,78.5c-91.9,143.6-135.9,132.1,520.8,132.1h593.5L8418.4-1473.3z M1886.2-1689.6l-91.9-114.9h-256.5c-289.1,0-279.5-11.5-128.3,149.3l76.6,80.4h245.1h247L1886.2-1689.6z M2780.3-1584.3c0-5.7-26.8-57.4-59.4-114.9l-59.4-105.3h-258.5c-199.1,0-254.6,5.7-243.1,24.9c7.7,11.5,44,63.2,78.5,114.9l67,90h237.4C2673.1-1574.7,2780.3-1578.6,2780.3-1584.3z M3603.5-1584.3c0-3.8-17.2-55.5-40.2-114.9l-38.3-105.3h-258.5H3010l57.4,114.9l57.4,114.9h239.3C3496.3-1574.7,3603.5-1578.6,3603.5-1584.3z M4417.2-1645.6c-28.7-176.1,1.9-158.9-289.1-158.9c-233.6,0-258.5,3.8-248.9,30.6c7.7,17.2,21.1,68.9,32.5,114.9l21.1,84.2h248.9h247L4417.2-1645.6z M5250-1689.6v-114.9h-245.1c-135.9,0-250.8,3.8-254.6,7.7c-3.8,3.8-3.8,55.5-1.9,114.9l7.7,107.2h247h247V-1689.6z M6088.5-1672.4c13.4-53.6,23-105.3,23-114.9c0-21.1-492-23-503.5-1.9c-5.7,7.7-15.3,59.4-23,114.9l-13.4,99.6h247h248.9L6088.5-1672.4z M6934.7-1689.6l59.3-116.8l-262.3,5.7l-260.4,5.7l-36.4,95.7c-19.1,53.6-36.4,101.5-36.4,111c0,7.7,107.2,13.4,239.3,13.4h239.3L6934.7-1689.6z M7761.8-1664.7c36.4-51.7,70.8-103.4,80.4-114.9c11.5-19.2-42.1-24.9-243.1-24.9h-258.5l-67,114.9l-68.9,114.9h245.1h247L7761.8-1664.7z M1608.6-2030.4c-13.4-19.1-63.2-84.2-111-143.6l-86.2-109.1H1130c-157,0-283.3,5.7-283.3,11.5c0,5.8,57.4,70.8,128.3,143.6l126.4,132.1h266.1C1620.1-1995.9,1631.6-1997.8,1608.6-2030.4z M6230.2-2130c19.1-68.9,34.5-130.2,34.5-137.8c0-9.6-1003.2-15.3-2230.4-15.3c-1227.2,0-2230.4,5.7-2230.4,15.3c1.9,7.7,44,70.8,97.6,143.6l93.8,128.3l2100.2-3.8l2098.3-5.7L6230.2-2130z M7154.9-2130c36.4-72.7,67-137.8,67-143.6s-128.3-9.6-285.3-9.6h-285.2l-49.8,130.2c-26.8,70.8-49.8,135.9-49.8,143.6s120.6,13.4,268,13.4h268L7154.9-2130z M8079.6-2112.7c130.2-181.9,141.7-170.4-176.1-170.4h-279.5l-44,72.7c-24.9,38.3-63.2,103.4-88.1,143.6l-44,70.8h275.7l273.8-1.9L8079.6-2112.7z M8994.7-2095.5c51.7-55.5,111.1-120.6,130.2-143.6l36.4-44h-287.2h-285.3l-95.7,120.6c-53.6,65.1-103.4,130.2-111.1,143.6c-11.5,17.2,44.1,23,250.8,23H8899L8994.7-2095.5z"/></g></g>
</svg>"""

channel = r"\textbf{Coding\\4\\Perfection}"
namepre = "Video By: "
name = r"\textbf{Gregory Morse}"
email = "E-mail: " + r"\textbf{gregory.morse@live.com}"

class Coding4Perfection(Scene):
  def showLogo(self):
    import keyword
    kws = [TextMobject(x) for x in keyword.kwlist]
    for x in kws: x.set_color("#93C763")
    ltopsym = SVGMobjectString(laptopsym)
    ltopsym.stretch_to_fit_width(FRAME_X_RADIUS * 2)
    ltopsym.stretch_to_fit_height(-FRAME_Y_RADIUS * 2)
    ltopsym.set_color(GRAY)
    infsym = SVGMobjectString(infinitysym)
    infsym.set_color(GREEN)
    infsym.scale(0.5)
    cautsym = SVGMobjectString(cautionsym)
    cautsym.set_color(YELLOW)
    cautsym.scale(0.5)
    emptysym = SVGMobjectString(emptysetsym)
    emptysym.set_color(RED)
    emptysym.scale(0.5)
    logo = VGroup(Dot(color=GREEN, radius=0.5), Circle(color=YELLOW, radius=0.5), Circle(color=RED, radius=0.5))
    logo.arrange(DOWN)
    c = TextMobject(channel)
    n = TextMobject(namepre + r"\\" + name)
    n.scale(0.7)
    txt = VGroup(c, n)
    txt.arrange(DOWN)
    intro = Group(txt, logo)
    intro.arrange(RIGHT)
    intro.to_edge(TOP / 2)
    infsym.move_to(logo[0])
    cautsym.move_to(logo[1])
    emptysym.move_to(logo[2])
    e = TextMobject(email)
    e.scale(0.7)
    e.move_to(DOWN)
    kws[0].to_edge(RIGHT)
    circles = [Arc(TAU * i / len(kws), 2 * TAU, radius=FRAME_Y_RADIUS * 1.5) for i in range(len(kws))]
    self.play(FadeInFrom(c, UP), FadeInFrom(logo, RIGHT), FadeInFrom(n, DOWN), FadeInFrom(ltopsym, LEFT), GrowFromCenter(e), *[MoveAlongPath(kws[i], circles[i], run_time=5) for i in range(len(kws))])
    backcircles = [Arc(TAU * i / len(kws), -2 * TAU, radius=FRAME_Y_RADIUS * 1.5) for i in range(len(kws))]
    self.play(*[MoveAlongPath(kws[i], backcircles[i], run_time=5) for i in range(len(kws))])
    self.play(FadeOut(n), FadeOut(e), ApplyMethod(c.shift, (0, -n.get_height() / 2, 0)), Transform(logo[0], infsym), Transform(logo[1], cautsym), Transform(logo[2], emptysym), *[FadeOut(x) for x in kws])
    self.play(ApplyMethod(c.set_color, BLUE))
    self.play(*[ApplyMethod(x.scale, 0.3) for x in [c, logo]])
    self.play(ApplyMethod(ltopsym.scale, 0.3), ApplyMethod(logo.move_to, logo.get_center() * 0.3), ApplyMethod(c.move_to, c.get_center() * 0.3))
    cur = ltopsym.get_center()
    self.play(ApplyMethod(ltopsym.to_edge, LEFT+DOWN))
    self.play(*[ApplyMethod(x.shift, ltopsym.get_center() - cur) for x in [c, logo]])
    self.play(*[ApplyMethod(x.fade, 0.7) for x in [c, logo, ltopsym]])
    #self.remove(c, logo, ltopsym)
  def showOutro(self):
    pass
 
class Challenge1(Coding4Perfection):
  def construct(self):
    tblBase16 = r"""
\begin{tiny}
  \begin{table}
    \centering
    \begin{tabular}{|r|l|l|}
         \hline
         \textbf{Decimal} & \textbf{Hexadecimal} & \textbf{Binary} \\ \hline
""" + ''.join([r"{:d} & {:X} & {:04b}\\".format(j, j, j) + "\n" + r"\hline" + "\n" for j in range(16)]) + r"""
    \end{tabular}
    \caption*{Single Hexadecimal Digits}
  \end{table}
\end{tiny}
"""
    chrNames = {0: "NUL", 1: "SOH", 2: "STX", 3: "ETX", 4: "EOT", 5: "ENQ", 6: "ACK", 7: "BEL",
      8: "BS", 9: "TAB", 10: "LF", 11: "VT", 12: "FF", 13: "CR", 14: "SO", 15: "SI",
      16: "DLE", 17: "DC1", 18: "DC2", 19: "DC3", 20: "DC4", 21: "NAK", 22: "SYN", 23: "ETB",
      24: "CAN", 25: "EM", 26: "SUB", 27: "ESC", 28: "FS", 29: "GS", 30: "RS", 31: "US",
      32: "Space", 127: "DEL"}
    chrDesc = ["null", "start of heading", "start of text", "end of text",
      "end of transmission", "enquiry", "acknowledge", "bell",
      "backspace", "horizontal tab", "NL line feed, new line", "vertical tab",
      "NP form feed, new page", "carriage return", "shift out", "shift in",
      "data link escape", "device control 1", "device control 2", "device control 3",
      "device control 4", "negative acknowledge", "synchronous idle", "end of trans. block",
      "cancel", "end of medium", "substitute", "escape",
      "file separator", "group separator", "record separator", "unit separator"]
    tblAsciiCapt = "Single Hexadecimal Digits"
    #import codecs #codecs.encode(chr(i), "utf-8")
    #extended ASCII: 128 through 160 and 173 are not printable
    tblAscii = [r"""
\begin{tiny}
  \begin{table}
    \centering
    \begin{tabular}{|r|r|r|l|""" + ("l|" if j < 2 else "") + r"""}
         \hline
         \textbf{Dec} & \textbf{Hx} & \textbf{Oct} & \textbf{Char} """ + ("& " if j < 2 else "") + r"""\\
         \hline
""" + ''.join(["{:d} & {:X} & {:03o} & ".format(i, i, i) + ("" if i >= 128 and i <= 160 or i == 173 else (encodeTex(chr(i)) if chr(i).isprintable() else chrNames[i])) + (" & " + chrDesc[i] if i < 32 else "") + r"\\" + "\n" + r"\hline" + "\n" for i in range(j * 16, (j + 1) * 16)]) + r"""
    \end{tabular}
  \end{table}
\end{tiny}
""" for j in range(16)]
    base64table = ("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                   "abcdefghijklmnopqrstuvwxyz0123456789+/")
    base64tableCapt = "Base-64 Character Encoding Table"
    tblBase64 = [r"""
\begin{tiny}
  \begin{table}
    \centering
    \begin{tabular}{|c|c|c|}
      \hline
      Index & Binary & Char\\
      \hline
""" + ''.join([("{:d} & {:06b} & " + x + r"\\" + "\n" + r"\hline" + "\n").format(j * 16 + i, j * 16 + i)
               for i, x in enumerate(base64table[j*16:j*16+16])]) + r"""
    \end{tabular}
  \end{table}
\end{tiny}
""" for j in range(0, 4)]
    #"Padding: '', '=' or '=='"
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
\caption*{No padding}
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
\caption*{Single padding `='}
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
\caption*{Double padding `=='}
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
    tblBitwiseAnd = r"""
\begin{table}
    \centering
    \begin{tabular}{|c|c|c|c|c|}
         \hline
         \textbf{$a$} & \multirow{5}{*}{$\&$} & \textbf{$b$} & \multirow{5}{*}{$=$} & \textbf{$a\& b$} \\ \cline{1-1} \cline{3-3} \cline{5-5}
         0 & & 0 & & 0 \\ \cline{1-1} \cline{3-3} \cline{5-5}
         0 & & 1 & & 0 \\ \cline{1-1} \cline{3-3} \cline{5-5}
         1 & & 0 & & 0 \\ \cline{1-1} \cline{3-3} \cline{5-5}
         1 & & 1 & & 1 \\ \hline
    \end{tabular}
    \caption*{Bitwise And/Multiplication\\$a\& b\equiv a*b$}
\end{table}
"""
    tblBitwiseOr = r"""
\begin{table}
    \centering
    \begin{tabular}{|c|c|c|c|c|}
         \hline
         \textbf{$a$} & \multirow{5}{*}{$\mathbin{|}$} & \textbf{$b$} & \multirow{5}{*}{$=$} & \textbf{$a\mathbin{|}b$} \\ \cline{1-1} \cline{3-3} \cline{5-5}
         0 & & 0 & & 0 \\ \cline{1-1} \cline{3-3} \cline{5-5}
         0 & & 1 & & 1 \\ \cline{1-1} \cline{3-3} \cline{5-5}
         1 & & 0 & & 1 \\ \cline{1-1} \cline{3-3} \cline{5-5}
         1 & & 1 & & 1 \\ \hline
    \end{tabular}
    \caption*{Bitwise Or\\$a\mathbin{|}b\equiv (a+b+a*b) \% 2\equiv (a+b)\chi_{[1, 2]}\equiv \begin{cases}a+b\ge 1 & 1\\\text{otherwise} & 0\end{cases}$}
\end{table}
"""
    tblBitwiseXor = r"""
\begin{table}
    \centering
    \begin{tabular}{|c|c|c|c|c|}
         \hline
         \textbf{$a$} & \multirow{5}{*}{$\wedge$} & \textbf{$b$} & \multirow{5}{*}{$=$} & \textbf{$a\wedge b$} \\ \cline{1-1} \cline{3-3} \cline{5-5}
         0 & & 0 & & 0 \\ \cline{1-1} \cline{3-3} \cline{5-5}
         0 & & 1 & & 1 \\ \cline{1-1} \cline{3-3} \cline{5-5}
         1 & & 0 & & 1 \\ \cline{1-1} \cline{3-3} \cline{5-5}
         1 & & 1 & & 0 \\ \hline
    \end{tabular}
    \caption*{Bitwise Xor/Addition Modulo 2\\$a\wedge b \equiv (a + b) \% 2$}
\end{table}
"""
    tblFastestOps = r"""
\begin{small}
\begin{table}
    \centering
    \begin{tabular}{|c|c|}
         \hline
         Bitwise Not & $\sim a$\\ \hline
         Bitwise And & $a\& b$\\ \hline
         Bitwise Or & $a\mathbin{|} b$\\ \hline
         Bitwise Xor & $a\wedge b$\\ \hline
         Shift Left & $a << b$\\ \hline
         Shift Right & $a >> b$\\ \hline
         Circular Shift/Rotate Left & $(a << b) \mathbin{|} (a >> (\text{sizeof}(a) - b))$\\
         (rarely available in HLL) & $b\neq 0, b\neq \text{sizeof}(a)$\\ \hline
         Circular Shift/Rotate Right & $(a >> b) \mathbin{|} (a << (\text{sizeof}(a) - b))$\\
         (rarely available in HLL) & $b \neq 0, b\neq \text{sizeof}(a)$\\ \hline
    \end{tabular}
    \caption*{Dependence Free Fastest Operations O(1)\\in High Level Languages(HLL)}
\end{table}
\end{small}
"""
    tblFastOps = r"""
\begin{tiny}
\begin{table}
    \centering
    \begin{tabular}{|c|c|}
         \hline
         Addition & $a+b$\\ \hline
         Increment & $a+1$\\ \hline
         Subtraction & $a-b\equiv a+(-b)$\\ \hline
         Decrement & $a-1\equiv a+(-1)$\\ \hline
         Negation & $-a \equiv \sim a+1$\\ \hline
         Comparison & \shortstack[c]{$a=b\equiv a-b=0$\\$a\neq b\equiv a-b\neq 0$\\$a>b\equiv a-b>0$\\$a<b\equiv a-b<0$\\$a\ge b\equiv a-b\ge 0$\\$a\le b\equiv a-b\le 0$}\\ \hline
         Test Comparison & \shortstack[c]{$a\square 0\equiv a\&a\square 0$\\$\square \in \{=, \neq, <, >, \ge, \le\}$}\\ \hline
         Carry Check (rarely available in HLL) & \shortstack[c]{$a\square b\ge(1 << \text{sizeof}(a))$\\$a\square b<(1 << \text{sizeof}(a)), \square \in {+, -}$}\\ \hline
    \end{tabular}
    \caption*{Dependent Carry Operations O(n) in HLL\\Can assume one CPU clock cycle in modern processors\\due to carry look-ahead and units such as 4-bit adders}
\end{table}
\end{tiny}
"""
    tblBitOps = r"""
\begin{tiny}
\begin{table}
    \centering
    \begin{tabular}{|c|c|}
         \hline
         \multicolumn{2}{|c|}{\textbf{Multiply/Divide/Modulo by power of $2^n$ via shifting}}\\ \hline
         Multiply by powers of 2 & $v*2^n \equiv v << n$\\ \hline
         Integer Divide by powers of 2 & $\lfloor \frac{v}{2^n} \rfloor \equiv v >> n$\\ \hline
         Power of $2^n$ remainders & $v \% 2^n \equiv v \& ((1 << n) - 1)$\\ \hline
         \multicolumn{2}{|c|}{\text{Most important bit-masking/combining techniques}}\\ \hline
         First $n$-contiguous bits of value $v$ & $v \& ((1 << n) - 1)$\\ \hline
         Last $n$-contiguous bits of $m$-bit value $v$ & $v >> (m - n)$\\ \hline
         Middle $n$-contiguous bits & $(v >> (m - n - p)) \& ((1 << n) - 1)$\\
         starting at $p$ of $m$-bit value $v$ & $\equiv (v \& ((1 << (n + p)) - 1)) >> (m - n - p)$\\ \hline
         \shortstack[c]{Addition of values with\\non-overlapping bits} & $a + b \equiv a \mathbin{|} b \equiv a \wedge b$\\ \hline
         \multicolumn{2}{|c|}{\textbf{Changing individual bits}}\\ \hline
         Turn off $n$th bit & $v \& \sim (1 << n)$\\ \hline
         Turn on $n$th bit & $v \mathbin{|} (1 << n)$\\ \hline
         Toggle/flip $n$th bit & $v \wedge (1 << n)$\\ \hline
         \shortstack[c]{Turn off $n$th bit for integer\\data type without size} & $\begin{cases} v \& (1 << n) \neq 0 & v \wedge (1 << n) \\ \text{otherwise} & v \end{cases}$\\ \hline
    \end{tabular}
    \caption*{Very Common Bit Operations}
\end{table}
\end{tiny}
"""
    #https://software.intel.com/en-us/articles/intel-sdm
    title = "cryptopals crypto challenge Set 1 Challenge 1"
    challenge1 = ("Convert hex to base64", 
                  (r"The string:\\",
                    r"49276d206b696c6c696e6720796f757220627261696e206c\\" +
                    r"696b65206120706f69736f6e6f7573206d757368726f6f6d\\",
                    r"Should produce:\\",
                    r"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBs\\" +
                    r"aWtlIGEgcG9pc29ub3VzIG11c2hyb29t\\",
                    r"So go ahead and make that happen.\\" +
                    r"You'll need to use this code for the rest of the exercises.\\",
                    r"Cryptopals Rule\\",
                    r"Always operate on raw bytes, never on encoded strings.\\" + 
                    "Only use hex and base64 for pretty-printing."),
                    ((WHITE, BLACK), (DARK_GRAY, LIGHT_GRAY), (WHITE, BLACK), (DARK_GRAY, LIGHT_GRAY), (WHITE, BLACK), (WHITE, ORANGE), (WHITE, BLACK)))
    codeChallenge1 = """
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
    curSet = "set1.py"
    fileName = "utility.py"
    captHexToBase64 = "Python 3 built in codecs library solution"
    codeHexToBase64 = """
import codecs
def hexToBase64(str):
  #base64 encoding leaves extra new line at end so it is trimmed
  return codecs.encode(codecs.decode(str, "hex"), "base64")[:-1].decode()
"""
    captHexPartToInt = "4-bit hex ASCII character decoder"
    codeHexPartToInt = """
#test cases are: all characters from 0 to 255
#in production code: ord('0'), ord('A'), ord('a') should be cached, reused
def hexPartToInt(char):
  return (ord(char) - ord('0') if char >= '0' and char <= '9' else
          ord(char) - ord('A')+10 if char >= 'A' and char <= 'F' else
          ord(char) - ord('a')+10 if char >= 'a' and char <= 'f' else None)
"""
    captGetHexPartToInt = "4-bit hex ASCII character decoder with cached reused values"
    codeGetHexPartToInt = """
#in production code: use cached 256 byte table lookup for performance
def getHexPartToInt():
  ord0, ordA, orda = ord('0'), ord('A'), ord('a') #allow capturing
  def hexPartToIntInner(char):
    return (ord(char) - ord0 if char >= '0' and char <= '9' else
            ord(char) - ordA + 10 if char >= 'A' and char <= 'F' else
            ord(char) - orda + 10 if char >= 'a' and char <= 'f' else None)
  return hexPartToIntInner
hexPartToIntFaster = getHexPartToInt()
"""
    captGetHexPartToIntTable = "4-bit hex ASCII character decoder with table lookup"
    codeGetHexPartToIntTable = """
def getHexPartToIntTable():
  tbl = ([None] * ord('0') + list(range(0, 10)) +
         [None] * (ord('A') - ord('9') - 1) + list(range(10, 16)) +
         [None] * (ord('a') - ord('F') - 1) + list(range(10, 16)) +
         [None] * (255 - ord('f')))
  def hexPartToTableInner(char):
    return tbl[ord(char)]
  return hexPartToTableInner
hexPartToIntTable = getHexPartToIntTable()
"""
    captHexStrToBin = "Hex string to bytes"
    codeHexStrToBin = """
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
    captBinToBase64 = "Bytes to Base64 encoding"
    codeBinToBase64 = """
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
    captHexToBase64Alt = "Putting it all together\\\\Hex string to Base64 encoding"
    codeHexToBase64Alt = """
def hexToBase64Alt(str):
  res = hexStrToBin(str)
  if res == None: return res
  return binToBase64(res).decode("utf-8")
"""
    captTestHexPartToInt = "Testing 4-bit hex ASCII character decoder"
    codeTestHexPartToInt = """
def testHexPartToInt():
  import binascii
  for i in range(0, 256):
    part = hexPartToInt(chr(i))      
    if part != None and part != int.from_bytes(
      codecs.decode('0' + chr(i), "hex"), byteorder='little'):
      return False
    elif part == None:
      try:
        codecs.decode('0' + chr(i), "hex")
        return False
      except ValueError: pass
      except binascii.Error: pass
    if (hexPartToIntFaster(chr(i)) != part or
        hexPartToIntTable(chr(i)) != part): return False
  return True
"""
    captTestConversions = "Testing Hex string to bytes and Bytes to Base64 encoding"
    codeTestConversions = """
def testHexStrToBin():
  for i in range(0, 256):
    if hexStrToBin("%0.2X" % i) != codecs.decode("%0.2X" % i, "hex"):
      return False
  return True
def testBinToBase64():
  #Vanilla Ice - Ice Ice Baby
  testStr = b"I'm killing your brain like a poisonous mushroom"
  for i in range(0, len(testStr)):
    if (binToBase64(testStr[:-i]) !=
        codecs.encode(testStr[:-i],"base64")[:-1]): return False
  return True
"""
    captTestUtility = "Test Controller"
    codeTestUtility = """
def testUtility():
  testSet = [(testHexPartToInt, "hexPartToInt"),
             (testHexStrToBin, "hexStrToBin"),
             (testBinToBase64, "binToBase64")]
  bPassAll = True
  for s in testSet:
    if not s[0]():
      bPassAll = False
      print("Failed %s" % s[1])
  if bPassAll: print("All utility tests passed")
"""
     
    def showChallenge(): 
      probtext = TextMobject(*challenge1[1])
      for i, (clr, bkclr) in enumerate(challenge1[2]):
        probtext[i].set_color(clr)
        if bkclr != BLACK: probtext[i].add_background_rectangle(bkclr, buff=SMALL_BUFF)
      g = VGroup(TextMobject(title), TextMobject(r"\begin{tabular}{|c|}\hline" + "\n" + r"\textbf{" + challenge1[0] + r"}\\\hline\end{tabular}"), probtext)
      g[0].add_background_rectangle(YELLOW, buff=SMALL_BUFF)
      g.arrange(DOWN)
      self.play(FadeInFrom(g, UP))
      self.wait(10)
      #self.play(ApplyMethod(probtext[0].add_background_rectangle, YELLOW_E, 0.4, buff=SMALL_BUFF))
      #self.wait(10)
      self.remove(g)
      
    def showSolution():
      g = getPyDisplay(title, curSet, codeChallenge1)
      self.play(FadeInFrom(g, UP))
      self.wait(10)
      self.remove(g)
    
    def showHexTable():
      tbl = TextMobject(tblBase16, template_tex_file_body=TEMPLATE_TEXT_FILE_BODY_TABULAR)
      self.play(FadeInFrom(tbl, UP))
      self.wait(10)
      self.remove(tbl)
      
    def showAsciiTable():
      tbl = [TextMobjectUTF(tblAscii[j]) for j in range(16)]
      tbl[0].to_edge(LEFT)
      for i in range(1, 16): tbl[i].next_to(tbl[i - 1], RIGHT)
      tbl.append(TextMobject(tblAsciiCapt))
      tbl[16].to_edge(UP)
      self.play(*[FadeInFrom(x, UP) for x in tbl])
      self.wait(10)
      self.play(*[ApplyMethod(tbl[i].shift, tbl[0].get_left() - tbl[1].get_left()) for i in range(16)])
      self.wait(10)
      self.play(*[ApplyMethod(tbl[i].shift, tbl[1].get_left() - tbl[2].get_left()) for i in range(16)])
      self.wait(10)
      self.play(*[ApplyMethod(tbl[i].shift, tbl[2].get_left() - tbl[4].get_left()) for i in range(16)])
      self.wait(10)
      self.play(*[ApplyMethod(tbl[i].shift, tbl[4].get_left() - tbl[6].get_left()) for i in range(16)])
      self.wait(10)
      self.play(*[ApplyMethod(tbl[i].shift, tbl[6].get_left() - tbl[8].get_left()) for i in range(16)])
      self.wait(10)
      self.play(*[ApplyMethod(tbl[i].shift, tbl[8].get_left() - tbl[10].get_left()) for i in range(16)])
      self.wait(10)
      self.play(*[ApplyMethod(tbl[i].shift, tbl[10].get_left() - tbl[12].get_left()) for i in range(16)])
      self.wait(10)
      self.play(*[ApplyMethod(tbl[i].shift, tbl[12].get_left() - tbl[14].get_left()) for i in range(16)])
      self.wait(10)

      self.remove(*tbl)
      
    def showTableBase64():
      tbl = [TextMobject(tblBase64[j]) for j in range(4)]
      tbl[0].to_edge(LEFT)
      tbl[1].next_to(tbl[0], RIGHT)
      tbl[2].next_to(tbl[1], RIGHT)
      tbl[3].next_to(tbl[2], RIGHT)
      tbl.append(TextMobject(base64tableCapt))
      tbl[4].to_edge(UP)
      self.play(*[FadeInFrom(x, UP) for x in tbl])
      self.wait(10)
      self.play(*[ApplyMethod(tbl[i].shift, tbl[0].get_left() - tbl[1].get_left()) for i in range(4)])
      self.wait(5)
      self.remove(*tbl)

    def showTablePaddingBase64():
      padtbl = TextMobject(padtbltex, template_tex_file_body=TEMPLATE_TEXT_FILE_BODY_TABULAR)
      self.play(FadeInFrom(padtbl, UP))
      self.wait(10)
      self.remove(padtbl)
    
    def showHexToBase64():
      g = getPyDisplay(captHexToBase64, fileName, codeHexToBase64)
      self.play(FadeInFrom(g, UP))
      self.wait(10)
      self.remove(g)

    def showHexPartToInt():
      g = getPyDisplay(captHexPartToInt, fileName, codeHexPartToInt)
      self.play(FadeInFrom(g, UP))
      self.wait(10)
      self.remove(g)
    
    def showGetHexPartToInt():
      g = getPyDisplay(captGetHexPartToInt, fileName, codeGetHexPartToInt)
      self.play(FadeInFrom(g, UP))
      self.wait(10)
      self.remove(g)

    def showGetHexPartToIntTable():
      g = getPyDisplay(captGetHexPartToIntTable, fileName, codeGetHexPartToIntTable)
      self.play(FadeInFrom(g, UP))
      self.wait(10)
      self.remove(g)

    def showHexStrToBin():
      g = getPyDisplay(captHexStrToBin, fileName, codeHexStrToBin)
      self.play(FadeInFrom(g, UP))
      self.wait(10)
      self.remove(g)
      
    def showBitwise():
      o = TextMobject.CONFIG.copy()
      o['template_tex_file_body']=TEMPLATE_TEXT_FILE_BODY_TABULAR
      tbl = TextMobject(tblBitwiseAnd, CONFIG=o, template_tex_file_body=TEMPLATE_TEXT_FILE_BODY_TABULAR)
      self.play(FadeInFrom(tbl, UP))
      self.wait(5)
      self.remove(tbl)
      print(TextMobject.CONFIG)
      tbl = TextMobject(tblBitwiseOr, CONFIG=o, template_tex_file_body=TEMPLATE_TEXT_FILE_BODY_TABULAR)
      self.play(FadeInFrom(tbl, UP))
      self.wait(10)
      self.remove(tbl)
      tbl = TextMobject(tblBitwiseXor, CONFIG=o, template_tex_file_body=TEMPLATE_TEXT_FILE_BODY_TABULAR)
      self.play(FadeInFrom(tbl, UP))
      self.wait(5)
      self.remove(tbl)
      tbl = TextMobject(tblFastestOps, CONFIG=o, template_tex_file_body=TEMPLATE_TEXT_FILE_BODY_TABULAR)
      self.play(FadeInFrom(tbl, UP))
      self.wait(10)
      self.remove(tbl)
      tbl = TextMobject(tblFastOps, CONFIG=o, template_tex_file_body=TEMPLATE_TEXT_FILE_BODY_TABULAR)
      self.play(FadeInFrom(tbl, UP))
      self.wait(10)
      self.remove(tbl)
      tbl = TextMobject(tblBitOps, CONFIG=o, template_tex_file_body=TEMPLATE_TEXT_FILE_BODY_TABULAR)
      self.play(FadeInFrom(tbl, UP))
      self.wait(10)
      self.remove(tbl)

    def showBinToBase64():
      g = getPyDisplay(captBinToBase64, fileName, codeBinToBase64)
      g.to_edge(UP)
      self.play(Write(g))
      self.wait(10)
      self.play(ApplyMethod(g.to_edge, DOWN))
      self.wait(5)
      self.remove(g)

    def showHexToBase64Alt():
      g = getPyDisplay(captHexToBase64Alt, fileName, codeHexToBase64Alt)
      self.play(FadeInFrom(g, UP))
      self.wait(10)
      self.remove(g)

    def showTestHexPartToInt():
      g = getPyDisplay(captTestHexPartToInt, fileName, codeTestHexPartToInt)
      self.play(FadeInFrom(g, UP))
      self.wait(10)
      self.remove(g)
    
    def showTestConversions():
      g = getPyDisplay(captTestConversions, fileName, codeTestConversions)
      self.play(FadeInFrom(g, UP))
      self.wait(10)
      self.remove(g)

    def showTestUtility():
      g = getPyDisplay(captTestUtility, fileName, codeTestUtility)
      self.play(FadeInFrom(g, UP))
      self.wait(10)
      self.remove(g)

    subScenes = [self.showLogo, showChallenge, showSolution, showHexTable, showAsciiTable, showTableBase64, showTablePaddingBase64,
                 showHexToBase64, showHexPartToInt, showGetHexPartToInt, showGetHexPartToIntTable,
                 showHexStrToBin, showBitwise, showBinToBase64, showHexToBase64Alt, showTestHexPartToInt,
                 showTestConversions, showTestUtility]
    subScenes = [showBitwise]

    for i in subScenes: i()