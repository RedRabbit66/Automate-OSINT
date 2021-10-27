#!/usr/local/bin/python
# -*- coding: utf-8 -*-

# Antic: # #!/usr/local/bin/python

#activate_this = '/Applications/XAMPP/xamppfiles/cgi-bin/venv/bin/activate'
#execfile(activate_this, dict(__file__=activate_this))

import cgi, cgitb, os, sys
import subprocess
import requests

cgitb.enable()

python_bin = "/Applications/XAMPP/xamppfiles/cgi-bin/venv/bin/python"

paste = None

psbdmp_API = '705d440a1025a46e94d9adf4c3630cb5'


def printOutput(redirect_page):
    print("Content-Type: text/html; charset=UTF-8\r\n")
    print("""
<html>
<head>
<title>Redireccionant a la pàgina dels resultats</title>
<meta http-equiv="refresh" content="1; URL=../pastes/{0}.txt"/>
<link rel="stylesheet" href="styles/main_css.css">
</head>
<body>
<section class="dark">
    <h1>Paste downloaded</h1>
    <h2>Redirecting you to the paste download page</h2>
</section>
</body>
</html>
""").format(redirect_page)

#print("  <p>CGI FieldStorage: </p>")
form = cgi.FieldStorage()
#print(form)

#form.fp.seek(0) # we reset fp because FieldStorage exhausted it
# if f.fp.seek(0) fails we can also do this:
# f.fp = f.file
form.fp = form.file
form.read_urlencoded()

#print form["email"] # 10
#print "Keys: ", form.keys() # ["age", "name"]

#print "Correu rebut: ", form["Download"].value

#print "Correu nomes: ", form["Download"].value.split('\r\n', 1)[0]
try:
    paste = form["Download"].value.split('\r\n', 1)[0]
    '''
    print("Content-Type: text/html; charset=UTF-8\r\n")
    print("<html><body>")
    print("<p>Keys: {0}</p>".format(form.keys())) # ["age", "name"]

    print("  <p>Download: " + paste + "</p>")
    print("</body></html>")
    '''
except:
    pass


if paste is not None:
    url_dump = "https://psbdmp.ws/api/v3/dump/" + paste + "?key=" + psbdmp_API
    print("URLDUMP: " + url_dump)
    response = requests.request("GET", url_dump)
    dump_json = response.json()
    print("[+] Dumping content in " + paste + ".txt")
    #print(dump_json["content"])
    f_dump = open("../htdocs/pastes/" + paste + ".txt",'w')
    f_dump.write(dump_json["content"])
    f_dump.close()
    #printOutput(paste)

