#!/usr/bin/python3
# -*- coding: utf-8 -*-

#activate_this = '/Applications/XAMPP/xamppfiles/cgi-bin/venv/bin/activate'
#execfile(activate_this, dict(__file__=activate_this))

import cgi
import cgitb
import subprocess
import hashlib

cgitb.enable()


python_bin = "/Applications/XAMPP/xamppfiles/cgi-bin/venv/bin/python"

email = None
domain = None
username = None
ip = None
password = None
wallet = None
term = None


def printOutput(redirect_page):
    print("Content-Type: text/html; charset=UTF-8\r\n")
    print("""
    <html>
    <head>
        <title>Redireccionant a la pàgina dels resultats</title>
        <meta http-equiv="refresh" content="1; URL=../results/{0}.html"/>
        <link rel="stylesheet" href="styles/main_css.css">
    </head>
    <body>
        <section class="dark">
        <h1>Investigation done!</h1>
        <h2>Redirecting you to the report page</h2>
        </section>
    </body>
    </html>
    """).format(redirect_page)


form = cgi.FieldStorage()
form.fp = form.file
form.read_urlencoded()

try:
    email = form["email"].value.split('\r\n', 1)[0]
except:
    pass
try:
    domain = form["domain"].value.split('\r\n', 1)[0]
except:
    pass
try:
    username = form["username"].value.split('\r\n', 1)[0]
except:
    pass
try:
    ip = form["ip"].value.split('\r\n', 1)[0]
except:
    pass
try:
    password = form["password"].value.split('\r\n', 1)[0]
except:
    pass
try:
    wallet = form["wallet"].value.split('\r\n', 1)[0]
except:
    pass
try:
    term = form["term"].value.split('\r\n', 1)[0]
except:
    pass


if email is not None:
    process = subprocess.Popen(['sudo', '/usr/bin/python3', 'automate-osint.py', '-html', '-e', email],
                               stdout=subprocess.PIPE,
                               universal_newlines=True)
    (output, err) = process.communicate()
    # The following line makes the waitting possible
    p_status = process.wait()
    printOutput(hashlib.sha1(email.encode('utf-8')).hexdigest())
if domain is not None:
    process = subprocess.Popen(['sudo', '/usr/bin/python3', 'automate-osint.py', '-html', '-d', domain],
                               stdout=subprocess.PIPE,
                               universal_newlines=True)
    (output, err) = process.communicate()
    # The following line makes the waitting possible
    p_status = process.wait()
    printOutput(hashlib.sha1(domain.encode('utf-8')).hexdigest())
if username is not None:
    process = subprocess.Popen(['sudo', '/usr/bin/python3', 'automate-osint.py', '-html', '-u', username],
                               stdout=subprocess.PIPE,
                               universal_newlines=True)
    (output, err) = process.communicate()
    # The following line makes the waitting possible
    p_status = process.wait()
    printOutput(hashlib.sha1(username.encode('utf-8')).hexdigest())

if ip is not None:
    process = subprocess.Popen(['sudo', '/usr/bin/python3', 'automate-osint.py', '-html', '-i', ip],
                               stdout=subprocess.PIPE,
                               universal_newlines=True)
    (output, err) = process.communicate()
    # The following line makes the waitting possible
    p_status = process.wait()
    printOutput(hashlib.sha1(ip.encode('utf-8')).hexdigest())

if password is not None:
    process = subprocess.Popen(['sudo', '/usr/bin/python3', 'automate-osint.py', '-html', '-p', password],
                               stdout=subprocess.PIPE,
                               universal_newlines=True)
    (output, err) = process.communicate()
    # The following line makes the waitting possible
    p_status = process.wait()
    printOutput(hashlib.sha1(password.encode('utf-8')).hexdigest())

if wallet is not None:
    process = subprocess.Popen(['sudo', '/usr/bin/python3', 'automate-osint.py', '-html', '-w', wallet],
                               stdout=subprocess.PIPE,
                               universal_newlines=True)
    (output, err) = process.communicate()
    # The following line makes the waitting possible
    p_status = process.wait()
    printOutput(hashlib.sha1(wallet.encode('utf-8')).hexdigest())

if term is not None:
    process = subprocess.Popen(['sudo', '/usr/bin/python3', 'automate-osint.py', '-html', '-t', term],
                               stdout=subprocess.PIPE,
                               universal_newlines=True)
    (output, err) = process.communicate()
    # The following line makes the waitting possible
    p_status = process.wait()
    printOutput(hashlib.sha1(term.encode('utf-8')).hexdigest())
