#!/usr/bin/python
# -*- coding: utf-8 -*-

import cgi, cgitb, os, sys
import subprocess


UPLOAD_DIR = './upload'

def save_uploaded_file():
    print 'Content-Type: text/html; charset=UTF-8'
    
    form = cgi.FieldStorage()
    if not form.has_key('file'):
        print '<h1>Not found parameter: file</h1>'
        return

    form_file = form['file']
    if not form_file.file:
        print '<h1>Not found parameter: file</h1>'
        return

    if not form_file.filename:
        print '<h1>Not found parameter: file</h1>'
        return
    uploaded_file_path = os.path.join(UPLOAD_DIR, os.path.basename(form_file.filename))
    with file(uploaded_file_path, 'wb') as fout:
        while True:
            chunk = form_file.file.read(100000)
            if not chunk:
                break
            fout.write (chunk)    
    process = subprocess.Popen(['sudo', '/opt/anaconda3/bin/python3' , 'parse_mails.py', uploaded_file_path], 
                           stdout=subprocess.PIPE,
                           universal_newlines=True)
    (output, err) = process.communicate()
    #La seguent linia fa l'espera possible
    p_status = process.wait()
    print '''
<html>
 <head>
  <title>Redireccionant a la pàgina dels resultats</title>
  <meta http-equiv="refresh" content="0; URL=../''' + form_file.filename + '''.html"/>
 </head>
<body>
'''
    print '<h1>Completed file upload</h1>'
    print '''
<hr>
</body>
</html>
'''


cgitb.enable()
save_uploaded_file()