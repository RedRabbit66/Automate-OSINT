#!/usr/bin/python
# -*- coding: utf-8 -*-

# Import modules for CGI handling
import cgi, cgitb
# Create instance of FieldStorage
form = cgi.FieldStorage()
# Get data from fields
if form.getvalue('email'):
   option = form.getvalue('email')
else:
   option = "Not set"
print "Content-type:text/html\r\n\r\n"
print "<html>"
print "<head>"
print "<title>Automated OSINT</title>"
print "</head>"
print "<body>"
print "<h2> Selected Subject is %s</h2>" % option
print "</body>"
print "</html>"