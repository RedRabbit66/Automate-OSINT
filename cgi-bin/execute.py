#!/usr/bin/python
# -*- coding: utf-8 -*-


print("CGI FieldStorage: ")
print(cgi.FieldStorage())

form = cgi.FieldStorage()
if "email" not in form:
    print("<H1>Error</H1>")
    print("Please fill in the name and addr fields.")
    return
print("<p>Email:", form["email"].value)
