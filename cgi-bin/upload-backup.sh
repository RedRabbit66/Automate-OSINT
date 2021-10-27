#!/bin/bash

echo Content-Type: text/html

read dark

dark=`echo $dark | awk -F'=' '{print $2}' | sed 's/\r$//'`

if [ "$dark" == "email" ] ; then
	echo -e "
	<html>
	  <head>
	    <meta http-equiv=\"Refresh\" content=\"7; url=/index.html\" />
	  </head>
	  <body>
	    <p>Usuari $usuari incorrecte.</p>
	    <p>UsuariValid: $usuariValid</p>
	  </body>
	</html>
	"

if [ "$dark" == "domain" ] ; then
	echo -e "
<html>
  <head>
    <title>Domain</title>
  </head>
  <body>
    <p>Domain</p>
  </body>
</html>
"
if [ "$dark" == "username" ] ; then

	echo -e "
<html>
  <head>
    <title>Username</title>
  </head>
  <body>
    <p>Username</p>
  </body>
</html>
"


