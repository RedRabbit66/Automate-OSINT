#!/bin/bash

echo Content-Type: text/html
read dark
darkk=`echo $dark | awk -F'=' '{print $2}' | sed 's/\r$//'`
echo -e "
<html>
  <head>
    <title>Hola</title>
  </head>
  <body>
    <p>Dark: $dark i $darkk</p>
  </body>
</html>
"