#!/bin/bash

#echo Content-Type: text/html
echo -e "Content-Type: text/html; charset=UTF-8\r\n"
read dark
option=`echo $dark | awk -F'=' '{print $2}' | sed 's/\r$//'`

if [[ $dark == *"email"* || $dark == *"domain"* || $dark == *"username"* || $dark == *"ip"* || $dark == *"password"* || $dark == *"wallet"* || $dark == *"term"* ]]; then
    echo -e "
<html>
	<head>
		<meta http-equiv=\"Refresh\" content=\"0; url=/$option.html\" />
	</head>
	<body>
		<p>Opcio rebuda: $option</p>
	</body>
</html>
    "
    
else
    
    echo -e "
<html>
  <head>
    <meta http-equiv=\"Refresh\" content=\"5; url=/index.html\" />
  </head>
  <body>
    <p>Invalid option!</p>
    <p>Option: $option</p>
    <br>
    <p>Redirecting you to home page...</p>
  </body>
</html>
    "
    
fi

