#!/bin/bash

echo -e "Content-Type: text/html; charset=UTF-8\r\n"

read Download

function readJson {  
  UNAMESTR=`uname`
  if [[ "$UNAMESTR" == 'Linux' ]]; then
    SED_EXTENDED='-r'
  elif [[ "$UNAMESTR" == 'Darwin' ]]; then
    SED_EXTENDED='-E'
  fi; 

  VALUE=`grep -m 1 "\"${2}\"" ${1} | sed ${SED_EXTENDED} 's/^ *//;s/.*: *"//;s/",?//'`

  if [ ! "$VALUE" ]; then
    echo "Error: Cannot find \"${2}\" in ${1}" >&2;
    exit 1;
  else
    echo $VALUE ;
  fi; 
}

paste=`echo $Download | awk -F'=' '{print $2}' | sed s/+/\ /g`

paste=`echo $paste | tr -d '\r'`

#paste=`sed "s/$(printf '\r')\$//" $paste_f`

psbdmp_API="705d440a1025a46e94d9adf4c3630cb5"

url_dump="https://psbdmp.ws/api/v3/dump/$paste?key=$psbdmp_API"

#echo "Url_dump: $url_dump"

#echo "Paste: $paste"

#Download=Qq4SeWeS

paste_json=`sudo curl $url_dump --silent -o pastes/$paste.json`

paste_content=`readJson pastes/$paste.json content`# || exit 1;


echo $paste_content > ../htdocs/pastes/$paste.txt


echo -e "
<html>
	<head>
		<meta http-equiv=\"Refresh\" content=\"0; url=../pastes/$paste.txt\" />
	</head>
	<body>
		<p>Parse ID: $paste</p>
	</body>
</html>
	"

