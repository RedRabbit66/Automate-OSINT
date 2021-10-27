#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import geoip2.webservice
#from mpl_toolkits.basemap import Basemap
import json
import requests
import sys
import socket
from datetime import datetime
import time
from virus_total_apis import PublicApi as VirusTotalPublicApi
from shodan import Shodan
import os
#import matplotlib.pyplot as plt
os.environ["PROJ_LIB"] = "C:\\Utilities\\Python\\Anaconda\\Library\\share"  # fixr


email_pattern = '(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)'
domain_pattern = '^((?!-))(xn--)?[a-z0-9][a-z0-9-_]{0,61}[a-z0-9]{0,1}\.(xn--)?([a-z0-9\-]{1,61}|[a-z0-9-]{1,30}\.[a-z]{2,})$'


def parseConfig():
    conf_file = "config.json"
    try:
        with open(conf_file, 'r') as read_conf:
            conf = json.load(read_conf)
        global leak_lookup_API
        global google_API
        global breachdirectory_API_2
        global google_cx
        global shodan_API
        global censys_API
        global censys_secret
        global psbdmp_API
        global whoxy_API_Key
        global vt_API_Key
        leak_lookup_API = conf["keys"]["leak_lookup"]
        google_API = conf["keys"]["google"]
        breachdirectory_API_2 = conf["keys"]["breachdirectory"]
        google_cx = conf["keys"]["google_cx"]
        shodan_API = conf["keys"]["shodan"]
        censys_API = conf["keys"]["censys"]
        censys_secret = conf["keys"]["censys_secret"]
        psbdmp_API = conf["keys"]["psbdmp"]
        whoxy_API_Key = conf["keys"]["whoxy"]
        vt_API_Key = conf["keys"]["virustotal"]

    except Exception as e:
        print("Unable to parse config file: {0}".format(e))
        sys.exit()

    return conf


def get_shodan_analisys(ip):
    try:
        api = Shodan(shodan_API)
        # Lookup an IP
        ipinfo = api.host(ip)

        # Print general info
        print("[+] Shodan info " + ipinfo['ip_str'])
        print("  -> Organization: ", ipinfo.get('org', 'n/a'))
        print("  -> Operating System: ", ipinfo.get('os', 'n/a'))
        print("  -> Country: ", ipinfo['country_name'])
        print("  -> City: ", ipinfo['city'])
        print("  -> Hostnames: ")
        for hostname in ipinfo['hostnames']:
            print("  --> ", hostname)

        # Print all banners
        print("Scan info: ")
        for item in ipinfo['data']:
            print("""
	- Port: {}
	- Banner: {}
	---
			""".format(item['port'], item['data']))
    except:
        print("[-] Check Shodan API.")


def analizeIP(ip):
    try:
        vt = VirusTotalPublicApi(vt_API_Key)
        response = vt.get_ip_report(str(ip))
        if response["response_code"]:
            if response["response_code"] == 200:
                try:
                    print("[+] Virustotal report: ")
                    # if response["results"]["detected_urls"]:
                    if (response["results"]["detected_urls"] != ""):
                        print(" -> IP: " + ip)
                        #print(" --> Positives: ", response['results']['positives'])
                        print(" --> Malicious IP!")
                    else:
                        print(" ->IP: " + ip)
                        print(" --> Legit IP!")
                except:
                    pass
    except:
        print("[-] Check your internet connectivity and Virustotal API key.")


def locateIP(ip):
    name = ""
    longitude = 0
    latitude = 0
    try:
        with geoip2.webservice.Client(534778, '2KcXWF0vdaOxe6dL') as client:
            response = client.city(ip)
            name = response.city.name
            if name is None:
                name = "Unknown"
            longitude = response.location.longitude
            latitude = response.location.latitude
            print("[+] IP Geolocation")
            print(" -> City: " + str(response.city.name))
            print(" --> Latitude: " + str(response.location.latitude))
            print(" --> Longitude: " + str(response.location.longitude))

    except:
        name = "Multicast IP"
        longitude = 0
        latitude = 0
        print("[+] IP Geolocation")
        print(" -> City: " + str(name))
        print(" --> Latitude: " + str(latitude))
        print(" --> Longitude: " + str(longitude))
