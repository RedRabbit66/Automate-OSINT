#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import json
import requests
import re
import hashlib
from googleapiclient.discovery import build
from shodan import Shodan
from subprocess import PIPE, Popen
import argparse
from datetime import datetime
import time
import csv
import subprocess
import inspect

import hashlib

import trio
import httpx

import geoip2.webservice



__author__ = '@llure29 (Llorenç Garcia)'

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


def cmdline(command):
    process = Popen(
        args=command,
        stdout=PIPE,
        shell=True
    )
    return process.communicate()[0].decode("utf-8")

'''
def Popen(*args, **kwargs):
    sig = inspect.signature(real_popen)
    bound_args = sig.bind(*args, **kwargs).arguments
    bound_args['stdout'] = subprocess.DEVNULL
    bound_args['stderr'] = subprocess.DEVNULL
    return real_popen(**bound_args)

real_popen = subprocess.Popen
subprocess.Popen = Popen
'''

def yesNo(user_response):
    if user_response == "y":
        return True
    else:
        return False

def comprova_leaks(email):
    response = requests.post('https://leak-lookup.com/api/search', data={'key':leak_lookup_API, 'type': 'email_address', 'query': email})
    json_response = response.json()
    try:
        if (json_response["error"] == "false"):

            print("[+] User information has been exposed in the following databases:")
            
            for leak in json_response["message"]:
                print("  -> " + leak)
        else:
            print("[-] Check your leak-lookup API credits.")

    except:
        print("[-] Email seems hasn't been leaked.")


def get_gravatar_info(email):
    email_hash=hashlib.md5(email.encode('utf-8')).hexdigest()

    #print("Email Hash: ", email_hash)

    accounts = []

    try:
        response=requests.get("https://www.gravatar.com/" + email_hash)
        
        if response.status_code==200:
            #print("URL: ", response.url)
            accounts.append(response.url)
            response=requests.get(response.url + '.json')
            #print("Response: ", response.json())
            json_response = response.json()
            print("[+] Gravatar info:")
            print(" -> Gravatar profile: ", json_response["entry"][0]["profileUrl"])
            print(" -> Full name (gravatar.com): ", json_response["entry"][0]["name"]["formatted"])
            print(" -> Possible username: ", json_response["entry"][0]["preferredUsername"])
            print(" -> Gravatar photos: ")
            for photo in json_response["entry"][0]["photos"]:
                print("  --> " + photo["value"])
            
            urls=json_response['entry'][0]['urls']
            for url in urls:
                accounts.append(url['value'])
                print("URL linked to Gravatar profile: ", url['value'])
        else:
            print("[-] Account not linked to gravatar.com")

    except:
        pass

def get_breachdirectory(email):
    url = "https://breachdirectory.p.rapidapi.com/"

    querystring = {"func":"auto","term":email}

    headers = {
        'x-rapidapi-key': breachdirectory_API_2,
        'x-rapidapi-host': "breachdirectory.p.rapidapi.com"
        }
    try:
        response = requests.request("GET", url, headers=headers, params=querystring)

        #print(response.text)

        json_response = response.json()

        #if (json_response["error"] and (json_response["error"] == "Not found")):
        #	print("[-] This email hasn\'t been leaked!")
        #else:
        if json_response["result"] != "":
            for result in json_response["result"]:
                print("[+] Leaked sources: ")
                for source in result["sources"]:
                    print(" - ", source)
                try:
                    print(" --> Password from above sources: ", result["password"])
                    print(" ---> Password Hash: ",result["sha1"])
                    print(" --- ")
                except:
                    pass
        else:
            print("[-] This email hasn\'t been leaked!")

    except Exception as error:
        if (json_response["error"] == "Not found"):
            print("[-] Error extracting leaked info. Try it later.")
        else:
            print("[-] Error extracting leaked info. Try it later.")
        #("Response: ", json_response)
        #print(error)


#Google CUstom Search Engine
def pastes_search(search):
    # Build a service object for interacting with the API. Visit
    # the Google APIs Console <http://code.google.com/apis/console>
    # to get an API key for your own application.
    service = build("customsearch", "v1", developerKey=google_API)

    pastes_urls = []
    pastes_snippet = []

    try:
        res = service.cse().list(
            q=search,
            cx=google_cx,
        ).execute()
        #print(res)
        #print("---------")
        #print(res["items"])

        if (int(res["searchInformation"]["totalResults"]) > 0):
            print("[+] Founds in Pastes:")
            for item in res["items"]:
                pastes_urls.append(item["link"])
                pastes_snippet.append(item["snippet"])
                print(" -> Link: ", item["link"])
                print(" -> Snippet: ", item["snippet"])

        else:
            print("[-] No appearances in internet pastes.")

    except:
        print("[-] Error searching in internet pastes.")


def psbdmp_search(target):
    url = "https://psbdmp.ws/api/v3/search/" + target

    try:
        response = requests.request("GET", url)

        json_response = response.json()

        for dump in json_response["data"]:
            print("[+] Dump ID: ", dump["id"])
            print("[+] Dump Tags: ", dump["tags"])
            print("[+] Dump Date: ", dump["time"])
            print("[+] Dump preview: ", dump["text"])
            user_response = str(input(" ---> Do you want to save the full content of the dump? [y/n]"))
            if yesNo(user_response):
                #This functionality spends API credits
                dump_id = dump["id"]
                url_dump = "https://psbdmp.ws/api/v3/dump/" + dump_id + "?key=" + psbdmp_API
                print("URLDUMP: " + url_dump)
                response = requests.request("GET", url_dump)
                dump_json = response.json()
                print("[+] Dumping content in " + dump_id + ".txt")
                #print(dump_json["content"])
                f_dump = open("../htdocs/results/" + dump_id + ".txt",'w')
                f_dump.write(dump_json["content"])
                f_dump.close()

    except:
        print("[-] PSBDMP: Not found on pastes.")


def leaksDBs(email):
    #onlyfiles = [f for f in listdir('./DBs/') if isfile(join('./DBs/', f))]
    #print("Onlyfiles: ", onlyfiles)
    command = cmdline("/usr/bin/grep -R " + email + " ./DBs/ 2> /dev/null")
    if command:
        print("[+] Found on leaked databases:")
        leaks = command.split()
        #print(leak)
        for leak in leaks:
            try:
                #print(leak.split(":"))
                if (leak.split(":")[1] == email):
                    print(" -> Leak found on: ", leak.split(":")[0].split("[")[2].split("]")[0])
                    print("  - Origin country: ", leak.split(":")[0].split("[")[3].split("]")[0])
                    print("  - Password: ", leak.split(":")[2])
            except:
                pass
    else:
        print("[-] Not found on downloaded databases.")




def get_darknet_leak(email):
    # Tor proxy
    from_m = "Initial"
    proxy = "127.0.0.1:9150"
    raw_node = []
    session = requests.session()
    session.proxies = {'http': 'socks5h://{}'.format(proxy), 'https': 'socks5h://{}'.format(proxy)}
    url = "http://pwndb2am4tzkvold.onion/"

    username = email.split("@")[0]
    domain = email.split("@")[1]
    #print(username)
    #print(domain)
    if not username:
        username = '%'

    request_data = {'luser': username, 'domain': domain, 'luseropr': 1, 'domainopr': 1, 'submitform': 'em'}

    try:
        req = session.post(url, data=request_data, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36'})
    except Exception as error:
        raw_node = { 'status': 'No TOR', 'desc': str(type(error))}

    if (raw_node == []):
        if ("Array" in req.text):
            leaks = req.text.split("Array")[1:]
            emails = []
            for leak in leaks:
                leaked_email = ''
                domain = ''
                password = ''
                try:
                    leaked_email = leak.split("[luser] =>")[1].split("[")[0].strip()
                    domain = leak.split("[domain] =>")[1].split("[")[0].strip()
                    password = leak.split("[password] =>")[1].split(")")[0].strip()
                except:
                    pass
                if leaked_email and leaked_email != 'donate':
                    emails.append({'username': leaked_email, 'domain': domain, 'password': password})

            if (len(emails) > 0):
                raw_node = {'pass': emails}
            else:
                raw_node = { 'status': 'No password leaked'}
        else:
            raw_node = { 'status': 'No password leaked'}

    #print(raw_node)
    try:
        if raw_node["pass"] != "":
            print("[+] Darknet results:")
            count = 0
            for leak in raw_node["pass"]:
                print(" - Darknet leak ({0}): ".format(count+1))
                print("  -> Username: ", leak["username"])
                print("  -> Domain: ", leak["domain"])
                print("  --> Password: ", leak["password"])
                count +=1
    except:
        print("[-] Not exposed in darknet.")
    

def newest(path):
    files = os.listdir(path)
    paths = [os.path.join(path, basename) for basename in files]
    return max(paths, key=os.path.getctime)

def sitesUsedByTarget(email):
    process = subprocess.Popen([ 'holehe' , '--only-used' , '-C' , email , '>/dev/null' , '2>&1'], 
                        stdout=subprocess.PIPE,
                        universal_newlines=True)

    (output, err) = process.communicate()
    #The following line makes the waitting possible
    p_status = process.wait()
    #print(newest('/Applications/XAMPP/xamppfiles/cgi-bin/'))
    try:
        with open(newest('/Applications/XAMPP/xamppfiles/cgi-bin/'),'r') as f:
            rowReader = csv.reader(f, delimiter=',')
            next(rowReader)  #-use this if your txt file has a header strings as column names
            print("[+] Discovered sites used by target:")
            
            for values in rowReader:
                if values[5] == "True":
                    print(" -> Name: " + values[0])
                    print("  --> Domain: " + values[1])
                    print("  --> Method: " + values[2])
                    print("  --> Email recovery: " + values[6])
                    print("  --> phoneNumber: " + values[7])
                    print("  --> others: " + values[8])
                
    except:
        print("It's not able to discover sites used by target.")


