#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from subprocess import PIPE, Popen
import hashlib
import requests
import sys
import json
from googleapiclient.discovery import build


def parseConfig():
    conf_file = "config.json"
    try:
        with open(conf_file, 'r') as read_conf:
            conf = json.load(read_conf)
        global google_API
        global google_cx
        global psbdmp_API
        google_API = conf["keys"]["google"]
        google_cx = conf["keys"]["google_cx"]
        psbdmp_API = conf["keys"]["psbdmp"]

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


def commonPasswordChecker(password):
    common = True
    command = cmdline("/usr/bin/grep -R " + password +
                      " ./Passwords/ 2> /dev/null")
    if command:
        print("[+] Found on common passwords:")
        leaks = command.split()
        for leak in leaks:
            try:
                passwd = leak.split(":")[1]
                if passwd == password:
                    print("  -> Password found on: ",
                          str(leak.split(":")[0].split("//")[1].split(".")[0]))
                    common = False
            except:
                pass
    if common:
        print("[-] It's not a common password!")
    else:
        print("[+] It's a common password!")


def leakedPasswordChecker(password):
    leaked = False
    password_hash = hashlib.sha1(password.encode('utf-8')).hexdigest()
    command = cmdline("/usr/bin/grep -i " + password_hash +
                      " ./Passwords/pwned-passwords-sha1.txt 2> /dev/null")
    if command:
        print("[+] Found on leaked databases:")
        leaks = command.split()
        for leak in leaks:
            #print("Leak:", leak)
            try:
                #passwd = leak.split(":")[0]
                #print("Passwd: ", passwd)
                # if passwd == password_hash:
                print("  -> Hash: ", password_hash)
                print("  --> Times founded: ", str(leak.split(":")[1]))
                leaked = True
            except:
                pass
    if not leaked:
        print("[-] Safe password! It hasn't been leaked yet")

# Google CUstom Search Engine


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
        # print(res)
        # print("---------")
        # print(res["items"])

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


def yesNo(user_response):
    if user_response == "y":
        return True
    else:
        return False


def psbdmp_search(target):
    url = "https://psbdmp.ws/api/v3/search/" + target
    found = False

    try:
        response = requests.request("GET", url)

        json_response = response.json()

        for dump in json_response["data"]:
            found = True
            print("[+] Dump ID: ", dump["id"])
            print(" -> Dump Tags: ", dump["tags"])
            print(" -> Dump Date: ", dump["time"])
            print(" -> Dump preview: ", dump["text"])
            user_response = str(
                input(" ---> Do you want to save the full content of the dump? [y/n]"))
            if yesNo(user_response):
                # This functionality spends API credits
                dump_id = dump["id"]
                url_dump = "https://psbdmp.ws/api/v3/dump/" + dump_id + "?key=" + psbdmp_API
                #print("URLDUMP: " + url_dump)
                response = requests.request("GET", url_dump)
                dump_json = response.json()
                print("[+] Dumping content in ../htdocs/results/" +
                      dump_id + ".txt")
                # print(dump_json["content"])
                f_dump = open("../htdocs/results/" + dump_id + ".txt", 'w')
                f_dump.write(dump_json["content"])
                f_dump.close()

    except:
        pass
        #print("[-] Error! Check psbdmp.ws API!")
    if not found:
        print("[-] PSBDMP: Not found on dumps!")


def get_darknet_leak(password):
    # Tor proxy
    from_m = "Initial"
    proxy = "127.0.0.1:9150"
    raw_node = []
    session = requests.session()
    session.proxies = {
        'http': 'socks5h://{}'.format(proxy), 'https': 'socks5h://{}'.format(proxy)}
    url = "http://pwndb2am4tzkvold.onion/"

    request_data = {'password': password, 'submitform': 'pw'}

    try:
        req = session.post(url, data=request_data, headers={
                           'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36'})
    except Exception as error:
        raw_node = {'status': 'No TOR', 'desc': str(type(error))}

    #print("RAW: ", raw_node)
    if (raw_node == []):
        if ("Array" in req.text):
            leaks = req.text.split("Array")[1:]
            emails = []
            for leak in leaks:
                #print("Leak: ", leak)

                leaked_email = ''
                domain = ''
                password = ''
                try:
                    leaked_email = leak.split("[luser] =>")[
                        1].split("[")[0].strip()
                    domain = leak.split("[domain] =>")[1].split("[")[0].strip()
                    password = leak.split("[password] =>")[
                        1].split(")")[0].strip()
                except:
                    pass
                if leaked_email and leaked_email != 'donate':
                    emails.append({'username': leaked_email,
                                  'domain': domain, 'password': password})

            if (len(emails) > 0):
                raw_node = {'pass': emails}
            else:
                raw_node = {'status': 'No password leaked'}
        else:
            raw_node = {'status': 'No password leaked'}

    # print(raw_node)
    try:
        if raw_node["pass"] != "":
            print("[+] Darknet results:")
            count = 0
            for leak in raw_node["pass"]:
                print(" -> Darknet leak ({0}): ".format(count+1))
                print("   -> Username: ", leak["username"])
                print("   -> Domain: ", leak["domain"])
                print("   --> Password: ", leak["password"])
                count += 1
    except:
        print("[-] Not exposed in darknet")
