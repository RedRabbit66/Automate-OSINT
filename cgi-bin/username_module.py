#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import json
import requests
from googleapiclient.discovery import build
import csv
import subprocess


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


def sherlock_finder(username):

    process = subprocess.Popen(['/opt/anaconda3/bin/python3', 'sherlock/sherlock/sherlock.py', '--print-found', '--csv', '--folderoutput', 'sherlock_output', username],
                               stdout=subprocess.PIPE, universal_newlines=True)

    (output, err) = process.communicate()
    # The following line makes the waitting possible
    p_status = process.wait()
    try:
        username_filename = "./sherlock_output/" + username + ".csv"
        #print("username_filename: " + username_filename)
        with open((username_filename), 'r') as f:
            rowReader = csv.reader(f, delimiter=',')
            # -use this if your txt file has a header strings as column names
            next(rowReader)

            print("[+] Discovered accounts used by username")
            for values in rowReader:
                if values[4] == "Claimed":
                    print(" -> Site: " + values[1])
                    print("  --> Main URL: " + values[2])
                    print("  --> User URL: " + values[3])

    except:
        print("[-] Not discovered acounts found")


# Google CUstom Search Engine
def pastes_search(search):
    # Build a service object for interacting with the API. Visit
    # the Google APIs Console <http://code.google.com/apis/console>
    # to get an API key for your own application.
    service = build("customsearch", "v1", developerKey=google_API)

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

    try:
        response = requests.request("GET", url)

        json_response = response.json()

        for dump in json_response["data"]:
            print("[+] Dump ID: ", dump["id"])
            print("[+] Dump Tags: ", dump["tags"])
            print("[+] Dump Date: ", dump["time"])
            print("[+] Dump preview: ", dump["text"])
            user_response = str(
                input(" ---> Do you want to save the full content of the dump? [y/n]"))
            if yesNo(user_response):
                # This functionality spends API credits
                dump_id = dump["id"]
                url_dump = "https://psbdmp.ws/api/v3/dump/" + dump_id + "?key=" + psbdmp_API
                print("URLDUMP: " + url_dump)
                response = requests.request("GET", url_dump)
                dump_json = response.json()
                print("[+] Dumping content in " + dump_id + ".txt")
                # print(dump_json["content"])
                f_dump = open("../htdocs/results/" + dump_id + ".txt", 'w')
                f_dump.write(dump_json["content"])
                f_dump.close()

    except:
        print("[-] PSBDMP: Not found.")


def get_darknet_leak(username):
    # Tor proxy
    from_m = "Initial"
    proxy = "127.0.0.1:9150"
    raw_node = []
    session = requests.session()
    session.proxies = {
        'http': 'socks5h://{}'.format(proxy), 'https': 'socks5h://{}'.format(proxy)}
    url = "http://pwndb2am4tzkvold.onion/"

    if not username:
        username = '%'

    request_data = {'luser': username, 'domain': '%',
                    'luseropr': 1, 'domainopr': 1, 'submitform': 'em'}

    try:
        req = session.post(url, data=request_data, headers={
                           'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36'})
    except Exception as error:
        raw_node = {'status': 'No TOR', 'desc': str(type(error))}

    if (raw_node == []):
        if ("Array" in req.text):
            leaks = req.text.split("Array")[1:]
            emails = []
            for leak in leaks:
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
                print(" - Darknet leak ({0}): ".format(count+1))
                print("  -> Username: ", leak["username"])
                print("  -> Domain: ", leak["domain"])
                print("  --> Password: ", leak["password"])
                count += 1
    except:
        print("[-] Not exposed in darknet.")
