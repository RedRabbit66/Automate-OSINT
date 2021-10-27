#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import requests
import re
import hashlib
import time
import csv
import subprocess
import json
from urllib.parse import urlencode


def parseConfig():
    conf_file = "config.json"
    try:
        with open(conf_file, 'r') as read_conf:
            conf = json.load(read_conf)
        global bitcoin_abuse_API
        global bitcoinwhoswho_API_KEY
        bitcoin_abuse_API = conf["keys"]["bitcoin_abuse"]
        bitcoinwhoswho_API_KEY = conf["keys"]["bitcoinwhoswho"]
    except Exception as e:
        print("Unable to parse config file: {0}".format(e))
        sys.exit()

    return conf


def wallet_report(address):

    try:
        config = parseConfig()

        # print(response.text)

        req_address = requests.get(
            "https://www.bitcoinabuse.com/api/reports/check?address=" + address + "&api_token=" + bitcoin_abuse_API)

        json_adress = json.loads(req_address.content)

        #print("JSON: ", json_adress)

        #json_response = response.json()

        if json_adress["count"] > 0:
            print("[+] Bitcoinabuse records")
            for record in json_adress["recent"]:
                print(" [*] New record")
                print("  -> Abuse Type ID: ", record["abuse_type_id"])
                print("  -> Abuse Type: ", record["abuse_type_other"])
                print("  -> Description: ", record["description"])
                print("  -> Created at: ", record["created_at"])

    except:
        print("[-] BitcoinAbuse API Error")


def btc_info(wallet):
    try:
        config = parseConfig()
        bitcoin_abuse_API = config["keys"]["bitcoin_abuse"]
        bitcoinwhoswho_API_KEY = config["keys"]["bitcoinwhoswho"]

        # print(response.text)

        req_address = requests.get(
            "https://chain.api.btc.com/v3/address/" + wallet)

        json_adress = json.loads(req_address.content)

        #print("JSON: ", json_adress)

        #json_response = response.json()

        if json_adress["status"] == "success":

            print("[+] BTC info:")
            print(" -> Satoshis receibed: ", json_adress["data"]["received"])
            print(" -> Satoshis sent: ", json_adress["data"]["sent"])
            print(" -> Actual balance: ", json_adress["data"]["balance"])
            print(" -> Total Transactions: ", json_adress["data"]["tx_count"])
            print(" -> First transaction: ", json_adress["data"]["first_tx"])
            print(" -> Last Transaction: ", json_adress["data"]["last_tx"])

    except:
        print("[-] BTC API Error!")


def url_wallet_info(address):

    try:
        config = parseConfig()
        bitcoin_abuse_API = config["keys"]["bitcoin_abuse"]
        bitcoinwhoswho_API_KEY = config["keys"]["bitcoinwhoswho"]

        # print(response.text)

        req_address = requests.get(
            "https://bitcoinwhoswho.com/api/url/" + bitcoinwhoswho_API_KEY + "?address=" + address)

        json_response = json.loads(req_address.content)

        #print("JSON: ", json_response)

        if json_response["status"] == "success":
            print("[+] Bitcoinwhoswho: URL appearances")
            for url in json_response["urls"]:
                print(" [*] New record")
                print("  -> URL: ", url["url"])
                print("  --> Page title: ", url["page_title"])
                print("  --> Meta description: ", url["meta_description"])

    except:
        print("[-] API BitcoinWhoiswho Error")
