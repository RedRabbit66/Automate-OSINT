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
    table = """<section class="ftco-section">
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-6 text-center mb-5">
                <h2 class="heading-section">Not username founds</h2>
            </div>
        </div>
    </div>"""
    process = subprocess.Popen(['/opt/anaconda3/bin/python3', 'sherlock/sherlock/sherlock.py', '--print-found', '--csv', '--folderoutput', 'sherlock_output', username],
                               stdout=subprocess.PIPE, universal_newlines=True)

    (output, err) = process.communicate()
    # The following line makes the waitting possible
    p_status = process.wait()
    try:
        username_filename = "./sherlock_output/" + username + ".csv"
        print("username_filename: " + username_filename)
        with open((username_filename), 'r') as f:
            print("Done2")
            rowReader = csv.reader(f, delimiter=',')
            # -use this if your txt file has a header strings as column names
            next(rowReader)

            table = ""
            table = table + """
    <section class="ftco-section">
        <div class="container">
            <div class="row justify-content-center">
                <div class="col-md-6 text-center mb-5">
                    <h2 class="heading-section">Discovered accounts used by username</h2>
                </div>
            </div>
            <div class="row">
                <div class="col-md-12">
                    <div class="table-wrap">
                        <table class="table table-bordered table-dark table-hover">
                            <tbody>
                                """
            # Creem la taula amb les capçaleres corresponents
            header = ['Site', 'Main URL', 'User URL']
            table += "<thead>\n"

            for column in header:
                table += "    <th>{0}</th>\n".format(column.strip())
            table += "</thead>\n"
            for values in rowReader:
                if values[4] == "Claimed":
                    print(values[1])
                    # NOVA FILA
                    table += "  <tr>\n"
                    # NOU CAMP (COLUMNA) a la FILA
                    table += """<th scope="row">{0}</th>""".format(values[1])
                    table += """<td><a href="{0}">{0}</a></td>\n""".format(
                        values[2])
                    table += """<td><a href="{0}">{0}</a></td>\n""".format(
                        values[3])

                    # TANCO FILA
                    table += "  </tr>\n"

            table += """    </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </section>"""

    except:
        table = """<section class="ftco-section">
        <div class="container">
            <div class="row justify-content-center">
                <div class="col-md-6 text-center mb-5">
                    <h2 class="heading-section">Not username founds</h2>
                </div>
            </div>
        </div>"""

    return table

# Google CUstom Search Engine


def pastes_search_html(search):
    # Build a service object for interacting with the API. Visit
    # the Google APIs Console <http://code.google.com/apis/console>
    # to get an API key for your own application.
    service = build("customsearch", "v1", developerKey=google_API)

    table = """<section class="ftco-section">
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-6 text-center mb-5">
                <h2 class="heading-section">Not found on any paste from internet</h2>
            </div>
        </div>
    </div>"""

    try:
        res = service.cse().list(
            q=search,
            cx=google_cx,
        ).execute()
        # print(res)
        # print("---------")
        # print(res["items"])

        if (int(res["searchInformation"]["totalResults"]) > 0):
            table = ""
            table = """
    <section class="ftco-section">
        <div class="container">
            <div class="row justify-content-center">
                <div class="col-md-6 text-center mb-5">
                    <h2 class="heading-section">Found it on pastes from internet</h2>
                </div>
            </div>
            <div class="row">
                <div class="col-md-12">
                    <div class="table-wrap">
                        <table class="table table-bordered table-dark table-hover">
                            <tbody>
                                """

            # Creem la taula amb les capçaleres corresponents
            header = ['Link', 'Snippet']
            table += "<thead>\n"
            for column in header:
                table += "    <th>{0}</th>\n".format(column.strip())
            table += "</thead>\n"

            print("[+] Founds in Pastes:")
            for item in res["items"]:
                # NOVA FILA
                table += "  <tr>\n"
                # NOU CAMP (COLUMNA) a la FILA
                table += """<th scope="row"><a href="{0}">{0}</a></th>""".format(
                    item["link"])
                table += """<td>{0}</td>\n""".format(item["snippet"])

                # TANCO FILA
                table += "  </tr>\n"

                print(" -> Link: ", item["link"])
                print(" -> Snippet: ", item["snippet"])

            table += """    </tbody>
						</table>
					</div>
				</div>
			</div>
		</div>
	</section>"""

        else:
            print("[-] No appearances in internet pastes.")

    except:
        print("[-] Error searching in internet pastes.")

    return table


def psbdmp_search_html(target):
    url = "https://psbdmp.ws/api/v3/search/" + target

    table = """<section class="ftco-section">
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-6 text-center mb-5">
                <h2 class="heading-section">PSBDMP: not found on pastes</h2>
            </div>
        </div>
    </div>"""

    try:
        response = requests.request("GET", url)

        # print(response.text)

        json_response = response.json()

        #print("JSON DATA: ", json_response["data"])

        if not 'data' in json_response or len(json_response['data']) == 0:
            pass
        else:
            table = ""
            table = """
        <section class="ftco-section">
            <div class="container">
                <div class="row justify-content-center">
                    <div class="col-md-6 text-center mb-5">
                        <h2 class="heading-section">PSBDMP: found on pastes</h2>
                    </div>
                </div>
                <div class="row">
                    <div class="col-md-12">
                        <div class="table-wrap">
                            <table class="table table-bordered table-dark table-hover">
                                <tbody>
                                    """

            # Creem la taula amb les capçaleres corresponents
            header = ['Dump ID', 'Dump Tags',
                      'Dump Date', 'Dump preview', 'Download']
            table += "<thead>\n"
            for column in header:
                table += "    <th>{0}</th>\n".format(column.strip())
            table += "</thead>\n"
            for dump in json_response["data"]:
                # NOVA FILA
                table += "  <tr>\n"
                # NOU CAMP (COLUMNA) a la FILA
                table += """<th scope="row">{0}</th>""".format(dump["id"])
                table += """<td>{0}</td>\n""".format(dump["tags"])
                table += """<td>{0}</td>\n""".format(dump["time"])
                table += """<td>{0}</td>\n""".format(dump["text"])
                table += """<td>{0}</td>\n""".format(dump["tags"])
                table += """<td><form action="../cgi-bin/download.sh" method="POST" enctype="text/plain"><input type="submit" value="{0}" name="Download"/></form></td>""".format(
                    dump["id"])

                print("[+] Dump ID: ", dump["id"])
                print("[+] Dump Tags: ", dump["tags"])
                print("[+] Dump Date: ", dump["time"])
                print("[+] Dump preview: ", dump["text"])

                # TANCO FILA
                table += "  </tr>\n"

            table += """    </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </section>"""

    except:
        print("Error! Check psbdmp.ws API!")

    return table


def get_darknet_leak(username):
    table = """<section class="ftco-section">
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-6 text-center mb-5">
                <h2 class="heading-section">Domain not exposed in Darknet market yet!</h2>
            </div>
        </div>
    </div>"""

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

    print(raw_node)
    try:
        if raw_node["pass"] != "":
            print("[+] Darknet results:")
            table = """
        <section class="ftco-section">
            <div class="container">
                <div class="row justify-content-center">
                    <div class="col-md-6 text-center mb-5">
                        <h2 class="heading-section">Darknet results</h2>
                    </div>
                </div>
                <div class="row">
                    <div class="col-md-12">
                        <div class="table-wrap">
                            <table class="table table-bordered table-dark table-hover">
                                <tbody>
                                    """

            # Creem la taula amb les capçaleres corresponents
            header = ['Dark Net Leak', 'Username', 'Domain', 'Password']
            table += "<thead>\n"
            for column in header:
                table += "    <th>{0}</th>\n".format(column.strip())
            table += "</thead>\n"
            count = 0
            for leak in raw_node["pass"]:
                # NOVA FILA
                table += "  <tr>\n"
                # NOU CAMP (COLUMNA) a la FILA
                table += """<th scope="row">{0}</th>""".format(count+1)
                table += """<td>{0}</td>\n""".format(leak["username"])
                table += """<td>{0}</td>\n""".format(leak["domain"])
                table += """<td>{0}</td>\n""".format(leak["password"])
                # TANCO FILA
                table += "  </tr>\n"

                print(" -> Darknet leak ({0}): ".format(count+1))
                print("   -> Username: ", leak["username"])
                print("   -> Domain: ", leak["domain"])
                print("   --> Password: ", leak["password"])
                count += 1
            table += """        </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </section>"""

    except:
        print("[-] Not exposed in darknet")

    return table
