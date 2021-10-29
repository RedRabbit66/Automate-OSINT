__author__ = "Llorenç Garcia"
__copyright__ = "Copyright 2007, The Cogent Project"
__credits__ = ["David Marquet"]
__license__ = "GPL-3.0"
__version__ = "1.0.0"
__maintainer__ = "Llorenç Garcia and David Marquet"
__status__ = "Production"


import csv
import hashlib
import json
import os
import subprocess
import sys
from subprocess import PIPE, Popen

import requests
from googleapiclient.discovery import build

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

def newest(path):
    files = os.listdir(path)
    paths = [os.path.join(path, basename) for basename in files]
    return max(paths, key=os.path.getctime)


def get_gravatar_info_html(email):
    email_hash = hashlib.md5(email.encode('utf-8')).hexdigest()

    table = ""

    accounts = []

    try:
        response = requests.get("https://www.gravatar.com/" + email_hash)

        if response.status_code == 200:
            print("URL: ", response.url)
            accounts.append(response.url)
            response = requests.get(response.url + '.json')
            #print("Response: ", response.json())
            json_response = response.json()
            print("Gravatar profile: ",
                  json_response["entry"][0]["profileUrl"])
            print("Full name (gravatar.com): ",
                  json_response["entry"][0]["name"]["formatted"])
            print("Possible username: ",
                  json_response["entry"][0]["preferredUsername"])
            print("Gravatar photos: ")
            for photo in json_response["entry"][0]["photos"]:
                print(photo["value"])

            urls = json_response['entry'][0]['urls']
            for url in urls:
                accounts.append(url['value'])
                print("URL linked to Gravatar profile: ", url['value'])

            table = ""
            table = table + """
    <section class="ftco-section">
        <div class="container">
            <div class="row justify-content-center">
                <div class="col-md-6 text-center mb-5">
                    <h2 class="heading-section">Gravatar Information</h2>
                </div>
            </div>
            <div class="row">
                <div class="col-md-12">
                    <div class="table-wrap">
                        <table class="table table-bordered table-dark table-hover">
                            <tbody>
                                """
            # Creem la taula amb les capçaleres corresponents
            header = ['Information', 'Result']
            table += "<thead>\n"
            for column in header:
                table += "    <th>{0}</th>\n".format(column.strip())
            table += "</thead>\n"

            # NOVA FILA
            table += "  <tr>\n"
            # NOU CAMP (COLUMNA) a la FILA
            table += """<th scope="row">{0}</th>""".format("Gravatar profile")
            table += """<td><a href="{0}">{0}</a></td>\n""".format(
                json_response["entry"][0]["profileUrl"])

            # TANCO FILA
            table += "  </tr>\n"

            # NOVA FILA
            table += "  <tr>\n"
            # NOU CAMP (COLUMNA) a la FILA
            table += """<th scope="row">{0}</th>""".format("Full name")
            table += """<td>{0}</td>\n""".format(
                json_response["entry"][0]["name"]["formatted"])

            # TANCO FILA
            table += "  </tr>\n"

            # NOVA FILA
            table += "  <tr>\n"
            # NOU CAMP (COLUMNA) a la FILA
            table += """<th scope="row">{0}</th>""".format("Possible username")
            table += """<td>{0}</td>\n""".format(
                json_response["entry"][0]["preferredUsername"])

            # TANCO FILA
            table += "  </tr>\n"

            # NOVA FILA
            table += "  <tr>\n"
            # NOU CAMP (COLUMNA) a la FILA
            table += """<th scope="row">{0}</th>""".format("Photos")
            table += """<td>"""
            for photo in json_response["entry"][0]["photos"]:
                print(photo["value"])
                table += """<a href="{0}">Photo link</a>""".format(
                    photo["value"])
            table += """</td>\n"""

            # TANCO FILA
            table += "  </tr>\n"

            # NOVA FILA
            table += "  <tr>\n"

            # NOU CAMP (COLUMNA) a la FILA
            table += """<th scope="row">{0}</th>""".format("Linked URLs")
            table += """<td>"""
            urls = json_response['entry'][0]['urls']
            for url in urls:
                print(url["value"])
                table += """<a href="{0}">URL link</a>""".format(url["value"])
            table += """</td>\n"""

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
                    <h2 class="heading-section">Account not linked to gravatar.com</h2>
                </div>
            </div>
        </div>"""

    return table


def sitesUsedByTarget(email):
    process = subprocess.Popen(['holehe', '--only-used', '-C', email],
                               stdout=subprocess.PIPE,
                               universal_newlines=True)

    (output, err) = process.communicate()
    # The following line makes the waitting possible
    p_status = process.wait()
    # print(newest('/Applications/XAMPP/xamppfiles/cgi-bin/'))
    try:
        with open(newest('/Applications/XAMPP/xamppfiles/cgi-bin/'), 'r') as f:
            rowReader = csv.reader(f, delimiter=',')
            # -use this if your txt file has a header strings as column names
            next(rowReader)

            table = ""
            table = table + """
    <section class="ftco-section">
        <div class="container">
            <div class="row justify-content-center">
                <div class="col-md-6 text-center mb-5">
                    <h2 class="heading-section">Discovered sites used by target</h2>
                </div>
            </div>
            <div class="row">
                <div class="col-md-12">
                    <div class="table-wrap">
                        <table class="table table-bordered table-dark table-hover">
                            <tbody>
                                """
            # Creem la taula amb les capçaleres corresponents
            header = ['Name', 'Domain', 'Method',
                      'Email recovery', 'phoneNumber', 'others']
            table += "<thead>\n"

            for column in header:
                table += "    <th>{0}</th>\n".format(column.strip())
            table += "</thead>\n"
            for values in rowReader:
                if values[5] == "True":
                    print(values[0])
                    # NOVA FILA
                    table += "  <tr>\n"
                    # NOU CAMP (COLUMNA) a la FILA
                    table += """<th scope="row">{0}</th>""".format(values[0])
                    table += """<td>{0}</td>\n""".format(values[1])
                    table += """<td>{0}</td>\n""".format(values[2])
                    table += """<td>{0}</td>\n""".format(values[6])
                    table += """<td>{0}</td>\n""".format(values[7])
                    table += """<td>{0}</td>\n""".format(values[8])

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
                    <h2 class="heading-section">It's not able to discover sites used by target</h2>
                </div>
            </div>
        </div>"""

    return table


def get_breachdirectory_html(email):
    global json_response
    url = "https://breachdirectory.p.rapidapi.com/"

    querystring = {"func": "auto", "term": email}

    table = """<section class="ftco-section">
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-6 text-center mb-5">
                <h2 class="heading-section">Not leaks found on Breachdirectory</h2>
            </div>
        </div>
    </div>"""

    headers = {
        'x-rapidapi-key': breachdirectory_API_2,
        'x-rapidapi-host': "breachdirectory.p.rapidapi.com"
    }
    try:
        response = requests.request(
            "GET", url, headers=headers, params=querystring)

        # print(response.text)

        json_response = response.json()

        # if (json_response["error"] and (json_response["error"] == "Not found")):
        #	print("[-] This email hasn\'t been leaked!")
        # else:
        if json_response["result"] != "":
            table = ""
            table = """
    <section class="ftco-section">
        <div class="container">
            <div class="row justify-content-center">
                <div class="col-md-6 text-center mb-5">
                    <h2 class="heading-section">Leaks found on Breachdirectory</h2>
                </div>
            </div>
            <div class="row">
                <div class="col-md-12">
                    <div class="table-wrap">
                        <table class="table table-bordered table-dark table-hover">
                            <tbody>
                                """
            # Creem la taula amb les capçaleres corresponents
            header = ['Source', 'Password', 'Password Hash (Sha1)']
            table += "<thead>\n"
            for column in header:
                table += "    <th>{0}</th>\n".format(column.strip())
            table += "</thead>\n"

            for result in json_response["result"]:
                print("[+] Leaked sources: ")
                # NOVA FILA
                table += "  <tr>\n"
                # NOU CAMP (COLUMNA) a la FILA
                table += """<th scope="row">"""

                for source in result["sources"]:
                    table += """<p><a href="{0}">{0}</a></p>""".format(
                        source.strip("\n"))
                    print(" - ", source)

                table += """</th>"""
                table += """<td>{0}</td>\n""".format(result["password"])
                table += """<td>{0}</td>\n""".format(result["sha1"])
                print(" --> Password from above sources: ", result["password"])
                print(" ---> Password Hash: ", result["sha1"])
                print(" --- ")

                # TANCO FILA
                table += "  </tr>\n"

            table += """    </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </section>"""

        else:
            print("[-] This email hasn\'t been leaked!")

    except Exception as error:
        print("[-] Error extracting leaked info. Try it later.")
        print("Response: ", json_response)
        print(error)
        table = """<section class="ftco-section">
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-6 text-center mb-5">
                <h2 class="heading-section">Not leaks found in Breachdirectory</h2>
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
        table = """<section class="ftco-section">
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-6 text-center mb-5">
                <h2 class="heading-section">PSBDMP: not found on pastes</h2>
            </div>
        </div>
    </div>"""
        print("[-] Error! Check psbdmp.ws API!")

    return table


def get_darknet_leak(email):
    global req
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

    username = email.split("@")[0]
    domain = email.split("@")[1]
    # print(username)
    # print(domain)
    if not username:
        username = '%'

    request_data = {'luser': username, 'domain': domain,
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


def cmdline(command):
    process = Popen(
        args=command,
        stdout=PIPE,
        shell=True
    )
    return process.communicate()[0].decode("utf-8")


def leaksDBs(email):
    table = """<section class="ftco-section">
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-6 text-center mb-5">
                <h2 class="heading-section">Domain not exposed in local databases!</h2>
            </div>
        </div>
    </div>"""
    #onlyfiles = [f for f in listdir('./DBs/') if isfile(join('./DBs/', f))]
    #print("Onlyfiles: ", onlyfiles)
    command = cmdline("/usr/bin/grep -R " + email + " ./DBs/ 2> /dev/null")
    if command:
        print("[+] Found on leaked databases:")
        leaks = command.split()
        # print(leak)
        table = """
    <section class="ftco-section">
        <div class="container">
            <div class="row justify-content-center">
                <div class="col-md-6 text-center mb-5">
                    <h2 class="heading-section">Found on local databases</h2>
                </div>
            </div>
            <div class="row">
                <div class="col-md-12">
                    <div class="table-wrap">
                        <table class="table table-bordered table-dark table-hover">
                            <tbody>
                                """

        # Creem la taula amb les capçaleres corresponents
        header = ['Found on', 'Origin country', 'Password']
        table += "<thead>\n"
        for column in header:
            table += "    <th>{0}</th>\n".format(column.strip())
        table += "</thead>\n"
        for leak in leaks:
            try:
                # print(leak.split(":"))
                if (leak.split(":")[1] == email):
                    # NOVA FILA
                    table += "  <tr>\n"
                    # NOU CAMP (COLUMNA) a la FILA
                    table += """<th scope="row">{0}</th>""".format(
                        leak.split(":")[0].split("[")[2].split("]")[0])
                    table += """<td>{0}</td>\n""".format(
                        leak.split(":")[0].split("[")[3].split("]")[0])
                    table += """<td>{0}</td>\n""".format(leak.split(":")[2])
                    # TANCO FILA
                    table += "  </tr>\n"

                    print(" -> Leak found on: ", leak.split(":")
                          [0].split("[")[2].split("]")[0])
                    print("  - Origin country: ", leak.split(":")
                          [0].split("[")[3].split("]")[0])
                    print("  - Password: ", leak.split(":")[2])
            except:
                pass
        table += """        </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </section>"""
    return table
