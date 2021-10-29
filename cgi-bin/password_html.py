__author__ = "Llorenç Garcia"
__copyright__ = "Copyright 2007, The Cogent Project"
__credits__ = ["David Marquet"]
__license__ = "GPL-3.0"
__version__ = "1.0.0"
__maintainer__ = "Llorenç Garcia and David Marquet"
__status__ = "Production"


import sys
import json
import requests
import hashlib
from googleapiclient.discovery import build
from subprocess import PIPE, Popen


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
    table = """<section class="ftco-section">
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-6 text-center mb-5">
                <h2 class="heading-section">Password not found on common lists</h2>
            </div>
        </div>
    </div>"""
    command = cmdline("/usr/bin/grep -R " + password +
                      " ./Passwords/ 2> /dev/null")
    if command:
        print("[+] Found on leaked databases:")
        leaks = command.split()
        table = """
    <section class="ftco-section">
        <div class="container">
            <div class="row justify-content-center">
                <div class="col-md-6 text-center mb-5">
                    <h2 class="heading-section">Password found on common lists</h2>
                </div>
            </div>
            <div class="row">
                <div class="col-md-12">
                    <div class="table-wrap">
                        <table class="table table-bordered table-dark table-hover">
                            <tbody>
                                """
        # Creem la taula amb les capçaleres corresponents
        header = ['Password', 'List']
        table += "<thead>\n"
        for column in header:
            table += "    <th>{0}</th>\n".format(column.strip())
        table += "</thead>\n"
        for leak in leaks:
            try:
                passwd = leak.split(":")[1]
                if passwd == password:
                    # NOVA FILA
                    table += "  <tr>\n"
                    # NOU CAMP (COLUMNA) a la FILA
                    table += """<th scope="row"><a href="{0}">{0}</a></th>""".format(
                        password)
                    table += """<td>{0}</td>\n""".format(
                        str(leak.split(":")[0].split("//")[1]))

                    # TANCO FILA
                    table += "  </tr>\n"
                    print("[+] Password found on: ",
                          str(leak.split(":")[0].split("//")[1]))
                    common = False
            except:
                pass
        table += """    </tbody>
						</table>
					</div>
				</div>
			</div>
		</div>
	</section>"""
    if common:
        print("[-] It's not a common password!")
    else:
        print("[+] It's a common password!")
    return table


# Google Custom Search Engine
def pastes_search_html(search):
    # Build a service object for interacting with the API. Visit
    # the Google APIs Console <http://code.google.com/apis/console>
    # to get an API key for your own application.
    service = build("customsearch", "v1", developerKey=google_API)

    table = """<section class="ftco-section">
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-6 text-center mb-5">
                <h2 class="heading-section">Password not found on any paste from internet</h2>
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
                    <h2 class="heading-section">Password found it on pastes from internet</h2>
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


def leakedPasswordChecker(password):
    table = """<section class="ftco-section">
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-6 text-center mb-5">
                <h2 class="heading-section">HaveIBeenPwned: Safe password! It hasn't been leaked yet!</h2>
            </div>
        </div>
    </div>"""

    leaked = False
    password_hash = hashlib.sha1(password.encode('utf-8')).hexdigest()
    command = cmdline("/usr/bin/grep -i " + password_hash +
                      " ./Passwords/pwned-passwords-sha1.txt 2> /dev/null")
    if command:
        print("[+] Found on leaked databases:")
        leaks = command.split()
        table = ""
        table = """
    <section class="ftco-section">
        <div class="container">
            <div class="row justify-content-center">
                <div class="col-md-6 text-center mb-5">
                    <h2 class="heading-section">HaveIBeenPwned: Password already leaked</h2>
                </div>
            </div>
            <div class="row">
                <div class="col-md-12">
                    <div class="table-wrap">
                        <table class="table table-bordered table-dark table-hover">
                            <tbody>
                                """

        # Creem la taula amb les capçaleres corresponents
        header = ['Hash', 'Count']
        table += "<thead>\n"
        for column in header:
            table += "    <th>{0}</th>\n".format(column.strip())
        table += "</thead>\n"
        for leak in leaks:
            #print("Leak:", leak)
            try:

                # NOVA FILA
                table += "  <tr>\n"
                # NOU CAMP (COLUMNA) a la FILA
                table += """<th scope="row">{0}</th>""".format(password_hash)
                table += """<td>{0}</td>\n""".format(str(leak.split(":")[1]))
                # TANCO FILA
                table += "  </tr>\n"

                print("[+] Hash: ", password_hash)
                print("[+] Times founded: ", str(leak.split(":")[1]))
                leaked = True
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


def get_darknet_leak(password):
    table = """<section class="ftco-section">
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-6 text-center mb-5">
                <h2 class="heading-section">Password not exposed in Darknet market yet!</h2>
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

    request_data = {'password': password, 'submitform': 'pw'}

    try:
        req = session.post(url, data=request_data, headers={
                           'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36'})
    except Exception as error:
        raw_node = {'status': 'No TOR', 'desc': str(type(error))}

    print("RAW: ", raw_node)
    if (raw_node == []):
        if ("Array" in req.text):
            leaks = req.text.split("Array")[1:]
            emails = []
            for leak in leaks:
                print("Leak: ", leak)

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
