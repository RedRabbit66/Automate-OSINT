__author__ = "Llorenç Garcia"
__copyright__ = "Copyright 2007, The Cogent Project"
__credits__ = ["David Marquet"]
__license__ = "GPL-3.0"
__version__ = "1.0.0"
__maintainer__ = "Llorenç Garcia and David Marquet"
__status__ = "Production"


import json
import socket
import sys
import time

import requests
from virus_total_apis import PublicApi as VirusTotalPublicApi

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


def getIP(d):
    table = """<section class="ftco-section">
		<div class="container">
			<div class="row justify-content-center">
				<div class="col-md-6 text-center mb-5">
					<h2 class="heading-section">Can't resolve IP address</h2>
				</div>
			</div>
		</div>"""
    try:
        data = socket.gethostbyname(d)
        ip = repr(data)
        table = """<section class="ftco-section">
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-6 text-center mb-5">
                <h2 class="heading-section">IP address: {0}</h2>
            </div>
        </div>
    </div>""".format(str(ip[1:-1]))
        print("[+] IP address: " + str(ip[1:-1]))
    except Exception:
        # fail gracefully!
        print("[-] Can't resolve domain.")
    return table


def whois_html(domain):
    print("-------------------WhoIs module---------------------")
    req_whois = requests.get(
        "https://api.whoxy.com/?key=" + whoxy_API_Key + "&whois=" + domain)
    json_whois = json.loads(req_whois.content)

    #print("RESPONSE: ", json_whois)

    table = """<section class="ftco-section">
		<div class="container">
			<div class="row justify-content-center">
				<div class="col-md-6 text-center mb-5">
					<h2 class="heading-section">It's not able to discover WHOIS information</h2>
				</div>
			</div>
		</div>"""

    if json_whois['status'] == 0:
        print("Whois Retrieval Failed")

    try:
        if json_whois['domain_registered'] != 'no':
            table = """
	<section class="ftco-section">
		<div class="container">
			<div class="row justify-content-center">
				<div class="col-md-6 text-center mb-5">
					<h2 class="heading-section">Whois Information {0}</h2>
				</div>
			</div>
			<div class="row">
				<div class="col-md-12">
					<div class="table-wrap">
						<table class="table table-bordered table-dark table-hover">
							<tbody>
								""".format(domain)
            # Creem la taula amb les capçaleres corresponents
            header = ['Information', 'Result']
            table += "<thead>\n"
            for column in header:
                table += "    <th>{0}</th>\n".format(column.strip())
            table += "</thead>\n"

            # NOVA FILA
            table += "  <tr>\n"
            # NOU CAMP (COLUMNA) a la FILA
            table += """<th scope="row">{0}</th>""".format("Registered")
            table += """<td>{0} in {1}</td>\n""".format(
                json_whois['create_date'], json_whois['domain_registrar']['registrar_name'])

            # TANCO FILA
            table += "  </tr>\n"

            # NOVA FILA
            table += "  <tr>\n"
            # NOU CAMP (COLUMNA) a la FILA
            table += """<th scope="row">{0}</th>""".format("Name servers")
            table += "<td>"
            for j in json_whois['name_servers']:
                table += """<p>{0}</p>""".format(j)
                print(j)
            table += "</td>"

            # TANCO FILA
            table += "  </tr>\n"

            # NOVA FILA
            table += "  <tr>\n"
            # NOU CAMP (COLUMNA) a la FILA
            table += """<th scope="row">{0}</th>""".format("Contact")
            table += "<td>"
            for k in json_whois['registrant_contact']:
                table += """<p>{0}</p>""".format(
                    json_whois['registrant_contact'][k])
                print(json_whois['registrant_contact'][k])
            table += "</td>"

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
            print("No match for domain" + domain)

    except KeyError as e:
        print("No information found about ", e)
    except:
        print("ERROR")

    return table


def whois_history_html(domain):
    print("-------------------WhoIs history module---------------------")
    req_whois_history = requests.get(
        "http://api.whoxy.com/?key=" + whoxy_API_Key + "&history=" + domain)
    json_whois_history = json.loads(req_whois_history.content)

    print("History: ", req_whois_history)

    dates = []

    table = ""
    table = """<section class="ftco-section">
		<div class="container">
			<div class="row justify-content-center">
				<div class="col-md-6 text-center mb-5">
					<h2 class="heading-section">It's not able to discover sites used by target</h2>
				</div>
			</div>
		</div>"""

    if json_whois_history['status'] == 0:
        print("Whois Retrieval Failed")

    print("[*] Found " + str(json_whois_history['total_records_found']) + " result(s)")

    if json_whois_history['total_records_found'] > 0:

        table = ""

        for c, i in enumerate(json_whois_history['whois_records']):
            try:

                if not i['update_date'] in dates:

                    table += """
			<section class="ftco-section">
				<div class="container">
					<div class="row justify-content-center">
						<div class="col-md-6 text-center mb-5">
							<h4 class="heading-section">Whois History {0} - Updated on {1} in {2}</h4>
						</div>
					</div>
					<div class="row">
						<div class="col-md-12">
							<div class="table-wrap">
								<table class="table table-bordered table-dark table-hover">
									<tbody>
										""".format(domain, i['update_date'], i['domain_registrar']['registrar_name'])
                    # Creem la taula amb les capçaleres corresponents
                    header = ['Information', 'Result']
                    table += "<thead>\n"
                    for column in header:
                        table += "    <th>{0}</th>\n".format(column.strip())
                    table += "</thead>\n"

                    # NOVA FILA
                    table += "  <tr>\n"
                    # NOU CAMP (COLUMNA) a la FILA
                    table += """<th scope="row">{0}</th>""".format("Contact")
                    table += "<td>"
                    for k in i['registrant_contact']:
                        table += """<p>{0}</p>""".format(
                            i['registrant_contact'][k])
                        print(i['registrant_contact'][k])
                    table += "</td>"

                    # TANCO FILA
                    table += "  </tr>\n"

                    # NOVA FILA
                    table += "  <tr>\n"
                    # NOU CAMP (COLUMNA) a la FILA
                    table += """<th scope="row">{0}</th>""".format(
                        "Name servers")
                    table += "<td>"
                    for j in i['name_servers']:
                        table += """<p>{0}</p>""".format(j)
                        print(j)
                    table += "</td>"

                    # TANCO FILA
                    table += "  </tr>\n"

                    print("[*] Domain " + domain + " was registered on " +
                          i['create_date'] + " in " + i['domain_registrar']['registrar_name'])

                    print("[*] Contact: ")
                    for k in i['registrant_contact']:
                        print(i['registrant_contact'][k])

                    print("[*] Name servers:")
                    for j in i["name_servers"]:
                        print(j)

                    table += """    </tbody>
								</table>
							</div>
						</div>
					</div>
				</div>
			</section>"""

                    dates.append(i['update_date'])

            except KeyError as e:
                print("No information found about " + e.message)

            except:
                print("No information found on " + domain)
    else:
        print("No records found")

        print("Dates: ", dates)

    return table


def virustotal_domain_html(domain):
    help = 0
    print("----------------VirusTotal module---------------------------")

    table = """<section class="ftco-section">
		<div class="container">
			<div class="row justify-content-center">
				<div class="col-md-6 text-center mb-5">
					<h2 class="heading-section">Virustotal: Not IPs resolved for this domain</h2>
				</div>
			</div>
		</div>"""

    req_virustotal = requests.get(
        "https://www.virustotal.com/vtapi/v2/domain/report?apikey=" + vt_API_Key + "&domain=" + domain)

    if req_virustotal.status_code == 204:
        print("API limitation, putting into sleep for 70 sec")
        time.sleep(70)
        req_virustotal = requests.get(
            "https://www.virustotal.com/vtapi/v2/domain/report?apikey=" + vt_API_Key + "&domain=" + domain)

    if req_virustotal.status_code == 403:
        print("Wrong API key, no more info can be gathered")
        sys.exit()

    json_virustotal = json.loads(req_virustotal.content)

    if json_virustotal['response_code'] != 0:
        table = """
		<section class="ftco-section">
			<div class="container">
				<div class="row justify-content-center">
					<div class="col-md-6 text-center mb-5">
						<h4 class="heading-section">Domain Resolutions (Virustotal)</h4>
					</div>
				</div>
				<div class="row">
					<div class="col-md-12">
						<div class="table-wrap">
							<table class="table table-bordered table-dark table-hover">
								<tbody>
									"""
        # Creem la taula amb les capçaleres corresponents
        header = ['IP address', 'Last Resolved']
        table += "<thead>\n"
        for column in header:
            table += "    <th>{0}</th>\n".format(column.strip())
        table += "</thead>\n"

        print("[*] Domain was resolved to following IPs: ")
        for i in json_virustotal['resolutions']:
            # NOVA FILA
            table += "  <tr>\n"
            print(i['ip_address'] + " on " + i['last_resolved'])
            table += """<th scope="row">{0}</th>""".format(i['ip_address'])
            table += """<td>{0}</td>""".format(i['last_resolved'])
            # TANCO FILA
            table += "  </tr>\n"
            help = help + 1
            # if help > 2:
            #	print("MAX HELP")
            #	break

        table += """</tbody>
								</table>
							</div>
						</div>
					</div>
				</div>
			</section>"""

    else:
        print("Nothing found")

    return table


def domainReputationHTML(domain):
    table = """<section class="ftco-section">
	<div class="container">
		<div class="row justify-content-center">
			<div class="col-md-6 text-center mb-5">
				<h2 class="heading-section">Virustotal: Can't retreive reputation</h2>
			</div>
		</div>
	</div>"""
    vt = VirusTotalPublicApi(vt_API_Key)
    response = vt.get_domain_report(domain)
    #print("Response: ", response)
    try:
        if response["response_code"]:
            #print("Response_code:", response["response_code"])
            if response["response_code"] == 200:
                try:
                    print(
                        "[+] Virustotal: Domain reputation ({0}):".format(domain))
                    print(
                        "  -> Veredict: ", response["results"]["Webutation domain info"]["Verdict"])
                    print("  -> Adult content?: ",
                          response["results"]["Webutation domain info"]["Adult content"])
                    print("  -> Safety score: ",
                          response["results"]["Webutation domain info"]["Safety score"])
                    table = """
					<section class="ftco-section">
						<div class="container">
							<div class="row justify-content-center">
								<div class="col-md-6 text-center mb-5">
									<h4 class="heading-section">Virustotal: Domain reputation ({0})</h4>
								</div>
							</div>
							<div class="row">
								<div class="col-md-12">
									<div class="table-wrap">
										<table class="table table-bordered table-dark table-hover">
											<tbody>
												""".format(domain)
                    # Creem la taula amb les capçaleres corresponents
                    header = ['Veredict', 'Adult content?', 'Safety score']
                    table += "<thead>\n"
                    for column in header:
                        table += "    <th>{0}</th>\n".format(column.strip())
                    table += "</thead>\n"

                    # NOVA FILA
                    table += "  <tr>\n"
                    table += """<th scope="row">{0}</th>""".format(
                        response["results"]["Webutation domain info"]["Verdict"])
                    table += """<td>{0}</td>""".format(
                        response["results"]["Webutation domain info"]["Adult content"])
                    table += """<td>{0}</td>""".format(
                        response["results"]["Webutation domain info"]["Safety score"])

                    '''
					if response["results"]["detected_downloaded_samples"]:
						if (response["results"]["detected_downloaded_samples"] > 0):
							table += """<td>"""
							table += """Positive samples found!"""
							#for sample in response["results"]["detected_downloaded_samples"]:
								#print("POSITIVES: ", sample["positives"])
								#print("DATES: ", sample["date"])
								#table += """{0}<br>""".format(sample["positives"] + " antivirus detect it as malicious at " + sample["date"])
							table += """</td>"""
						else:
							table += """<td>Legit domain</td>"""
					'''

                    # TANCO FILA
                    table += "  </tr>\n"

                    table += """</tbody>
											</table>
										</div>
									</div>
								</div>
							</div>
						</section>"""

                except:
                    pass
    except:
        pass

    return table


def get_darknet_leak(domain):
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

    # print(raw_node)
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


def getEmails(domain):
    #cors = "https://thingproxy.freeboard.io/fetch/"

    table = """<section class="ftco-section">
	<div class="container">
		<div class="row justify-content-center">
			<div class="col-md-6 text-center mb-5">
				<h2 class="heading-section">Not found emails asociated to this domain!</h2>
			</div>
		</div>
	</div>"""
    hinfo = {'content-type': 'application/json'}
    # quitar cors
    payload = json.dumps({"term": domain, "maxresults": 10000, "media": 0, "target": 2, "terminate": [
                         "d58a2c30-7c41-4f82-8a61-659b1d06218c"], "timeout": 20})
    #res = requests.post(cors + "https://public.intelx.io/phonebook/search?k=c7ca2255-89d1-4b9f-bc88-97fe781dd631",  headers=hinfo, data=payload)
    res = requests.post(
        "https://public.intelx.io/phonebook/search?k=c7ca2255-89d1-4b9f-bc88-97fe781dd631",  headers=hinfo, data=payload)
    if res.status_code == 200:
        tmp = res.json()
        #print("TMP: ", tmp)
        id = tmp["id"]
        #print("ID: ", id)
        time.sleep(1)
        #res = requests.get(cors+"https://public.intelx.io/phonebook/search/result?k=c7ca2255-89d1-4b9f-bc88-97fe781dd631&id="+tmp["id"]+"&limit=10000")
        res = requests.get(
            "https://public.intelx.io/phonebook/search/result?k=c7ca2255-89d1-4b9f-bc88-97fe781dd631&id="+tmp["id"]+"&limit=10000")
        # print(res.text)
        json_response = res.json()
        #print("JSON_Response: ", json_response)
        try:
            table = """
			<section class="ftco-section">
				<div class="container">
					<div class="row justify-content-center">
						<div class="col-md-6 text-center mb-5">
							<h4 class="heading-section">Emails discovered for this domain ({0})</h4>
						</div>
					</div>
					<div class="row">
						<div class="col-md-12">
							<div class="table-wrap">
								<table class="table table-bordered table-dark table-hover">
									<tbody>
										""".format(domain)
            # Creem la taula amb les capçaleres corresponents
            header = ['Email']
            table += "<thead>\n"
            for column in header:
                table += "    <th>{0}</th>\n".format(column.strip())
            table += "</thead>\n"

            print("[+] Emails discovered for this domain:")
            for selector in json_response["selectors"]:
                # NOVA FILA
                table += "  <tr>\n"
                table += """<th scope="row">{0}</th>""".format(
                    selector["selectorvalue"])
                print("  -> Email discovered: ", selector["selectorvalue"])
                # TANCO FILA
                table += "  </tr>\n"
            table += """</tbody>
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
				<h2 class="heading-section">Not found emails asociated to this domain!</h2>
			</div>
		</div>
	</div>"""

    else:
        table = """<section class="ftco-section">
	<div class="container">
		<div class="row justify-content-center">
			<div class="col-md-6 text-center mb-5">
				<h2 class="heading-section">Not found emails asociated to this domain!</h2>
			</div>
		</div>
	</div>"""

    return table
