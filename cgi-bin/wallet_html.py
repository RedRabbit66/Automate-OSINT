__author__ = "Llorenç Garcia"
__copyright__ = "Copyright 2007, The Cogent Project"
__credits__ = ["David Marquet"]
__license__ = "GPL-3.0"
__version__ = "1.0.0"
__maintainer__ = "Llorenç Garcia and David Marquet"
__status__ = "Production"


import sys
import requests
import json


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


def wallet_report_html(address):

    table = """<section class="ftco-section">
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-6 text-center mb-5">
                <h2 class="heading-section">No records found of this wallet</h2>
            </div>
        </div>
    </div>"""

    try:

        url = "https://www.bitcoinabuse.com/api/reports/check?"

        response = requests.request("GET", url)

        # print(response.text)

        req_address = requests.get(
            "https://www.bitcoinabuse.com/api/reports/check?address=" + address + "&api_token=" + bitcoin_abuse_API)

        json_adress = json.loads(req_address.content)

        #print("JSON: ", json_adress)

        if json_adress["count"] > 0:
            table = ""
            table = """
    <section class="ftco-section">
        <div class="container">
            <div class="row justify-content-center">
                <div class="col-md-6 text-center mb-5">
                    <h2 class="heading-section">Reports of this wallet</h2>
                </div>
            </div>
            <div class="row">
                <div class="col-md-12">
                    <div class="table-wrap">
                        <table class="table table-bordered table-dark table-hover">
                            <tbody>
                                """
            # Creem la taula amb les capçaleres corresponents
            header = ['Abuse Type ID', 'Abuse Type',
                      'Description', 'Created at']
            table += "<thead>\n"
            for column in header:
                table += "    <th>{0}</th>\n".format(column.strip())
            table += "</thead>\n"
            for record in json_adress["recent"]:
                print("[+] New record")
                print("Abuse Type ID: ", record["abuse_type_id"])
                print("Abuse Type: ", record["abuse_type_other"])
                print("Description: ", record["description"])
                print("Created at: ", record["created_at"])

                # NOVA FILA
                table += "  <tr>\n"
                # NOU CAMP (COLUMNA) a la FILA
                table += """<th scope="row">{0}</th>""".format(
                    record["abuse_type_id"])
                table += """<td>{0}</td>\n""".format(
                    record["abuse_type_other"])
                table += """<td>{0}</td>\n""".format(record["description"])
                table += """<td>{0}</td>\n""".format(record["created_at"])

                # TANCO FILA
                table += "  </tr>\n"

            table += """    </tbody>
						</table>
					</div>
				</div>
			</div>
		</div>
	</section>"""

    #json_response = response.json()

    except:
        print("[-] API BitcoinAbuse Error")

    return table


def url_wallet_info_html(address):

    table = """<section class="ftco-section">
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-6 text-center mb-5">
                <h2 class="heading-section">BitcoinWhoisWho: Not found on any URL</h2>
            </div>
        </div>
    </div>"""

    try:

        # print(response.text)

        req_address = requests.get(
            "https://bitcoinwhoswho.com/api/url/" + bitcoinwhoswho_API_KEY + "?address=" + address)

        json_response = json.loads(req_address.content)

        print("JSON: ", json_response)

        if json_response["status"] == "success":
            table = ""
            table = """
    <section class="ftco-section">
        <div class="container">
            <div class="row justify-content-center">
                <div class="col-md-6 text-center mb-5">
                    <h2 class="heading-section">BitcoinWhoiswho: Found on the following URLs</h2>
                </div>
            </div>
            <div class="row">
                <div class="col-md-12">
                    <div class="table-wrap">
                        <table class="table table-bordered table-dark table-hover">
                            <tbody>
                                """
            # Creem la taula amb les capçaleres corresponents
            header = ['URL', 'Page title', 'Meta description']
            table += "<thead>\n"
            for column in header:
                table += "    <th>{0}</th>\n".format(column.strip())
            table += "</thead>\n"
            for url in json_response["urls"]:
                print("[+] New record")
                print("URL: ", url["url"])
                print("Page title: ", url["page_title"])
                print("Meta description: ", url["meta_description"])

                # NOVA FILA
                table += "  <tr>\n"
                # NOU CAMP (COLUMNA) a la FILA
                table += """<th scope="row">{0}</th>""".format(url["url"])
                table += """<td>{0}</td>\n""".format(url["page_title"])
                table += """<td>{0}</td>\n""".format(url["meta_description"])

                # TANCO FILA
                table += "  </tr>\n"

            table += """    </tbody>
						</table>
					</div>
				</div>
			</div>
		</div>
	</section>"""

    #json_response = response.json()

    except:
        print("[-] API BitcoinWhoiswho Error")
        table = """<section class="ftco-section">
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-6 text-center mb-5">
                <h2 class="heading-section">BitcoinWhoisWho: Not found on any URL</h2>
            </div>
        </div>
    </div>"""

    return table


def btc_info_html(wallet):
    table = """<section class="ftco-section">
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-6 text-center mb-5">
                <h2 class="heading-section">BTC.com: Not info found from this wallet</h2>
            </div>
        </div>
    </div>"""
    try:

        # print(response.text)

        req_address = requests.get(
            "https://chain.api.btc.com/v3/address/" + wallet)

        json_adress = json.loads(req_address.content)

        #print("JSON: ", json_adress)

        #json_response = response.json()

        if json_adress["status"] == "success":
            table = ""
            table = """
    <section class="ftco-section">
        <div class="container">
            <div class="row justify-content-center">
                <div class="col-md-6 text-center mb-5">
                    <h2 class="heading-section">BTC.com: Wallet info</h2>
                </div>
            </div>
            <div class="row">
                <div class="col-md-12">
                    <div class="table-wrap">
                        <table class="table table-bordered table-dark table-hover">
                            <tbody>
                                """
            # Creem la taula amb les capçaleres corresponents
            header = ['Satoshis receibed', 'Satoshis sent', 'Actual balance',
                      'Total Transactions', 'First transaction', 'Last Transaction']
            table += "<thead>\n"
            for column in header:
                table += "    <th>{0}</th>\n".format(column.strip())
            table += "</thead>\n"

            # NOVA FILA
            table += "  <tr>\n"
            # NOU CAMP (COLUMNA) a la FILA
            table += """<th scope="row">{0}</th>""".format(
                json_adress["data"]["received"])
            table += """<td>{0}</td>\n""".format(json_adress["data"]["sent"])
            table += """<td>{0}</td>\n""".format(
                json_adress["data"]["balance"])
            table += """<td>{0}</td>\n""".format(
                json_adress["data"]["tx_count"])
            table += """<td>{0}</td>\n""".format(
                json_adress["data"]["first_tx"])
            table += """<td>{0}</td>\n""".format(
                json_adress["data"]["last_tx"])

            # TANCO FILA
            table += "  </tr>\n"

            table += """    </tbody>
						</table>
					</div>
				</div>
			</div>
		</div>
	</section>"""

            print("[+] BTC info:")
            print("Satoshis receibed: ", json_adress["data"]["received"])
            print("Satoshis sent: ", json_adress["data"]["sent"])
            print("Actual balance: ", json_adress["data"]["balance"])
            print("Total Transactions: ", json_adress["data"]["tx_count"])
            print("First transaction: ", json_adress["data"]["first_tx"])
            print("Last Transaction: ", json_adress["data"]["last_tx"])

    except:
        print("BitcoinAbuse API Error")

    return table
