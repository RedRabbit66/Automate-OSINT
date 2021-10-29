__author__ = "Llorenç Garcia"
__copyright__ = "Copyright 2007, The Cogent Project"
__credits__ = ["David Marquet"]
__license__ = "GPL-3.0"
__version__ = "1.0.0"
__maintainer__ = "Llorenç Garcia and David Marquet"
__status__ = "Production"


import sys
import json
import re
import hashlib
import argparse
from xhtml2pdf import pisa
import username_module
import username_html
import email_module
import email_html
import wallet_module
import wallet_html
import password_module
import password_html
import term_module
import term_html
import domain_module
import domain_html
import ip_module
import ip_html
import hashlib

email_pattern = '(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)'
domain_pattern = '^((?!-))(xn--)?[a-z0-9][a-z0-9-_]{0,61}[a-z0-9]{0,1}\.(xn--)?([a-z0-9\-]{1,61}|[a-z0-9-]{1,30}\.[a-z]{2,})$'


def parseConfig():
    conf_file = "config.json"
    try:
        with open(conf_file, 'r') as read_conf:
            conf = json.load(read_conf)
    except Exception as e:
        print("Unable to parse config file: {0}".format(e))
        sys.exit()

    return conf


def returnIndex(message):
    contingut_HTML = "Content-Type: text/html; charset=UTF-8\r\n"
    contingut_HTML = contingut_HTML + """<html>
	<head>
		<title>Error</title>
		<meta http-equiv=\"Refresh\" content=\"5; url=/index.html\" />
	</head>
	<body>
		<p>{0}</p>
	</body>
</html>""".format(message)
    f.write(contingut_HTML)
    f.close()
    exit(0)


def convert_html_to_pdf(source_html, output_filename):
    # open output file for writing (truncated binary)
    result_file = open(output_filename, "w+b")

    # convert HTML to PDF
    pisa_status = pisa.CreatePDF(
        source_html,                # the HTML to convert
        dest=result_file)           # file handle to recieve result

    # close output file
    result_file.close()                 # close output file

    # return False on success and True on errors
    return pisa_status.err


def parseArgs():
    parser = argparse.ArgumentParser(
        prog='automate-osint.py', usage='%(prog)s [options] path', description='Automated-OSINT is used to gather open source intelligence (OSINT) on diferent aspects.')
    parser.add_argument('-e', '--email', help='Email to search.',
                        required=False, type=str, default="")
    parser.add_argument('-d', '--domain', help='Company name or domain to search.',
                        required=False, type=str, default="")
    parser.add_argument('-u', '--username', help='Username to search.',
                        required=False, type=str, default="")
    parser.add_argument('-i', '--ip', help='IP to search.',
                        required=False, type=str, default="")
    parser.add_argument('-p', '--password', help='Password to search.',
                        required=False, type=str, default="")
    parser.add_argument('-w', '--wallet', help='BTC wallet to search.',
                        required=False, type=str, default="")
    parser.add_argument('-t', '--term', help='BTC wallet to search.',
                        required=False, type=str, default="")
    parser.add_argument('-html', '--html', help='Enable HTML output, default False.',
                        default=False, action='store_true')
    global arguments
    arguments = parser.parse_args()


def main():

    document_name = "default"
    output_pdf_filename = "default.pdf"

    parseArgs()

    config = parseConfig()
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
    leak_lookup_API = config["keys"]["leak_lookup"]
    google_API = config["keys"]["google"]
    breachdirectory_API_2 = config["keys"]["breachdirectory"]
    google_cx = config["keys"]["google_cx"]
    shodan_API = config["keys"]["shodan"]
    censys_API = config["keys"]["censys"]
    censys_secret = config["keys"]["censys_secret"]
    psbdmp_API = config["keys"]["psbdmp"]
    whoxy_API_Key = config["keys"]["whoxy"]
    vt_API_Key = config["keys"]["virustotal"]
    bitcoin_abuse_API = config["keys"]["bitcoin_abuse"]
    bitcoinwhoswho_API_KEY = config["keys"]["bitcoinwhoswho"]

    email = arguments.email
    domain = arguments.domain
    username = arguments.username
    ip = arguments.ip
    password = arguments.password
    wallet = arguments.wallet
    global html_output
    html_output = arguments.html
    term = arguments.term

    if email:
        document_name = hashlib.sha1(email.encode('utf-8')).hexdigest()
    if domain:
        document_name = hashlib.sha1(domain.encode('utf-8')).hexdigest()
    if username:
        document_name = hashlib.sha1(username.encode('utf-8')).hexdigest()
    if ip:
        document_name = hashlib.sha1(ip.encode('utf-8')).hexdigest()
    if password:
        document_name = hashlib.sha1(password.encode('utf-8')).hexdigest()
    if wallet:
        document_name = hashlib.sha1(wallet.encode('utf-8')).hexdigest()
    if term:
        document_name = hashlib.sha1(term.encode('utf-8')).hexdigest()

    #os.system("touch ../htdocs/results/" + document_name + ".html")
    #os.system("/bin/chmod 777 ../htdocs/results/" + document_name + ".html")
    global f
    f = open("../htdocs/results/" + document_name + ".html", 'w')

    global contingut_HTML
    #contingut_HTML = "Content-Type: text/html; charset=UTF-8\r\n"
    contingut_HTML = ""
    contingut_HTML = contingut_HTML + """<html>
	<head>
		<title>{0}</title>
		<meta charset="utf-8">
		<meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">

		<link href='https://fonts.googleapis.com/css?family=Roboto:400,100,300,700' rel='stylesheet' type='text/css'>

		<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/font-awesome/4.7.0/css/font-awesome.min.css">
		
		<link rel="stylesheet" href="../css/style.css">



	</head>
	<body>""".format("Results")

    if email:
        if(email and (re.match(email_pattern, email))):
            if not html_output:
                email_module.parseConfig()
                email_module.get_gravatar_info(email)
                print("")
                email_module.comprova_leaks(email)
                print("")
                email_module.get_breachdirectory(email)
                print("")
                email_module.get_darknet_leak(email)
                print("")
                email_module.pastes_search(email)
                print("")
                email_module.psbdmp_search(email)
                print("")
                email_module.leaksDBs(email)
                print("")
                email_module.sitesUsedByTarget(email)
                #print("Email to phone investigation:")
                # trio.run(email2phone)
            else:
                email_html.parseConfig()
                contingut_HTML = contingut_HTML + \
                    email_html.get_gravatar_info_html(email)
                contingut_HTML = contingut_HTML + \
                    email_html.sitesUsedByTarget(email)
                contingut_HTML = contingut_HTML + \
                    email_html.get_breachdirectory_html(email)
                contingut_HTML = contingut_HTML + \
                    email_html.pastes_search_html(email)
                contingut_HTML = contingut_HTML + \
                    email_html.psbdmp_search_html(email)
                contingut_HTML = contingut_HTML + \
                    email_html.get_darknet_leak(email)
                contingut_HTML = contingut_HTML + email_html.leaksDBs(email)

        else:
            print("[-] This is not an email!")
            returnIndex(
                "This is not an email! Redirecting you to the main page.")

    if domain:
        if (domain and (re.match(domain_pattern, domain))):
            if not html_output:
                domain_module.parseConfig()
                domain_module.getIP(domain)
                print("")
                domain_module.whois(domain)
                print("")
                domain_module.whois_history(domain)
                print("")
                domain_module.virustotal_domain(domain)
                print("")
                domain_module.domainReputation(domain)
                print("")
                domain_module.get_darknet_leak(domain)
                print("")
                domain_module.getEmails(domain)

            else:
                domain_html.parseConfig()

                contingut_HTML = contingut_HTML + domain_html.getIP(domain)
                contingut_HTML = contingut_HTML + \
                    domain_html.whois_html(domain)
                contingut_HTML = contingut_HTML + \
                    domain_html.whois_history_html(domain)
                contingut_HTML = contingut_HTML + \
                    domain_html.virustotal_domain_html(domain)
                contingut_HTML = contingut_HTML + \
                    domain_html.domainReputationHTML(domain)
                contingut_HTML = contingut_HTML + \
                    domain_html.get_darknet_leak(domain)
                contingut_HTML = contingut_HTML + domain_html.getEmails(domain)

        else:
            print("[-] This is not a domain!")
            returnIndex(
                "This is not a domain! Redirecting you to the main page.")

    if username:
        if html_output:
            username_html.parseConfig()
            contingut_HTML = contingut_HTML + \
                username_html.sherlock_finder(username)
            contingut_HTML = contingut_HTML + \
                username_html.psbdmp_search_html(username)
            contingut_HTML = contingut_HTML + \
                username_html.pastes_search_html(username)
            contingut_HTML = contingut_HTML + \
                username_html.get_darknet_leak(username)
        else:
            username_module.parseConfig()
            username_module.sherlock_finder(username)
            print("")
            username_module.pastes_search(username)
            print("")
            username_module.psbdmp_search(username)
            print("")
            username_module.get_darknet_leak(username)

    if ip:
        if html_output:
            ip_html.parseConfig()
            contingut_HTML = contingut_HTML + ip_html.get_shodan_analisys(ip)
            contingut_HTML = contingut_HTML + ip_html.locateIPHTML(ip)
            contingut_HTML = contingut_HTML + ip_html.analizeIP_html(ip)
        else:
            ip_module.parseConfig()
            ip_module.locateIP(ip)
            print("")
            ip_module.get_shodan_analisys(ip)
            print("")
            ip_module.analizeIP(ip)

    if password:
        if html_output:
            password_html.parseConfig()
            contingut_HTML = contingut_HTML + \
                password_html.commonPasswordChecker(password)
            contingut_HTML = contingut_HTML + \
                password_html.pastes_search_html(password)
            contingut_HTML = contingut_HTML + \
                password_html.psbdmp_search_html(password)
            contingut_HTML = contingut_HTML + \
                password_html.leakedPasswordChecker(password)
            contingut_HTML = contingut_HTML + \
                password_html.get_darknet_leak(password)
        else:
            password_module.parseConfig()
            password_module.commonPasswordChecker(password)
            print("")
            password_module.leakedPasswordChecker(password)
            print("")
            password_module.pastes_search(password)
            print("")
            password_module.psbdmp_search(password)
            print("")
            password_module.get_darknet_leak(password)

    if wallet:
        if not html_output:
            wallet_module.parseConfig()
            wallet_module.btc_info(wallet)
            print("")
            wallet_module.wallet_report(wallet)
            print("")
            wallet_module.url_wallet_info(wallet)
        else:
            wallet_html.parseConfig()
            contingut_HTML = contingut_HTML + wallet_html.btc_info_html(wallet)
            contingut_HTML = contingut_HTML + \
                wallet_html.wallet_report_html(wallet)
            contingut_HTML = contingut_HTML + \
                wallet_html.url_wallet_info_html(wallet)

    if term:
        if html_output:
            contingut_HTML = contingut_HTML + term_html.databaseCheck(term)
        else:
            term_module.databaseCheck(term)

    if html_output:

        pdf_path_html = "../pdfs/" + document_name + ".pdf"

        contingut_HTML = contingut_HTML + """
		<footer><center><a href="{0}" target="_blank">Download PDF Report</a><br><a href="{1}">Return Home page</a></center></footer>
		<script src="js/jquery.min.js"></script>
		<script src="js/popper.js"></script>
		<script src="js/bootstrap.min.js"></script>
		<script src="js/main.js"></script>

		</body>
	</html>""".format(pdf_path_html, "../../index.html")

        f.write(contingut_HTML)
        f.close()

        output_pdf_filename = "../htdocs/pdfs/" + document_name + ".pdf"

        convert_html_to_pdf(contingut_HTML, output_pdf_filename)

        print("Document name (results folder): ", document_name)


if __name__ == '__main__':
    main()
