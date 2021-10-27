#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import json
import requests
import sys
import socket
from datetime import datetime
import time
from virus_total_apis import PublicApi as VirusTotalPublicApi
import urllib.request
import time


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
	"""
	This method returns the first IP address string
	that responds as the given domain name
	"""
	try:
		data = socket.gethostbyname(d)
		ip = repr(data)
		print("[+] IP address: " + str(ip[1:-1]))
	except Exception:
		# fail gracefully!
		print("[-] Can't resolve domain.")

def whois(domain):
	print("[+] WhoIs module")
	req_whois = requests.get("https://api.whoxy.com/?key=" + whoxy_API_Key + "&whois=" + domain)
	json_whois = json.loads(req_whois.content)

	if json_whois['status'] == 0:
		print("[-] Whois Retrieval Failed")

	try:
		if json_whois['domain_registered'] != 'no':

			print(" -> Domain " + json_whois['domain_name'] +  " was registered on " +  json_whois['create_date'] +  " in " + json_whois['domain_registrar']['registrar_name'])
			print(" -> Name servers")


			for j in json_whois['name_servers']:
				print("  -->" + j)

			#print(json_whois['registrant_contact'])
			#print(json_whois['name_servers'])
			#print(json_whois['domain_name'])

			print(" -> Contact: ")

			for k in json_whois['registrant_contact']:
				print(json_whois['registrant_contact'][k])
		else:
			print("[-] No match for domain" + domain)

	except KeyError as e:
		print("[-] No information found about " , e)
	except:
		print("[-] Whois Retrieval Failed")



def whois_history(domain):
	print("[+] WhoIs history module")
	req_whois_history = requests.get(
		"http://api.whoxy.com/?key=" + whoxy_API_Key + "&history=" + domain)
	json_whois_history = json.loads(req_whois_history.content)

	help = 0

	if json_whois_history['status'] == 0:
		print("[-] Whois Retrieval Failed")
		return False

	print(" [*] Found " + str(json_whois_history['total_records_found']) + " result(s)")

	if json_whois_history['total_records_found'] > 0:

		for c, i in enumerate(json_whois_history['whois_records']):
			try:

				print(" -> Domain " + domain + " was registered on " + i['update_date'] + " in " + i['domain_registrar']['registrar_name'])

				print(" -> Contact: ")
				for k in i['registrant_contact']:
					print(i['registrant_contact'][k])

				print(" -> Name servers:")
				for j in i["name_servers"]:
					print("   --> " + j)


			except KeyError as e:
				print(" - No information found about ", e)

			except:
				print(" - No information found on " + domain)
	else:
		print("[-] No records found")


def virustotal_domain(domain):
	help = 0
	print("[+] VirusTotal module")

	req_virustotal = requests.get("https://www.virustotal.com/vtapi/v2/domain/report?apikey=" + vt_API_Key + "&domain=" + domain)

	if req_virustotal.status_code == 204:
		print("API limitation, putting into sleep for 70 sec")
		time.sleep(70)
		req_virustotal = requests.get("https://www.virustotal.com/vtapi/v2/domain/report?apikey=" + vt_API_Key + "&domain=" + domain)

	if req_virustotal.status_code == 403:
		print("Wrong API key, no more info can be gathered")
		sys.exit()

	json_virustotal = json.loads(req_virustotal.content)

	if json_virustotal['response_code'] != 0:
		print(" - Domain was resolved to following IPs: ")
		for i in json_virustotal['resolutions']:
			print(i['ip_address'] + " on " + i['last_resolved'])
			#help = help + 1
			#if help > 2:
			#	break
	else:
		print("Nothing found")

def domainReputation(domain):
	vt = VirusTotalPublicApi(vt_API_Key)
	response = vt.get_domain_report(domain)
	#print("Response: ", response)
	try:
		if response["response_code"]:
			#print("Response_code:", response["response_code"])
			if response["response_code"] == 200:
				try:
					print("[+] Virustotal: Domain reputation ({0}):".format(domain))
					print("  -> Veredict: ", response["results"]["Webutation domain info"]["Verdict"])
					print("  -> Adult content?: ", response["results"]["Webutation domain info"]["Adult content"])
					print("  -> Safety score: ", response["results"]["Webutation domain info"]["Safety score"])
					if response["results"]["detected_downloaded_samples"]:
						if (response["results"]["detected_downloaded_samples"] > 0):
							for sample in response["results"]["detected_downloaded_samples"]:
								print(" --> " + sample["positives"] + " antivirus detect it as malicious at " + sample["date"])
						else:
							#print("[+] Domain: " + domain)
							print("  --> Legit domain!!!")
				except:
					return False
	except:
		print("[-] Can't analyze domain, check your interent connection and API key.")





def get_darknet_leak(domain):
	# Tor proxy
	from_m = "Initial"
	proxy = "127.0.0.1:9150"
	raw_node = []
	session = requests.session()
	session.proxies = {'http': 'socks5h://{}'.format(proxy), 'https': 'socks5h://{}'.format(proxy)}
	url = "http://pwndb2am4tzkvold.onion/"

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
		print("[-] Not exposed in darknet")
	


def getEmails(domain):
	# el cors quítalo es porque lo uso de proxy que no me deja hacer mas peticiones desde mi ip
	#cors = "https://thingproxy.freeboard.io/fetch/"
	hinfo = {'content-type': 'application/json' }
	# quitar cors
	payload = json.dumps({"term":domain,"maxresults":10000,"media":0,"target":2,"terminate":["d58a2c30-7c41-4f82-8a61-659b1d06218c"],"timeout":20})
	#res = requests.post(cors + "https://public.intelx.io/phonebook/search?k=c7ca2255-89d1-4b9f-bc88-97fe781dd631",  headers=hinfo, data=payload)
	res = requests.post("https://public.intelx.io/phonebook/search?k=c7ca2255-89d1-4b9f-bc88-97fe781dd631",  headers=hinfo, data=payload)
	if res.status_code == 200:
		tmp = res.json()
		#print("TMP: ", tmp)
		id = tmp["id"]
		#print("ID: ", id)
		time.sleep(1)
		#res = requests.get(cors+"https://public.intelx.io/phonebook/search/result?k=c7ca2255-89d1-4b9f-bc88-97fe781dd631&id="+tmp["id"]+"&limit=10000")
		res = requests.get("https://public.intelx.io/phonebook/search/result?k=c7ca2255-89d1-4b9f-bc88-97fe781dd631&id="+tmp["id"]+"&limit=10000")
		#print(res.text)
		json_response = res.json()
		#print("JSON_Response: ", json_response)
		try:
			print("[+] Emails discovered for this domain:")
			for selector in json_response["selectors"]:
				print ("  -> Email discovered: ", selector["selectorvalue"])

		except:
			print("[-] No emails available for this domain.")

	else:
		print(res)


