__author__ = "Llorenç Garcia"
__copyright__ = "Copyright 2007, The Cogent Project"
__credits__ = ["David Marquet"]
__license__ = "GPL-3.0"
__version__ = "1.0.0"
__maintainer__ = "Llorenç Garcia and David Marquet"
__status__ = "Production"


import geoip2.webservice
#from mpl_toolkits.basemap import Basemap
import json
import sys
from datetime import datetime
from virus_total_apis import PublicApi as VirusTotalPublicApi
from shodan import Shodan
import os
#import matplotlib.pyplot as plt

os.environ["PROJ_LIB"] = "C:\\Utilities\\Python\\Anaconda\\Library\\share"  # fixr
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


def get_shodan_analisys(ip):
    table = """<section class="ftco-section">
	<div class="container">
		<div class="row justify-content-center">
			<div class="col-md-6 text-center mb-5">
				<h2 class="heading-section">Shodan: Can't retreive information</h2>
			</div>
		</div>
	</div>"""
    try:
        api = Shodan(shodan_API)
        ipinfo = api.host(ip)
        table = ""
        table = table + """
<section class="ftco-section">
	<div class="container">
		<div class="row justify-content-center">
			<div class="col-md-6 text-center mb-5">
				<h2 class="heading-section">Main Information</h2>
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
        table += """<th scope="row">{0}</th>""".format("IP")
        table += """<td>{0}</td>\n""".format(ipinfo['ip_str'])

        # TANCO FILA
        table += "  </tr>\n"

        # NOVA FILA
        table += "  <tr>\n"
        # NOU CAMP (COLUMNA) a la FILA
        table += """<th scope="row">{0}</th>""".format("Organization")
        table += """<td>{0}</td>\n""".format(ipinfo.get('org', 'n/a'))

        # TANCO FILA
        table += "  </tr>\n"

        # NOVA FILA
        table += "  <tr>\n"
        # NOU CAMP (COLUMNA) a la FILA
        table += """<th scope="row">{0}</th>""".format("Operating System")
        table += """<td>{0}</td>\n""".format(ipinfo.get('os', 'n/a'))

        # TANCO FILA
        table += "  </tr>\n"

        # NOVA FILA
        table += "  <tr>\n"
        # NOU CAMP (COLUMNA) a la FILA
        table += """<th scope="row">{0}</th>""".format("Country")
        table += """<td>{0}</td>\n""".format(ipinfo['country_name'])

        # TANCO FILA
        table += "  </tr>\n"

        # NOVA FILA
        table += "  <tr>\n"
        # NOU CAMP (COLUMNA) a la FILA
        table += """<th scope="row">{0}</th>""".format("City")
        table += """<td>{0}</td>\n""".format(ipinfo['city'])

        # TANCO FILA
        table += "  </tr>\n"

        # NOVA FILA
        table += "  <tr>\n"
        # NOU CAMP (COLUMNA) a la FILA
        table += """<th scope="row">{0}</th>""".format("Hostnames")
        table += """<td>"""
        for hostname in ipinfo['hostnames']:
            table += """<p>{0}</p>""".format(hostname)
        table += """</td>\n"""
        # TANCO FILA
        table += "  </tr>\n"

        # NOVA FILA
        table += "  <tr>\n"
        # NOU CAMP (COLUMNA) a la FILA
        table += """<th scope="row">{0}</th>""".format("Scan info")
        table += """<td>"""
        for item in ipinfo['data']:
            table += """<p>Port: {0}</p>""".format(item['port'])
            table += """<p>Banner: {0}</p>""".format(item['data'])
            table += """</br>"""
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
        print("Check your Shodan API key!")

    return table


def analizeIP_html(ip):
    table = """<section class="ftco-section">
		<div class="container">
			<div class="row justify-content-center">
				<div class="col-md-6 text-center mb-5">
					<h2 class="heading-section">Virustotal: Not IPs resolved for this domain</h2>
				</div>
			</div>
		</div>"""

    #print("Response: ", response)
    try:
        vt = VirusTotalPublicApi(vt_API_Key)
        response = vt.get_ip_report(str(ip))
        if response["response_code"]:
            print("Response_code:", response["response_code"])
            if response["response_code"] == 200:
                try:
                    table = """
					<section class="ftco-section">
						<div class="container">
							<div class="row justify-content-center">
								<div class="col-md-6 text-center mb-5">
									<h4 class="heading-section">Virustotal: Information</h4>
								</div>
							</div>
							<div class="row">
								<div class="col-md-12">
									<div class="table-wrap">
										<table class="table table-bordered table-dark table-hover">
											<tbody>
												"""
                    # Creem la taula amb les capçaleres corresponents
                    header = ['Info', 'Results']
                    table += "<thead>\n"
                    for column in header:
                        table += "    <th>{0}</th>\n".format(column.strip())
                    table += "</thead>\n"
                    if len(response["results"]["detected_urls"]) == 0:
                        # NOVA FILA
                        table += "  <tr>\n"
                        # NOU CAMP (COLUMNA) a la FILA
                        table += """<th scope="row">{0}</th>""".format(
                            "Malicious")
                        table += """<td>{0}</td>\n""".format("False")
                        # TANCO FILA
                        table += "  </tr>\n"

                    else:
                        # NOVA FILA
                        table += "  <tr>\n"
                        # NOU CAMP (COLUMNA) a la FILA
                        table += """<th scope="row">{0}</th>""".format(
                            "Malicious")
                        table += """<td>{0}</td>\n""".format("True")
                        # TANCO FILA
                        table += "  </tr>\n"

                        # NOVA FILA
                        table += "  <tr>\n"
                        # NOU CAMP (COLUMNA) a la FILA
                        table += """<th scope="row">{0}</th>""".format(
                            "Malicious URLs")
                        table += "<td>"
                        for url in response["results"]["detected_urls"]:
                            table += """<p>{0}</p>""".format(url["url"])
                        table += "</td>"

                        # TANCO FILA
                        table += "  </tr>\n"

                    # NOVA FILA
                    table += "  <tr>\n"
                    # NOU CAMP (COLUMNA) a la FILA
                    table += """<th scope="row">{0}</th>""".format(
                        "Domain Resolutions")
                    table += "<td>"
                    for resolution in response["results"]["resolutions"]:
                        table += """<p>{0} ({1})</p>""".format(
                            resolution["hostname"], resolution["last_resolved"])
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
                except:
                    print("[-] Virustotal API failed!")
    except:
        table = """<section class="ftco-section">
				<div class="container">
					<div class="row justify-content-center">
						<div class="col-md-6 text-center mb-5">
							<h2 class="heading-section">Virustotal: Not IPs resolved for this domain</h2>
						</div>
					</div>
				</div>"""
    return table


def locateIPHTML(ip):
    name = ""
    longitude = 0
    latitude = 0
    try:
        with geoip2.webservice.Client(534778, '2KcXWF0vdaOxe6dL') as client:
            response = client.city(ip)
            name = response.city.name
            if name is None:
                name = "Unknown"
            longitude = response.location.longitude
            latitude = response.location.latitude
            print("IP: " + str(ip) + " --> City: " + str(response.city.name))
            print("IP: " + str(ip) + " --> Latitude: " +
                  str(response.location.latitude))
            print("IP: " + str(ip) + " --> Longitude: " +
                  str(response.location.longitude))

    except:
        name = "Multicast IP"
        longitude = 0
        latitude = 0
    try:
        # Printar tot al mapamundi
        #fig = plt.figure(figsize=(14, 10))
        #ax = fig.add_axes([0.1, 0.1, 0.8, 0.8])

        #m = Basemap(projection='merc', llcrnrlat=-80, urcrnrlat=80,llcrnrlon=-180, urcrnrlon=180, lat_ts=20, resolution='c')
        # m.drawcoastlines()

        #m.fillcontinents(color='tan', lake_color='lightblue')
        # m.drawmapboundary(fill_color='lightblue')

        #x, y = m(longitude, latitude)
        #plt.text(x, y, name, fontsize=12, fontweight='bold', ha='left', va='top', color='k')
        #m.scatter(x, y, marker='o', color='r', zorder=5)

        # Title
        #ax.set_title("IP: " + ip)

        # Guardem la imatge en format png amb el temps actual com a nom
        now = datetime.now()
        current_time = now.strftime("%H:%M:%S")
        image_path_html = "../mapas/" + current_time + ".png"
        image_path = "../htdocs/mapas/" + current_time + ".png"
        # plt.savefig(image_path)

        text = """<section class="ftco-section">
			<div class="container">
				<div class="row justify-content-center">
					<div class="col-md-6 text-center mb-5">
						<h2 class="heading-section">IP geolocation</h2>
					</div>
					<img src="{0}" alt="IP Geolocalization" class="center">
				</div>
			</div>
		</div>""".format(image_path_html)
    except:
        text = """<section class="ftco-section">
	<div class="container">
		<div class="row justify-content-center">
			<div class="col-md-6 text-center mb-5">
				<h2 class="heading-section">Virustotal: Can't retreive reputation</h2>
			</div>
		</div>
	</div>"""

    return text
