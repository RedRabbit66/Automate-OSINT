__author__ = "Llorenç Garcia"
__copyright__ = "Copyright 2007, The Cogent Project"
__credits__ = ["David Marquet"]
__license__ = "GPL-3.0"
__version__ = "1.0.0"
__maintainer__ = "Llorenç Garcia and David Marquet"
__status__ = "Production"


#from mpl_toolkits.basemap import Basemap
import sys
import email
import os
import requests
from subprocess import PIPE, Popen
import re
import whois
from datetime import datetime
import time
import json
import hashlib
from virus_total_apis import PublicApi as VirusTotalPublicApi
import geoip2.webservice
#import matplotlib.pyplot as plt

os.environ["PROJ_LIB"] = "C:\\Utilities\\Python\\Anaconda\\Library\\share"  # fixr
#import yara

apivoid_key2 = "39a9de59018068d9989ce9a307d1958d09703878"
apivoid_key = "dd08fe53e3bb8e67a51231af51ef8326a89559a5"
API_KEY = 'df343cda8c9487e24a6c9c002a99d1c5415c4cec6ad84fdec88d5ebb4783e77e'
vt = VirusTotalPublicApi(API_KEY)

ip_pattern = '^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
ipv6_pattern = '(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))'
domain_pattern = '(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)'
regex_domain = "^((?!-))(xn--)?[a-z0-9][a-z0-9-_]{0,61}[a-z0-9]{0,1}\.(xn--)?([a-z0-9\-]{1,61}|[a-z0-9-]{1,30}\.[a-z]{2,})$"


puntuacio = 100  # Nem restant fins arribar a 0
#spf_pass = False
links_to_analyze = []

office_macro_yara = "./yaras/Office_macro1.yara"
office_autoopen_yara = "./yaras/Office_doc_autoopen.yara"
office_code_execution_yara = "./yaras/Office_doc_code_execution.yara"
malicious_pdf_yara = "./yaras/pdf_rules.yara"

intel_phishing = "./yaras/yara_phishing_llorenc.yara"
intel_phishing2 = "./yaras/suspect_phishing1.yara"

scl_yara = "./yaras/scl-rule.yara"
bcl_yara = "./yaras/bcl-rule.yara"

intel_phishing_result = False
intel_phishing2_result = False

scl_yara_result = False
bcl_yara_result = False

domain_public_provider = False
same_company = False


from_domain = ""
reply_to_domain = ""
return_path_domain = ""

spf_pass = ''
spf_arc_pass = ''
dkim_pass = ''
dkim_arc_pass = ''
dmarc_pass = ''
dmarc_arc_pass = ''

longituds = []
latituds = []
city_names = []

if (len(sys.argv) != 2):
    print("Usage: python3 script.py <email_to_test.eml>")
    exit()


def FileCheck(fn):
    try:
        f = open(fn)
        msg = email.message_from_file(f)
        f.close()
        return msg
    except IOError:
        print("Error: File does not appear to exist.")
        exit()
        return 0


msg = FileCheck(sys.argv[1])
if(msg == 0):
    print("Can't open the file.")
    exit(0)

parser = email.parser.HeaderParser()
headers = parser.parsestr(msg.as_string())

# Printar les capçaleres
'''
for header in headers.items():
    print(header)
'''


def generateTableMesuresSeguretat():
    global puntuacio
    global spf_pass
    global spf_arc_pass
    table = "<h3>Resultats dels protocols d'autenticació</h3>"
    table += "<table id=\"MesuresSeguretat\">\n"

    # Creem la taula amb les capçaleres corresponents
    header = ['Paràmetre', 'Resultat', 'Prioritat', 'Informació']
    table += "  <tr>\n"
    for column in header:
        table += "    <th>{0}</th>\n".format(column.strip())
    table += "  </tr>\n"

    # NOVA FILA
    table += "  <tr>\n"
    # NOU CAMP (COLUMNA) a la FILA
    table += "    <td>{0}".format("SPF")
    table += """
<div class="col-md-12">
    <div class="info">
      <i class="icon-info-sign"></i>
      <span class="extra-info">
      </span>
    </div>
    Vincula un domini/IP a una direcció de correu. S'engarrega de revisar que el remitent és qui diu ser mitjançant la IP/domini origen.
</div></td>"""

    if spf_pass:
        if spf_pass == True:
            table += "    <td>{0}</td>\n".format("Correcte")
            table += "    <td>{0}</td>\n".format("Alta")
            table += "    <td>{0}</td>\n".format(
                "No hi ha hagut suplantació d'identitat!")
            #puntuacio  = puntuacio
        else:
            table += "    <td>{0}</td>\n".format("Fallit")
            table += "    <td>{0}</td>\n".format("Alta")
            table += "    <td>{0}</td>\n".format(
                "Es pot tractar d'una suplantació d'identitat!")
            puntuacio -= 10
    else:
        table += "    <td>{0}</td>\n".format("Inexistent")
        table += "    <td>{0}</td>\n".format("Mitjana")
        table += "    <td>{0}</td>\n".format("No es disposa del registre SPF")
        puntuacio -= 5

    # TANCO FILA
    table += "  </tr>\n"

    # NOVA FILA
    table += "  <tr>\n"
    # NOU CAMP (COLUMNA) a la FILA
    table += "    <td>{0}".format("ARC-SPF")
    table += """
<div class="col-md-12">
    <div class="info">
      <i class="icon-info-sign"></i>
      <span class="extra-info">
      </span>
    </div>
    Són els resultats del SPF que guarda la "cadena de custodia" del correu per tal d'evitar que es manipuli el missatge.
</div></td>"""
    if spf_arc_pass:
        if spf_arc_pass == True:
            table += "    <td>{0}</td>\n".format("Correcte")
            table += "    <td>{0}</td>\n".format("Mitjana")
            table += "    <td>{0}</td>\n".format(
                "No hi ha hagut suplantació d'identitat!")
            puntuacio = puntuacio
        else:
            table += "    <td>{0}</td>\n".format("Fallit")
            table += "    <td>{0}</td>\n".format("Alta")
            table += "    <td>{0}</td>\n".format(
                "Es pot tractar d'una suplantació d'identitat!")
            if spf_pass == True:
                puntuacio -= 10  # Algu ha modificat el spf original i realment és fallit
    else:
        table += "    <td>{0}</td>\n".format("Inexistent")
        table += "    <td>{0}</td>\n".format("Baixa")
        table += "    <td>{0}</td>\n".format(
            "No es disposa del registre SPF dins del ARC Protocol")
        puntuacio = puntuacio

    # TANCO FILA
    table += "  </tr>\n"

    # NOVA FILA
    table += "  <tr>\n"
    # NOU CAMP (COLUMNA) a la FILA
    table += "    <td>{0}".format("DKIM")
    table += """
<div class="col-md-12">
    <div class="info">
      <i class="icon-info-sign"></i>
      <span class="extra-info">
      </span>
    </div>
    Vincula un nom de domini a un missatge. Permet revisar si el missatge està firmat pel domini origen.
</div></td>"""
    if dkim_pass:
        if dkim_pass == True:
            table += "    <td>{0}</td>\n".format("Correcte")
            table += "    <td>{0}</td>\n".format("Alta")
            table += "    <td>{0}</td>\n".format(
                "El correu porta una firma digital signada pel remitent!")
            puntuacio = puntuacio
        else:
            table += "    <td>{0}</td>\n".format("Fallit")
            table += "    <td>{0}</td>\n".format("Alta")
            table += "    <td>{0}</td>\n".format(
                "Es pot tractar d'spoofing del missatge, la firma digital no coincideix!")
            puntuacio -= 5
    else:
        table += "    <td>{0}</td>\n".format("Inexistent")
        table += "    <td>{0}</td>\n".format("Mitjana")
        table += "    <td>{0}</td>\n".format(
            "El remitent no ha firmat digitalment el missatge!")
        puntuacio -= 3

    # TANCO FILA
    table += "  </tr>\n"

    # NOVA FILA
    table += "  <tr>\n"
    # NOU CAMP (COLUMNA) a la FILA
    table += "    <td>{0}".format("ARC-DKIM")
    table += """
<div class="col-md-12">
    <div class="info">
      <i class="icon-info-sign"></i>
      <span class="extra-info">
      </span>
    </div>
    Són els resultats del DKIM que guarda la "cadena de custodia" del correu per tal d'evitar que es manipuli el missatge.
</div>
</td>"""
    if dkim_arc_pass:
        if dkim_arc_pass == True:
            table += "    <td>{0}</td>\n".format("Correcte")
            table += "    <td>{0}</td>\n".format("Mitjana")
            table += "    <td>{0}</td>\n".format(
                "El correu porta una firma digital signada pel remitent!")
            puntuacio = puntuacio
        else:
            table += "    <td>{0}</td>\n".format("Fallit")
            table += "    <td>{0}</td>\n".format("Alta")
            table += "    <td>{0}</td>\n".format(
                "Es pot tractar d'spoofing del missatge, la firma digital no coincideix!")
            if dkim_pass == True:
                puntuacio -= 5
    else:
        table += "    <td>{0}</td>\n".format("Inexistent")
        table += "    <td>{0}</td>\n".format("Baixa")
        table += "    <td>{0}</td>\n".format(
            "El remitent no ha firmat digitalment el missatge!")
        puntuacio = puntuacio

    # TANCO FILA
    table += "  </tr>\n"

    # NOVA FILA
    table += "  <tr>\n"
    # NOU CAMP (COLUMNA) a la FILA
    table += "    <td>{0}".format("DMARC")
    table += """
<div class="col-md-12">
    <div class="info">
      <i class="icon-info-sign"></i>
      <span class="extra-info">
      </span>
    </div>
    Permet als clients que reben el correu que fer amb el correu segons els resultats del SPF i DKIM.
</div></td>"""
    if dmarc_pass:
        if dmarc_pass == True:
            table += "    <td>{0}</td>\n".format("Correcte")
            table += "    <td>{0}</td>\n".format("Alta")
            table += "    <td>{0}</td>\n".format(
                "El DMARC ha donat com a vàlid el correu segons els resultats del SPF i DKIM!")
            puntuacio = puntuacio
        else:
            table += "    <td>{0}</td>\n".format("Fallit")
            table += "    <td>{0}</td>\n".format("Alta")
            table += "    <td>{0}</td>\n".format(
                "El DMARC ha donat com a invàlid el correu segons els resultats del SPF i DKIM!")
            puntuacio -= 5
    else:
        table += "    <td>{0}</td>\n".format("Inexistent")
        table += "    <td>{0}</td>\n".format("Mitjana")
        table += "    <td>{0}</td>\n".format(
            "El servidor de correu no ha aplicat cap política segons les dades rebudes!")
        puntuacio = puntuacio

    # TANCO FILA
    table += "  </tr>\n"

    # NOVA FILA
    table += "  <tr>\n"
    # NOU CAMP (COLUMNA) a la FILA
    table += "    <td>{0}".format("ARC-DMARC")
    table += """
<div class="col-md-12">
    <div class="info">
      <i class="icon-info-sign"></i>
      <span class="extra-info">
      </span>
    </div>
    Són els resultats del DMARC que guarda la "cadena de custodia" del correu per tal d'evitar que es manipuli el missatge.
</div></td>"""
    if dmarc_arc_pass:
        if dmarc_arc_pass == True:
            table += "    <td>{0}</td>\n".format("Correcte")
            table += "    <td>{0}</td>\n".format("Mitjana")
            table += "    <td>{0}</td>\n".format(
                "El DMARC ha donat com a vàlid el correu segons els resultats del SPF i DKIM!")
            puntuacio = puntuacio
        else:
            table += "    <td>{0}</td>\n".format("Fallit")
            table += "    <td>{0}</td>\n".format("Alta")
            table += "    <td>{0}</td>\n".format(
                "El DMARC ha donat com a invàlid el correu segons els resultats del SPF i DKIM!")
            if dmarc_pass == True:
                puntuacio -= 5
    else:
        table += "    <td>{0}</td>\n".format("Inexistent")
        table += "    <td>{0}</td>\n".format("Baixa")
        table += "    <td>{0}</td>\n".format(
            "El servidor de correu no ha aplicat cap política segons les dades rebudes!")
        puntuacio = puntuacio

    # TANCO FILA
    table += "  </tr>\n"

    # TANCO TAULA
    table += "</table></br>"
    return table


def dadesMissatge():
    global puntuacio
    global ip_remitent
    global domain_public_provider
    global same_company
    table = "<h3>Resultats de les capçaleres del missatge:</h3>"
    table += "<table id=\"MesuresSeguretat\">\n"

    # Creem la taula amb les capçaleres corresponents
    header = ['Dada', 'Contingut', 'Anàlisi', 'Informació']
    table += "  <tr>\n"
    for column in header:
        table += "    <th>{0}</th>\n".format(column.strip())
    table += "  </tr>\n"

    # NOVA FILA
    table += "  <tr>\n"
    # NOU CAMP (COLUMNA) a la FILA
    table += "    <td>{0}</td>\n".format("Remitent")
    table += "    <td>{0}</td>\n".format(remitent_correu)
    try:
        if recent_creation_date:
            table += "    <td>{0}</td>\n".format("Perillós")
            table += "    <td>{0}</td>\n".format(
                "El domini s'ha creat recentment, es pot tractar d'un atac de phishing selectiu!")
            puntuacio -= 10
        else:
            if not domain_public_provider and same_company:
                table += "    <td>{0}</td>\n".format("Aprovat")
                table += "    <td>{0}</td>\n".format(
                    "El domini no s'ha creat recentment i prové de la mateixa organització!")
            else:
                table += "    <td>{0}</td>\n".format("Aprovat")
                table += "    <td>{0}</td>\n".format(
                    "El domini no s'ha creat recentment!")

    except:
        if domain_public_provider:
            table += "    <td>{0}</td>\n".format("Neutral")
            table += "    <td>{0}</td>\n".format(
                "El domini no te una data de registre pública\r\nPrové d'un proveidor públic de correu.")
            puntuacio -= 5
        else:
            if same_company:
                table += "    <td>{0}</td>\n".format("Positiu")
                table += "    <td>{0}</td>\n".format(
                    "El domini no te una data de registre pública\r\nPrové de la mateixa organització.")
            else:
                table += "    <td>{0}</td>\n".format("Neutral")
                table += "    <td>{0}</td>\n".format(
                    "El domini no te una data de registre pública!")
                puntuacio -= 5

    # TANCO FILA
    table += "  </tr>\n"

    # NOVA FILA
    table += "  <tr>\n"
    # NOU CAMP (COLUMNA) a la FILA
    table += "    <td>{0}</td>\n".format("Domini provinent")
    table += "    <td>{0}</td>\n".format(from_domain)

    if from_domini_malicios:
        table += "    <td>{0}</td>\n".format("Perillós")
        table += "    <td>{0}</td>\n".format(info_from_domain)
        puntuacio -= 20
    else:
        table += "    <td>{0}</td>\n".format("Aprovat")
        table += "    <td>{0}</td>\n".format(
            "El domini no està en cap llista negra!")

    # TANCO FILA
    table += "  </tr>\n"

    # NOVA FILA
    table += "  <tr>\n"
    # NOU CAMP (COLUMNA) a la FILA
    table += "    <td>{0}</td>\n".format("Data")
    table += "    <td>{0}</td>\n".format(data_correu)
    table += "    <td>{0}</td>\n".format("Personal")
    table += "    <td>{0}</td>\n".format(
        "Segons la zona horària, analitzar si es comprèn dins de l'hora de treball")

    # TANCO FILA
    table += "  </tr>\n"

    if ip_remitent != "-":
        # NOVA FILA
        table += "  <tr>\n"
        # NOU CAMP (COLUMNA) a la FILA
        table += "    <td>{0}</td>\n".format("IP-Remitent")
        table += "    <td>{0}</td>\n".format(ip_remitent)
        if analizeIP(ip_remitent):
            table += "    <td>{0}</td>\n".format("Maliciosa")
            table += "    <td>{0}</td>\n".format(
                "La IP del client des del qual s'ha enviat el correu és maliciosa!")
        else:
            table += "    <td>{0}</td>\n".format("Bona")
            table += "    <td>{0}</td>\n".format(
                "La IP del client des del qual s'ha enviat el correu no té mala reputació!")
        # TANCO FILA
        table += "  </tr>\n"

    else:
        # NOVA FILA
        table += "  <tr>\n"
        # NOU CAMP (COLUMNA) a la FILA
        table += "    <td>{0}</td>\n".format("IP-Remitent")
        table += "    <td>{0}</td>\n".format("Desconeguda")
        table += "    <td>{0}</td>\n".format("-")
        table += "    <td>{0}</td>\n".format("-")

        # TANCO FILA
        table += "  </tr>\n"

    # NOVA FILA
    table += "  <tr>\n"
    # NOU CAMP (COLUMNA) a la FILA
    table += "    <td>{0}</td>\n".format("Reply-To")
    table += "    <td>{0}</td>\n".format(reply_to)
    if reply_to_domini_malicios:
        table += "    <td>{0}</td>\n".format("Perillós")
        table += "    <td>{0}</td>\n".format(info_reply_to_domain)
        if from_domini_malicios:
            puntuacio -= 10
        else:
            puntuacio -= 20
    else:
        if (reply_to and (re.match(domain_pattern, reply_to))):
            table += "    <td>{0}</td>\n".format("Aprovat")
            table += "    <td>{0}</td>\n".format(
                "El domini no està en cap llista negra!")
        else:
            table += "    <td>{0}</td>\n".format("-")
            table += "    <td>{0}</td>\n".format("-")

    # TANCO FILA
    table += "  </tr>\n"

    # NOVA FILA
    table += "  <tr>\n"
    # NOU CAMP (COLUMNA) a la FILA
    table += "    <td>{0}</td>\n".format("Return-Path")
    table += "    <td>{0}</td>\n".format(return_path)
    if return_path_domini_malicios:
        table += "    <td>{0}</td>\n".format("Perillós")
        table += "    <td>{0}</td>\n".format(info_return_path_domain)
        if from_domini_malicios:
            puntuacio -= 10
        else:
            puntuacio -= 20
    else:
        if (reply_to and (re.match(domain_pattern, return_path))):
            table += "    <td>{0}</td>\n".format("Aprovat")
            table += "    <td>{0}</td>\n".format(
                "El domini no està en cap llista negra!")
        else:
            table += "    <td>{0}</td>\n".format("-")
            table += "    <td>{0}</td>\n".format("-")

    # TANCO FILA
    table += "  </tr>\n"

    # TANCO TAULA
    table += "</table></br>"
    return table


def generateTablefitxersAdjunts():
    global puntuacio
    table = "<br><h3>Informació dels fitxers adjunts:</h3>"
    table += "<table id=\"MesuresSeguretat\">\n"

    # Create the table's column headers
    header = ['Nom del fitxer', 'Hash', 'Anàlisi', 'Porta Macros',
              'Porta execució de codi', 'Autoopen Macro', 'PDF sospitós']
    table += "  <tr>\n"
    for column in header:
        table += "    <th>{0}</th>\n".format(column.strip())
    table += "  </tr>\n"

    for i in range(len(noms_fitxers_adjunts)):
        # NOVA FILA
        table += "  <tr>\n"
        # NOU CAMP (COLUMNA) a la FILA
        table += "    <td>{0}</td>\n".format(noms_fitxers_adjunts[i])
        table += "    <td>{0}</td>\n".format(hash_fitxers_adjunts[i])
        if infectats_fitxers_adjunts[i] == True:
            table += "    <td>{0}</td>\n".format("Infectat!")
            puntuacio -= 30
        else:
            table += "    <td>{0}</td>\n".format("Net!")
        if yara_macro_adjunts[i]:
            table += "    <td>{0}</td>\n".format(
                "Porta macros en el fitxer adjunt!")
            puntuacio -= 10
        else:
            table += "    <td>{0}</td>\n".format("No porta macros.")
        if yara_autoopen_adjunts[i]:
            table += "    <td>{0}</td>\n".format(
                "Porta codi que s'autoexecuta")
            puntuacio -= 10
        else:
            table += "    <td>{0}</td>\n".format(
                "no porta codi que s'autoexecuta")
        if yara_execution_adjunts[i]:
            table += "    <td>{0}</td>\n".format(
                "Conté peces de codi executable!")
            puntuacio -= 10
        else:
            table += "    <td>{0}</td>\n".format(
                "No conté peces de codi executable")
        if yara_execution_adjunts[i]:
            table += "    <td>{0}</td>\n".format(
                "És un document pdf suspitós a portar malware")
            puntuacio -= 10
        else:
            table += "    <td>{0}</td>\n".format("No")

        # TANCO FILA
        table += "  </tr>\n"

    # TANCO TAULA
    table += "</table></br>"
    return table


def insertInteligencia():
    # Resultats Yaras Phishing
    global puntuacio
    global intel_phishing_result
    global intel_phishing2_result
    global scl_yara_result
    global bcl_yara_result
    generaInteligencia()
    table = "<h3>Resultats segons el criteri de l'algoritme d'intel·ligència:"
    table += "<table id=\"MesuresSeguretat\">\n"

    # Create the table's column headers
    header = ['Inteligència', 'Estat', 'Informació']
    table += "  <tr>\n"
    for column in header:
        table += "    <th>{0}</th>\n".format(column.strip())
    table += "  </tr>\n"

    # NOVA FILA
    table += "  <tr>\n"
    # NOU CAMP (COLUMNA) a la FILA
    table += "    <td>{0}</td>\n".format("Correu de phishing selectiu?")
    if intel_phishing_result:
        table += "    <td>{0}</td>\n".format("Potencialment sí!")
        table += "    <td>{0}</td>\n".format(
            "Té el perfil d'un correu de phishing selectiu")
        puntuacio -= 10
    else:
        table += "    <td>{0}</td>\n".format("No")
        table += "    <td>{0}</td>\n".format(
            "No sembla un correu de phishing selectiu")

    # TANCO FILA
    table += "  </tr>\n"

    # NOVA FILA
    table += "  <tr>\n"
    # NOU CAMP (COLUMNA) a la FILA
    table += "    <td>{0}</td>\n".format("Correu típic de phishing?")
    if intel_phishing2_result:
        table += "    <td>{0}</td>\n".format("Potencialment sí!")
        table += "    <td>{0}</td>\n".format(
            "Té el perfil d'un correu típic de phishing!")
        puntuacio -= 15
    else:
        table += "    <td>{0}</td>\n".format("No")
        table += "    <td>{0}</td>\n".format(
            "No sembla un correu típic de phishing")
    # TANCO FILA
    table += "  </tr>\n"

    # NOVA FILA
    table += "  <tr>\n"
    # NOU CAMP (COLUMNA) a la FILA
    table += "    <td>{0}</td>\n".format("Correu no desitjat?")
    if scl_yara_result:
        table += "    <td>{0}</td>\n".format("Sí!")
        table += "    <td>{0}</td>\n".format(
            "El missatge genera poca confiança, el maquem com a no desitjat.")
        puntuacio -= 7
    else:
        table += "    <td>{0}</td>\n".format("No")
        table += "    <td>{0}</td>\n".format(
            "S'ha determinat que el missatge no era correu no desitjat.")
    # TANCO FILA
    table += "  </tr>\n"

    # NOVA FILA
    table += "  <tr>\n"
    # NOU CAMP (COLUMNA) a la FILA
    table += "    <td>{0}</td>\n".format("Genera queixes?")
    if bcl_yara_result:
        table += "    <td>{0}</td>\n".format("Sí!")
        table += "    <td>{0}</td>\n".format(
            "El missatge prové d'un remitent de correu massiu que genera un número queixes.")
        puntuacio -= 5
    else:
        table += "    <td>{0}</td>\n".format("No")
        table += "    <td>{0}</td>\n".format(
            "El missatge prové d'un remitent de correo massiu que no genera queixes massives.")
    # TANCO FILA
    table += "  </tr>\n"

    # TANCO TAULA
    table += "</table></br>"
    return table


def insertMap():
    text = """<img src="{0}" alt="Mapa mundi traçat" class="center">""".format(
        image_path_html)
    return text


def puntuacioFinal():
    global puntuacio
    output = sys.argv[1].split('/', 2)[2]
    print("Output: ", output)
    os.system("touch ../htdocs/" + output + ".html")
    os.system("/bin/chmod 777 ../htdocs/" + output + ".html")
    f = open("../htdocs/" + output + ".html", 'w')

    contingut_HTML = """<html>
    <head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>
    <style>
    
#MesuresSeguretat {
font-family: Arial, Helvetica, sans-serif;
border-collapse: collapse;
width: 100%;
}

#MesuresSeguretat td, #MesuresSeguretat th {
  border: 1px solid #ddd;
  padding: 8px;
}

#MesuresSeguretat tr:nth-child(even){background-color: #f2f2f2;}

#MesuresSeguretat tr:hover {background-color: #ddd;}

#MesuresSeguretat th {
  padding-top: 12px;
  padding-bottom: 12px;
  text-align: left;
  background-color: #4CAF50;
  color: white;
}
#dadesMissatge table, #dadesMissatge th, #dadesMissatge td {
  border: 1px solid black;
}
.center {
  display: block;
  margin-left: auto;
  margin-right: auto;
  width: 70%;
}
    
* {
  box-sizing: border-box;
}

body {
  font-family: Helvetica, sans-serif;
}

/* The actual timeline (the vertical ruler) */
.timeline {
  background-color: #474e5d;
  position: relative;
  max-width: 1200px;
  margin: 0 auto;
}

/* The actual timeline (the vertical ruler) */
.timeline::after {
  content: '';
  position: absolute;
  width: 6px;
  background-color: white;
  top: 0;
  bottom: 0;
  left: 50%;
  margin-left: -3px;
}

/* Container around content */
.container {
  padding: 10px 40px;
  position: relative;
  background-color: inherit;
  width: 50%;
}

/* The circles on the timeline */
.container::after {
  content: '';
  position: absolute;
  width: 25px;
  height: 25px;
  right: -17px;
  background-color: white;
  border: 4px solid #FF9F55;
  top: 15px;
  border-radius: 50%;
  z-index: 1;
}

/* Place the container to the left */
.left {
  left: 0;
}

/* Place the container to the right */
.right {
  left: 50%;
}

/* Add arrows to the left container (pointing right) */
.left::before {
  content: " ";
  height: 0;
  position: absolute;
  top: 22px;
  width: 0;
  z-index: 1;
  right: 30px;
  border: medium solid white;
  border-width: 10px 0 10px 10px;
  border-color: transparent transparent transparent white;
}

/* Add arrows to the right container (pointing left) */
.right::before {
  content: " ";
  height: 0;
  position: absolute;
  top: 22px;
  width: 0;
  z-index: 1;
  left: 30px;
  border: medium solid white;
  border-width: 10px 10px 10px 0;
  border-color: transparent white transparent transparent;
}

/* Fix the circle for containers on the right side */
.right::after {
  left: -16px;
}

/* The actual content */
.content {
  padding: 20px 30px;
  background-color: white;
  position: relative;
  border-radius: 6px;
}

/* Media queries - Responsive timeline on screens less than 600px wide */
@media screen and (max-width: 600px) {
  /* Place the timelime to the left */
  .timeline::after {
  left: 31px;
  }
  
  /* Full-width containers */
  .container {
  width: 100%;
  padding-left: 70px;
  padding-right: 25px;
  }
  
  /* Make sure that all arrows are pointing leftwards */
  .container::before {
  left: 60px;
  border: medium solid white;
  border-width: 10px 10px 10px 0;
  border-color: transparent white transparent transparent;
  }

  /* Make sure all circles are at the same spot */
  .left::after, .right::after {
  left: 15px;
  }
  
  /* Make all right containers behave like the left ones */
  .right {
  left: 0%;
  }
}



/* Make sure that padding behaves as expected */
* {box-sizing:border-box}

/* Container for skill bars */
.container2 {
  width: 100%; /* Full width */
  background-color: #ddd; /* Grey background */
}

.skills {
  text-align: right; /* Right-align text */
  padding-top: 10px; /* Add top padding */
  padding-bottom: 10px; /* Add bottom padding */
  color: white; /* White text color */
}

* {
  transition: all .2s ease;
}

.extra-info {
  display: none;
  line-height: 30px;
  font-size: 12px;
	position: absolute;
  top: 0;
  left: 50px;
}

.info:hover .extra-info {
  display: block;
}

.info {
  font-size: 20px;
  padding-left: 5px;
  width: 20px;
  border-radius: 15px;
}

.info:hover {
  background-color: white;
  padding: 0 0 0 5px;
  width: 315px;
  text-align: left !important;
}

"""
    contingut_HTML = contingut_HTML + \
        ".html {width: " + str(puntuacio) + "%; background-color: #04AA6D;}"
    contingut_HTML = contingut_HTML + \
        ".css {width: " + str(puntuacio) + "%; background-color: #2196F3;}"
    contingut_HTML = contingut_HTML + \
        ".js {width: " + str(puntuacio) + "%; background-color: #f44336;}"
    contingut_HTML = contingut_HTML + \
        ".php {width: " + str(puntuacio) + "%; background-color: #808080;}"

    contingut_HTML = contingut_HTML + """
    </style>

<meta name="viewport" content="width=device-width, initial-scale=1">
<link href="https://netdna.bootstrapcdn.com/font-awesome/3.2.1/css/font-awesome.css" rel="stylesheet">
<link rel="stylesheet" href="https://www.w3schools.com/w3css/4/w3.css">
    <title>Resultats del correu: """
    contingut_HTML = contingut_HTML + output + """</title></head>
    <body>
     <h1>Informe del correu introduït: """ + output + """</h1></br>"""

    contingut_HTML = contingut_HTML + generateTableMesuresSeguretat()

    contingut_HTML = contingut_HTML + dadesMissatge()

    contingut_HTML = contingut_HTML + generateTablefitxersAdjunts()

    contingut_HTML = contingut_HTML + generateTableURLs()

    contingut_HTML = contingut_HTML + print_route2()

    contingut_HTML = contingut_HTML + insertMap()

    contingut_HTML = contingut_HTML + insertInteligencia()

    contingut_HTML = contingut_HTML + generateProgressBar()

    contingut_HTML = contingut_HTML + \
        """<footer><a href="../uploadEmail.html">Tornar a la pàgina de pujades</a></footer>"""

    contingut_HTML = contingut_HTML + """</body>
</html>"""
    f.write(contingut_HTML)
    f.close()


noms_fitxers_adjunts = []
infectats_fitxers_adjunts = []
hash_fitxers_adjunts = []
yara_macro_adjunts = []
yara_autoopen_adjunts = []
yara_execution_adjunts = []
yara_pdf_adjunts = []


def generaInteligencia():
    global intel_phishing_result
    global intel_phishing2_result
    global scl_yara_result
    global bcl_yara_result
    command = cmdline("/usr/local/bin/yara " + intel_phishing +
                      " " + sys.argv[1] + " 2> /dev/null")
    if command:
        print("Match amb: " + intel_phishing)
        intel_phishing_result = True
    else:
        print("No ha fet match amb " + intel_phishing)
        intel_phishing_result = False
    command = cmdline("/usr/local/bin/yara " + intel_phishing +
                      " " + sys.argv[1] + " 2> /dev/null")
    if command:
        print("Match amb: " + intel_phishing2)
        intel_phishing2_result = True
    else:
        print("No ha fet match amb " + intel_phishing2)
        intel_phishing2_result = False
    command = cmdline("/usr/local/bin/yara " + scl_yara +
                      " " + sys.argv[1] + " 2> /dev/null")
    if command:
        print("Match amb: " + scl_yara)
        scl_yara_result = True
    else:
        print("No ha fet match amb " + scl_yara)
        scl_yara_result = False
    command = cmdline("/usr/local/bin/yara " + bcl_yara +
                      " " + sys.argv[1] + " 2> /dev/null")
    if command:
        print("Match amb: " + bcl_yara)
        bcl_yara_result = True
    else:
        print("No ha fet match amb " + bcl_yara)
        bcl_yara_result = False


def cmdline(command):
    process = Popen(
        args=command,
        stdout=PIPE,
        shell=True
    )
    return process.communicate()[0].decode("utf-8")


def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


# Per cada attachment, el llegim i el volquem
mail = email.message_from_string(msg.as_string())
for part in mail.walk():
    if part.get_content_maintype() == 'multipart':
        # print(part.as_string())
        continue
    if part.get('Content-Disposition') is None:
        # print(part.as_string())
        continue
    fileName = part.get_filename()

    if bool(fileName):
        filePath = os.path.join(fileName)
        # Afegir davant la carpeta dels fitxers adjunts
        # Eliminar els fitxers adjunts despres d'un anàlisi
        # if not os.path.isfile(filePath):
        noms_fitxers_adjunts.append(fileName)
        print("Nom del fitxer adjunt: " + fileName)
        fp = open(filePath, 'wb')

        fp.write(part.get_payload(decode=True))
        fp.close()
        command = cmdline("sudo /bin/chmod 777 " + filePath)
        print("Comanda: sudo /bin/chmod 777 " + filePath)
        print("COMAND: ", command)
        #os.system("chmod 777 " + filePath)
        print("MD5: " + md5(fileName))
        md5_hash = md5(fileName)
        hash_fitxers_adjunts.append(md5_hash)
        command = cmdline("/usr/local/bin/yara " +
                          office_macro_yara + " " + fileName + " 2> /dev/null")
        if command:
            print("Ha fet match")
            yara_macro_adjunts.append(True)
        else:
            print("No ha fet match")
            yara_macro_adjunts.append(False)
        # office_autoopen_yara
        command = cmdline("/usr/local/bin/yara " +
                          office_autoopen_yara + " " + fileName + " 2> /dev/null")
        if command:
            print("Ha fet match")
            yara_autoopen_adjunts.append(True)
        else:
            print("No ha fet match")
            yara_autoopen_adjunts.append(False)
        # office_code_execution_yara
        command = cmdline("/usr/local/bin/yara " +
                          office_code_execution_yara + " " + fileName + " 2> /dev/null")
        if command:
            print("Ha fet match")
            yara_execution_adjunts.append(True)
        else:
            print("No ha fet match")
            yara_execution_adjunts.append(False)
        # malicious_pdf_yara
        command = cmdline("/usr/local/bin/yara " +
                          malicious_pdf_yara + " " + fileName + " 2> /dev/null")
        if command:
            print("Ha fet match")
            yara_pdf_adjunts.append(True)
        else:
            print("No ha fet match")
            yara_pdf_adjunts.append(False)
        # Analitzem amb virustotal el hash del arxiu total
        try:
            #vt = VirusTotalPublicApi(API_KEY)
            response = vt.get_file_report(md5_hash)
            #print("Response: " + response)
            print("Positius: ", response['results']['positives'])
            if (response['results']['positives'] > 0):
                print("Arxiu " + fileName + " adjunt infectat! +50!!!")
                infectats_fitxers_adjunts.append(True)
            else:
                print("Arxiu " + fileName + " segur!")
                infectats_fitxers_adjunts.append(False)
            #json_result = json.dumps(response, sort_keys=False, indent=4)
            #print(json.dumps(response, sort_keys=False, indent=4))
        except:
            print("No sha pogut contactar amb virustotal")
            infectats_fitxers_adjunts.append(False)


# Printar per consola els headers seguents:
print('To:', msg['to'])
remitent_correu = msg['from']
print('From:', msg['from'])
print('Subject:', msg['subject'])
data_correu = msg['date']
print('Date:', msg['date'])
print('Reply-To:', msg['Reply-to'])
print('Priority:', msg['X-Priority'])
print('MSMail-Priority:', msg['X-MSMail-Priority'])
print('Mailer:', msg['X-Mailer'])
print('MimeOLE:', msg['X-MimeOLE'])
print('Originating IP (Ip del PC del remitent):', msg['x-originating-ip'])
print('User Agent:', msg['User-Agent'])
print('Message-ID:', msg['Message-ID'])
print('Body: ', msg['body'])
print('Received-SPF: ', msg['Received-SPF'])
print('Authentication-Results: ', msg['Authentication-Results'])
print('ARC-Authentication-Results: ', msg['ARC-Authentication-Results'])

ip_remitent = ""
if (msg['x-originating-ip']):
    # and msg['x-originating-ip'] == '[' and msg['x-originating-ip'][len(msg['x-originating-ip'])-1] == ']'
    ip_remitent = str(msg['x-originating-ip'][1:-1])
    print("New IP Remitent: " + ip_remitent)
result = re.match(ip_pattern, ip_remitent)
if not result:
    ip_remitent = "-"
    print("New IP Remitent: " + ip_remitent)


# Check SPF
if msg['Received-SPF']:
    # Hi ha registre SPF
    print("SPF validat")
    spf = str(msg['Received-SPF']).split()
    print(spf)
    if (spf[0] and spf[0] == "pass"):
        spf_pass = True
        print("SPF pass")
        print("No hi ha hagut suplantació d'identitat!")
        spf_result = str(msg['Received-SPF']).split("(")[1] + \
            str(msg['Received-SPF']).split(")")[0]
        print("Resultat SPF: ")
        print(spf_result)
    else:
        spf_pass = False
        print("SPF failed!")
        print("El correu pot haver patit un atac de suplantació d'identitat!")
else:
    # No hi ha registre SPF
    print("No conte el veredicte de si ha passat el control SPF o no")


if msg['Authentication-Results']:
    authentication_results = msg['Authentication-Results'].splitlines()
    for result in authentication_results:
        line = re.findall(r'dkim=[a-z]+', result)
        if line:
            #print("Result: ", line)
            #print ("DKIM: " + line[0])
            # print(line[0].split('=')[1])
            if (line[0].split('=')[1] == "pass"):
                print("DKIM PASS")
                dkim_pass = True
                break
            else:
                print("DKIM DENIED")
                dkim_pass = False
                break

# Dmarc
if msg['Authentication-Results']:
    authentication_results = msg['Authentication-Results'].splitlines()
    for result in authentication_results:
        line = re.findall(r'dmarc=[a-z]+', result)
        if line:
            if (line[0].split('=')[1] == "pass"):
                print("DMARC PASS")
                dmarc_pass = True
                break
            else:
                print("DMARC DENIED")
                dmarc_pass = False
                break


if msg['ARC-Authentication-Results']:
    arc_authentication_results = msg['ARC-Authentication-Results'].splitlines()
    for result in authentication_results:
        line = re.findall(r'arc=[a-z]+', result)
        if line:
            # ARC exists
            if (line[0].split('=')[1] == "pass"):
                print("ARC PASS")
                arc_pass = True
                spf_check = re.findall(r'spf=pass', result)
                # print(spf_check)
                if spf_check:
                    spf_arc_pass = True
                    print("SPF ARC PASSED!")
                dkim_check = re.findall(r'dkim=pass', result)
                # print(dkim_check)
                if dkim_check:
                    dkim_arc_pass = True
                    print("DKIM ARC PASSED!")
                dmarc_check = re.findall(r'dmarc=pass', result)
                # print(dmarc_check)
                if dmarc_check:
                    dmarc_arc_pass = True
                    print("DMARC ARC PASSED!")
                break
            else:
                print("ARC DENIED")
                arc_pass = False
                break


# Deixem una linea de separació
print()


# Ara llegim el correu d'una altra manera per poder-lo parsejar millor
with open(sys.argv[1], 'rb') as fp:
    msg2 = email.parser.BytesParser(policy=email.policy.default).parse(fp)

# Printar el cos del email
print("Cos del correu, el missatge:")
body = msg2.get_body(preferencelist=('plain', 'html'))
print(''.join(body.get_content().splitlines(keepends=True)))


# Retorna el contingut que hi ha entre parentesis o corchetes
def extract_meta(line):
    ip = re.search("\[(.*?)\]", line)
    if ip:
        return ip.group(0)
    else:
        a = re.search("\((.*?)\)", line)
        if a:
            return a.group(0)
        else:
            return ""


# Get all the fields present in an email's headers
#  @param filename the filename of an email (with header) saved as plaintext
#  @returns a list of all fields found
#
# Retorna un array amb els camps de les capçaleres del correu
def get_fields():
    fields = []
    # First find all the fields present in the email headers
    with open(sys.argv[1], "rb") as fp:
        headers = email.parser.BytesParser(
            policy=email.policy.default).parse(fp)

    # Add each field to a list
    for j in headers:
        fields.append(j + ":")

    print("Fields: ", fields)
    return fields

# Guardem totes les linees (headers) de Received:


def get_received():
    rt = []
    rec = []
    tmp = ""
    found = False

    fields = get_fields()

    # Parse the file looking for Received fields
    with open(sys.argv[1], "r") as fp:
        for line in fp:
            sep = line.split()
            # Found the end of the field , add to rt list
            if len(sep) != 0 and sep[0] in fields and found:
                rt.append(tmp)
                tmp = ""
                if sep[0] != "Received:":
                    found = False
                else:
                    # The next field is another Received
                    tmp += line
            elif found:
                # keep adding lines until we hit another field
                tmp += line
            elif "Received:" in line.split():
                # Found a received field, start adding lines
                tmp += line
                found = True

    # Format each received field into a single line and add to rec list
    for j in rt:
        rec.append(" ".join(j.split()))

    return rec


# Defin im les variables ips i names dels servidors smtp (MTAs) com a variables públiques
names = []
ips = []


# Printem la ruta (els salts que fa):
def print_route():
    text = """<div class="timeline">"""
    j = 1
    rec = get_received()

    for k in rec:
        sep = k.split()
        if sep[1] == "by":
            names.append("Null")
            ips.append("None")
            names.append(sep[2])
            ips.append("")
        else:
            f = sep.index("from")
            b = sep.index("by")
            half = k.split("by")
            quart = half[1].split("for")

            names.append(sep[f+1])
            ips.append(extract_meta(half[0]))
            names.append(sep[b+1])
            ips.append(extract_meta(quart[0]))

    print("\nHop #: From --> By")

    for k in range(len(names) - 1, -1, -2):
        print("Hop {0}: {1} {2} --> {3} {4}" .format(j, names[k - 1],
                                                     ips[k - 1], names[k],
                                                     ips[k]))

        if j % 2 == 0:
            text += """ <div class="container right\">\n"""
            text += """  <div class="content">
   <h2>Hop {0}</h2>
    <p>{1} {2} --> {3} {4}</p>
   </div>""".format(j, names[k - 1], ips[k - 1], names[k], ips[k])
        else:
            text += """ <div class="container left\">\n"""
            text += """  <div class="content">\n
   <h2>Hop {0}</h2>\n
    <p>{1} {2} --> {3} {4}</p>\n
   </div>\n""".format(j, names[k - 1], ips[k - 1], names[k], ips[k])

        j += 1

    text += """  </div>
 </div>"""
    return text


print("La ruta del correu, els servidors (MTAs) pels quals passa:")
print_route()


def print_route2():

    text = """<br><h3>Ruta que ha realitzat el correu:</h3>"""
    text += """<div class="timeline">"""
    j = 1
    '''
    rec = get_received()

    for k in rec:
        sep = k.split()
        if sep[1] == "by":
            names.append("Null")
            ips.append("None")
            names.append(sep[2])
            ips.append("")
        else:
            f = sep.index("from")
            b = sep.index("by")
            half = k.split("by")
            quart = half[1].split("for")

            names.append(sep[f+1])
            ips.append(extract_meta(half[0]))
            names.append(sep[b+1])
            ips.append(extract_meta(quart[0]))
    '''
    print("\nHop #: From --> By")

    for k in range(len(names) - 1, -1, -2):
        print("Hop {0}: {1} {2} --> {3} {4}" .format(j, names[k - 1],
                                                     ips[k - 1], names[k],
                                                     ips[k]))

        if (j % 2 == 0):

            text += """<div class="container right">
    <div class="content">
      <h4>Salt nº {0}: Origen --> Destí</h4>
      <p>{1} {2} --> {3} {4}</p>
    </div>
</div>""".format(j, names[k - 1], ips[k - 1], names[k], ips[k])
        else:
            text += """<div class="container left">
    <div class="content">
      <h4>Salt nº {0}: Origen --> Destí</h4>
      <p>{1} {2} --> {3} {4}</p>
    </div>
</div>""".format(j, names[k - 1], ips[k - 1], names[k], ips[k])

        j += 1

    text += """</div>"""
    return text


only_ips = []
print(ips)

for address in ips:
    #print("Adress: " + address)
    new_addr = ""
    if (address and address[0] == '[' and address[len(address)-1] == ']'):
        new_addr = str(address[1:-1])
        #print("New adress: " + new_addr)
    result = re.match(ip_pattern, new_addr)
    if result:
        only_ips.append(new_addr)
    result = re.match(ipv6_pattern, new_addr)
    if result:
        only_ips.append(new_addr)
    else:
        print("No fa match ni amb IPv4 ni IPv6: ", new_addr)

print(ips)
print(only_ips)

only_ips = only_ips[::-1]  # reversing del array

result = re.match(ip_pattern, ip_remitent)
if result:
    only_ips.insert(0, ip_remitent)


# HO COMENTEM PER NO GASTAR API QUERYS!!!

# Recolectem Ciutats d'on es troben les IPs (IPv4 i IPv6) (per despres representarles al mapa):
for mta_address in only_ips:
    if (re.match(ip_pattern, mta_address) or re.match(ipv6_pattern, mta_address)):
        print("Mta address: " + mta_address)
        # OJO lhem fet la asyncrona, podem reaprofitar connexió
        # async with geoip2.webservice.AsyncClient(534778, '2KcXWF0vdaOxe6dL') as client:
        try:
            with geoip2.webservice.Client(534778, '2KcXWF0vdaOxe6dL') as client:
                #response = client.country('203.0.113.0')
                #response = client.insights('203.0.113.0')
                response = client.city(mta_address)
                city_names.append(str(response.city.name))
                longituds.append(response.location.longitude)
                latituds.append(response.location.latitude)
                print("IP: " + str(mta_address) +
                      " --> City: " + str(response.city.name))
                print("IP: " + str(mta_address) + " --> Latitude: " +
                      str(response.location.latitude))
                print("IP: " + str(mta_address) + " --> Longitude: " +
                      str(response.location.longitude))
        except:
            city_names.append("Multicast IP")
            longituds.append(0)
            latituds.append(0)


# Printar tot al mapamundi
#fig = plt.figure(figsize=(14, 10))
#ax = fig.add_axes([0.1, 0.1, 0.8, 0.8])

#m = Basemap(projection='merc', llcrnrlat=-80, urcrnrlat=80,llcrnrlon=-180, urcrnrlon=180, lat_ts=20, resolution='c')
# m.drawcoastlines()

title = ""
for i in range(len(city_names)):
    title = title + " --> " + city_names[i]
    # if i < (len(city_names)-1):

    # Dibuixem linia entre ciutat i ciutat
    #m.drawgreatcircle(longituds[i], latituds[i], longituds[i+1], latituds[i+1], linewidth=2, color='b')
    # m.drawcoastlines()
    #m.fillcontinents(color='tan', lake_color='lightblue')
    # m.drawmapboundary(fill_color='lightblue')
    # draw parallels
    # m.drawparallels(np.arange(10,90,20),labels=[1,1,0,1])
    # draw meridians
    # m.drawmeridians(np.arange(-180,180,30),labels=[1,1,0,1])

    #x, y = m(longituds[i+1], latituds[i+1])
    #plt.text(x, y, city_names[i+1], fontsize=12,fontweight='bold', ha='left', va='top', color='k')

    #x, y = m(longituds[i], latituds[i])
    #plt.text(x, y, city_names[i], fontsize=12,fontweight='bold', ha='left', va='top', color='k')

# Assignem titol
#ax.set_title("Ruta del correu" + title)

# Guardem la imatge en format png amb el temps actual com a nom
#now = datetime.now()
#current_time = now.strftime("%H:%M:%S")
#image_path_html = "mapas/" + current_time + ".png"
#image_path = "../htdocs/mapas/" + current_time + ".png"
# plt.savefig(image_path)


def isRegistered(domain):
    try:
        w = whois.whois(domain)
    except Exception:
        return False
    else:
        print("Esta registrat: " + domain)
        return bool(w.domain_name)


def getCreationDate(domain):
    if isRegistered(domain):
        whois_info = whois.whois(domain)
        print("Domain creation date:", whois_info.creation_date)
        return whois_info.creation_date


def domainLess3Month(creation_date):
    if creation_date:
        ara = datetime.now()
        print("Present: ", ara)
        diferencia = ara - creation_date
        dies = diferencia.days
        print(dies)
        if dies < 90:
            print("Fa menys de 3 mesos!\r\nNo pinta bé! +10")
            return True
        else:
            print("Fa més de 3 mesos!")
            return False
    else:
        print("No te creation date!: +5")


# Descarreguem l'arxiu que conté els dominis dels proveidors publics
arxiu = open('public_domain_providers.txt', 'r')
linies = arxiu.readlines()
arxiu.close()

# Mirem que el domini del remitent i del destinatari no sigui el mateix
public_domain_providers = []
# Strips the newline character
for line in linies:
    public_domain_providers.append(line.strip())

if not msg['to']:
    msg['to'] = "<->"
to_email = msg['to'].split('<', 1)
to_email = to_email[len(to_email)-1].split('>', 1)
to_email = to_email[0]
print("To_email: " + to_email)
to_domain = ""
if (to_email and (re.match(domain_pattern, to_email))):
    print("Es un email!")
    to_domain = to_email.split('@', 1)
    to_domain = to_domain[len(to_domain)-1]
    print("To_domain: " + to_domain)


if not msg['from']:
    msg['from'] = "<->"
from_email = msg['from'].split('<', 1)
from_email = from_email[len(from_email)-1].split('>', 1)
from_email = from_email[0]
print("From_email: " + from_email)
if (from_email and (re.match(domain_pattern, from_email))):
    print("Es un email!")
    from_domain = from_email.split('@', 1)
    from_domain = from_domain[len(from_domain)-1]
    print("From_domain: " + from_domain)
    remitent_correu = from_email
#    isRegistered(from_domain)
    creation_date = getCreationDate(from_domain)
    if (domainLess3Month(creation_date)):
        recent_creation_date = True
    else:
        recent_creation_date = False
    # Mirar si es de la mateixa companyia
    for public_domain_prov in public_domain_providers:
        if (from_domain == public_domain_prov):
            print("Domini de un public provider, no conta com a companyia!")
            domain_public_provider = True


# Miro si el From i to son de la mateix companyia:
if not domain_public_provider:
    if to_domain == from_domain:
        print("Son de la mateixa companyia!!!")
        same_company = True
    else:
        print("Son de companyies diferents")

if not msg['Reply-to']:
    msg['Reply-to'] = "<->"
reply_to = msg['Reply-to'].split('<', 1)
reply_to = reply_to[len(reply_to)-1].split('>', 1)
reply_to = reply_to[0]
print("Reply_to: " + reply_to)
if (reply_to and (re.match(domain_pattern, reply_to))):
    print("Es un email!")
    reply_to_domain = reply_to.split('@', 1)
    reply_to_domain = reply_to_domain[len(reply_to_domain)-1]
    print("Reply_to_domain: " + reply_to_domain)

if not msg['Return-Path']:
    msg['Return-Path'] = "<->"
return_path = msg['Return-Path'].split('<', 1)
return_path = return_path[len(return_path)-1].split('>', 1)
return_path = return_path[0]
print("Return_path: " + return_path)
if (return_path and (re.match(domain_pattern, return_path))):
    print("Es un email!")
    return_path_domain = return_path.split('@', 1)
    return_path_domain = return_path_domain[len(return_path_domain)-1]
    print("Reply_to_domain: " + return_path_domain)


# Estreiem totes les paraules del body en un array
# Decodejem el body que pot estar encodejat en MIME
body = ''.join(body.get_content().splitlines(keepends=True))
# Guardem cada paraula en un array
pattern_space_nline = '[\n\r\s]+'
body_words = re.split(pattern_space_nline, body)
#print("New_body: ")
# print(body_words)

# Extreure links del body i veure la reputacio
url_pattern = 'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'


#links_to_analyze = ['http://www.seim.co.kr', 'http://www.google.es']
links_to_analyze = []

for word in body_words:
    if (word and (re.match(url_pattern, word))):
        # Word --> Url to analyze
        print("Es una url!!! --> " + word)
        links_to_analyze.append(word)

# Tambe hi han correus que els links estan en el codi HTML, no ens els podem saltar:
msg_words = str(msg).split('\"')
for word in msg_words:
    if (word and (re.match(url_pattern, word))):
        # Word --> Url to analyze
        print("Es una url!!! --> " + word)
        links_to_analyze.append(word)

# Escanear dominio
#response = vt.get_domain_report("google.com")


def analizeIP(ip):
    # ip_remitent
    print("IP a analitzar: " + str(ip))
    result = re.match(ip_pattern, ip)
    if result:
        print("IP address: " + str(ip))
        response = vt.get_ip_report(str(ip))
        #print("Response: ", response)
        try:
            if response["response_code"]:
                print("Response_code:", response["response_code"])
                if response["response_code"] == 200:
                    try:
                        if response["results"]["positives"]:
                            if (response["results"]["positives"] > 0):
                                print("IP: " + ip)
                                print("Positius:",
                                      response['results']['positives'])
                                print("IP maliciosa!!! -20!!!")
                                return True
                            else:
                                print("IP: " + ip)
                                print("IP legitima!!!")
                                return False
                    except:
                        return False
        except:
            print("No s'ha pogut analitzar la IP, revisa la teva connexió a internet")
    else:
        return False


from_domini_malicios = False
reply_to_domini_malicios = False
return_path_domini_malicios = False


info_from_domain = ""
data = False
data_reply_to = False
data_return_path = False

# NO VULL GASTAR QUERYS


def apivoid_domainrep(key, host):
    try:
        r = requests.get(
            url='https://endpoint.apivoid.com/domainbl/v1/pay-as-you-go/?key='+key+'&host='+host)
        return json.loads(r.content.decode())
    except:
        return ""


print("From domain: ", from_domain)
if re.match(regex_domain, from_domain):
    print("MATCH1")
    data = apivoid_domainrep(apivoid_key, from_domain)
# if (from_domain != reply_to_domain):
if re.match(regex_domain, reply_to_domain):
    data_reply_to = apivoid_domainrep(apivoid_key, reply_to_domain)

if re.match(regex_domain, return_path_domain):
    data_return_path = apivoid_domainrep(apivoid_key, return_path_domain)

print("Data: ", data)
print("Data_reply_to: ", data_reply_to)
print("Data_return_path: ", data_return_path)


def get_detection_engines(engines):
    list = ""
    for key, value in engines.items():
        if(bool(value['detected']) == 1):
            list += str(value['engine'])+", "
    return list.rstrip(", ")


if(data):
    if(data.get('error')):
        print("Error: "+data['error'])
    else:
        #print("Host: "+str(data['data']['report']['host']))
        info_from_domain += "Host: " + \
            str(data['data']['report']['host']) + "<br>"
        info_from_domain += "IP Address: " + \
            str(data['data']['report']['server']['ip']) + "<br>"
        info_from_domain += "Reverse DNS: " + \
            str(data['data']['report']['server']['reverse_dns']) + "<br>"
        info_from_domain += "---" + "<br>"
        info_from_domain += "Nombre de deteccions: " + \
            str(data['data']['report']['blacklists']['detections']) + "<br>"
        info_from_domain += "Detectat per: " + \
            get_detection_engines(
                data['data']['report']['blacklists']['engines']) + "<br>"
        info_from_domain += "---" + "<br>"
        info_from_domain += "Pais: "+str(data['data']['report']['server']['country_code'])+" ("+str(
            data['data']['report']['server']['country_name'])+")" + "<br>"
        info_from_domain += "Continent: "+str(data['data']['report']['server']['continent_code'])+" ("+str(
            data['data']['report']['server']['continent_name'])+")" + "<br>"
        info_from_domain += "Regió: " + \
            str(data['data']['report']['server']['region_name']) + "<br>"
        info_from_domain += "Ciutat: " + \
            str(data['data']['report']['server']['city_name']) + "<br>"
        info_from_domain += "---" + "<br>"
        info_from_domain += "Hosting gratuït: " + \
            str(data['data']['report']['category']['is_free_hosting']) + "<br>"
        info_from_domain += "URL Shortener: " + \
            str(data['data']['report']['category']
                ['is_url_shortener']) + "<br>"
        info_from_domain += "Dynamic DNS gratuït: " + \
            str(data['data']['report']['category']
                ['is_free_dynamic_dns']) + "<br>"
        if (data['data']['report']['blacklists']['detections'] > 0):
            from_domini_malicios = True
            print("Domini " + from_domain + " maliciós!")
else:
    print("Error: Request failed")


# Reply-To data
info_reply_to_domain = ""
if(data_reply_to):
    if(data_reply_to.get('error')):
        print("Error: "+data_reply_to['error'])
    else:
        #print("Host: "+str(data['data']['report']['host']))
        info_reply_to_domain += "Host: " + \
            str(data_reply_to['data']['report']['host']) + "<br>"
        info_reply_to_domain += "IP Address: " + \
            str(data_reply_to['data']['report']['server']['ip']) + "<br>"
        info_reply_to_domain += "Reverse DNS: " + \
            str(data_reply_to['data']['report']
                ['server']['reverse_dns']) + "<br>"
        info_reply_to_domain += "---" + "<br>"
        info_reply_to_domain += "Nombre de deteccions: " + \
            str(data_reply_to['data']['report']
                ['blacklists']['detections']) + "<br>"
        info_reply_to_domain += "Detectat per: " + \
            get_detection_engines(
                data_reply_to['data']['report']['blacklists']['engines']) + "<br>"
        info_reply_to_domain += "---" + "<br>"
        info_reply_to_domain += "Pais: "+str(data_reply_to['data']['report']['server']['country_code'])+" ("+str(
            data_reply_to['data']['report']['server']['country_name'])+")" + "<br>"
        info_reply_to_domain += "Continent: "+str(data_reply_to['data']['report']['server']['continent_code'])+" ("+str(
            data_reply_to['data']['report']['server']['continent_name'])+")" + "<br>"
        info_reply_to_domain += "Regió: " + \
            str(data_reply_to['data']['report']
                ['server']['region_name']) + "<br>"
        info_reply_to_domain += "Ciutat: " + \
            str(data_reply_to['data']['report']
                ['server']['city_name']) + "<br>"
        info_reply_to_domain += "---" + "<br>"
        info_reply_to_domain += "Hosting gratuït: " + \
            str(data_reply_to['data']['report']
                ['category']['is_free_hosting']) + "<br>"
        info_reply_to_domain += "URL Shortener: " + \
            str(data_reply_to['data']['report']
                ['category']['is_url_shortener']) + "<br>"
        info_reply_to_domain += "Dynamic DNS gratuït: " + \
            str(data_reply_to['data']['report']['category']
                ['is_free_dynamic_dns']) + "<br>"
        if (data_reply_to['data']['report']['blacklists']['detections'] > 0):
            reply_to_domini_malicios = True
            print("Domini " + reply_to_domain + " maliciós!")
else:
    print("Error data_reply_to: Request failed")


# Return-Path data
info_return_path_domain = ""
if(data_return_path):
    if(data_return_path.get('error')):
        print("Error: "+data_return_path['error'])
    else:
        #print("Host: "+str(data['data']['report']['host']))
        info_return_path_domain += "Host: " + \
            str(data_return_path['data']['report']['host']) + "<br>"
        info_return_path_domain += "IP Address: " + \
            str(data_return_path['data']['report']['server']['ip']) + "<br>"
        info_return_path_domain += "Reverse DNS: " + \
            str(data_return_path['data']['report']
                ['server']['reverse_dns']) + "<br>"
        info_return_path_domain += "---" + "<br>"
        info_return_path_domain += "Nombre de deteccions: " + \
            str(data_return_path['data']['report']
                ['blacklists']['detections']) + "<br>"
        info_return_path_domain += "Detectat per: " + \
            get_detection_engines(
                data_return_path['data']['report']['blacklists']['engines']) + "<br>"
        info_return_path_domain += "---" + "<br>"
        info_return_path_domain += "Pais: "+str(data_return_path['data']['report']['server']['country_code'])+" ("+str(
            data_return_path['data']['report']['server']['country_name'])+")" + "<br>"
        info_return_path_domain += "Continent: "+str(data_return_path['data']['report']['server']['continent_code'])+" ("+str(
            data_return_path['data']['report']['server']['continent_name'])+")" + "<br>"
        info_return_path_domain += "Regió: " + \
            str(data_return_path['data']['report']
                ['server']['region_name']) + "<br>"
        info_return_path_domain += "Ciutat: " + \
            str(data_return_path['data']['report']
                ['server']['city_name']) + "<br>"
        info_return_path_domain += "---" + "<br>"
        info_return_path_domain += "Hosting gratuït: " + \
            str(data_return_path['data']['report']
                ['category']['is_free_hosting']) + "<br>"
        info_return_path_domain += "URL Shortener: " + \
            str(data_return_path['data']['report']
                ['category']['is_url_shortener']) + "<br>"
        info_return_path_domain += "Dynamic DNS gratuït: " + \
            str(data_return_path['data']['report']
                ['category']['is_free_dynamic_dns']) + "<br>"
        if (data_return_path['data']['report']['blacklists']['detections'] > 0):
            return_path_domini_malicios = True
            print("Domini " + return_path_domain + " maliciós!")
            # print(info_return_path_domain)
else:
    print("Error data_return_path: Request failed")


def generateTableURLs():
    global links_to_analyze
    global puntuacio
    table = "<br><h3>Informació dels enllaços:</h3>"
    table += "<table id=\"MesuresSeguretat\">\n"

    # Create the table's column headers
    header = ['URL', 'Maliciosa', 'Informació']
    table += "  <tr>\n"
    for column in header:
        table += "    <th>{0}</th>\n".format(column.strip())
    table += "  </tr>\n"
    print("LINKS: ", links_to_analyze)
    for link in links_to_analyze:
        # NOVA FILA
        table += "  <tr>\n"
        # NOU CAMP (COLUMNA) a la FILA
        table += "    <td>{0}</td>\n".format(link)
        # Poner en cola una URL para ser escaneada.
        response = vt.scan_url(link)
        # Obtener los resultados de un análisis.
        time.sleep(3)
        response = vt.get_url_report(link)
        #print("Response: ", response)
        print("Response_code:", response["response_code"])
        if response["response_code"] == 200:
            if (response["results"]["positives"] > 0):
                table += "    <td>{0}</td>\n".format("Sí")
                cadena = "Nº Positius: {0}".format(
                    response['results']['positives'])
                table += "    <td>{0}</td>\n".format(cadena)
                puntuacio -= 20
                print("URL: " + link)
                print("Positius:", response['results']['positives'])
                print("URL maliciosa!!! +50!!!")

            else:
                print("URL: " + link)
                print("URL legitima!!!")
                table += "    <td>{0}</td>\n".format("No")
                table += "    <td>{0}</td>\n".format("L'enllaç sembla legítim")
        else:
            table += "    <td>{0}</td>\n".format("-")
            table += "    <td>{0}</td>\n".format(
                "No s'ha pogut connectar amb el servidor, torna-ho a provar més tard.")

        # TANCO FILA
        table += "  </tr>\n"

    # TANCO TAULA
    table += "</table><br>"
    return table


def generateProgressBar():
    global puntuacio
    if puntuacio < 0:
        puntuacio = 0

    if puntuacio >= 80:

        progress_bar = """
<div class="w3-container w3-green">
 <div class="center">
  <h1>Nivell de confiança</h1>
  <h2>{0}/100</h2>
  <p>Sembla un correu de confiança</p>
 </div>
</div>
    """.format(puntuacio)
    if puntuacio < 80 and puntuacio >= 50:
        progress_bar = """ 
<div class="w3-container w3-blue">
 <div class="center">
  <h1>Nivell de confiança</h1>
  <h2>{0}/100</h2>
  <p>Nivell de confiança mig, caldria valorar si és un correu malintencionat</p>
 </div>
</div>
""".format(puntuacio)
    if puntuacio < 50 and puntuacio > 0:
        progress_bar = """
<div class="w3-container w3-red">
  <h1>Nivell de confiança:</h1>
  <h2>{0}/100</h2>
</div>
<p>Vigila, sembla un correu de phishing! Pot ser perillós.</p>""".format(puntuacio)
    if puntuacio == 0:
        progress_bar = """
<div class="w3-container w3-black">
  <h1>Nivell de confiança:</h1>
  <h2>{0}/100</h2>
</div>
<p>Els indicadors asseguren que és un correu potencialment perillós</p>""".format(puntuacio)
    progress_bar += "<br>"
    return progress_bar


puntuacioFinal()
