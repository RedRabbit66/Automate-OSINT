#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from subprocess import PIPE, Popen


def cmdline(command):
    process = Popen(
        args=command,
        stdout=PIPE,
        shell=True
    )
    return process.communicate()[0].decode("utf-8")


def databaseCheck(term):
    table = """<section class="ftco-section">
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-6 text-center mb-5">
                <h2 class="heading-section">Not found on any local databases</h2>
            </div>
        </div>
    </div>"""
    command = cmdline("/usr/bin/grep -R " + term +
                      " ./Databases/ 2> /dev/null")
    if command:
        print("[+] Found on a database:")
        leaks = command.split("\n")
        table = """
            <section class="ftco-section">
                <div class="container">
                    <div class="row justify-content-center">
                        <div class="col-md-6 text-center mb-5">
                            <h2 class="heading-section">Found it on the following databases</h2>
                        </div>
                    </div>
                    <div class="row">
                        <div class="col-md-12">
                            <div class="table-wrap">
                                <table class="table table-bordered table-dark table-hover">
                                    <tbody>"""

        # Creem la taula amb les capçaleres corresponents
        header = ['Database', 'Result (Line)']
        table += "<thead>\n"
        for column in header:
            table += "    <th>{0}</th>\n".format(column.strip())
        table += "</thead>\n"
        for leak in leaks:
            if leak != '':
                try:
                    # NOVA FILA
                    table += "  <tr>\n"
                    # NOU CAMP (COLUMNA) a la FILA
                    table += """<th scope="row">{0}</th>""".format(
                        leak.split(":")[0])
                    table += """<td>{0}</td>\n""".format(
                        str(':'.join(leak.split(":")[1:])))

                    # TANCO FILA
                    table += "  </tr>\n"
                    print("[+]  Term found on: " + leak.split(":")[0])
                    print("[+]    Line of result: " +
                          str(':'.join(leak.split(":")[1:]).encode('ascii', 'ignore')))
                except:
                    pass
        table += """    </tbody>
						</table>
					</div>
				</div>
			</div>
		</div>
	</section>"""
    return table
