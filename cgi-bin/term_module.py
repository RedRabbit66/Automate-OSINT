__author__ = "Llorenç Garcia"
__copyright__ = "Copyright 2007, The Cogent Project"
__credits__ = ["David Marquet"]
__license__ = "GPL-3.0"
__version__ = "1.0.0"
__maintainer__ = "Llorenç Garcia and David Marquet"
__status__ = "Production"


from subprocess import PIPE, Popen


def cmdline(command):
    process = Popen(
        args=command,
        stdout=PIPE,
        shell=True
    )
    return process.communicate()[0].decode("utf-8")


def databaseCheck(term):
    command = cmdline("/usr/bin/grep -R " + term +
                      " ./Databases/ 2> /dev/null")
    if command:
        print("[+] Found on a database:")
        leaks = command.split("\n")
        #print("LEAKS: ", leaks)
        for leak in leaks:
            if leak != '':
                try:
                    print("[+]  Term found on: " + leak.split(":")[0])
                    print("  ->  Line of result: " +
                          str(':'.join(leak.split(":")[1:])))
                except:
                    pass
