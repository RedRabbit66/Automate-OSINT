#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from subprocess import PIPE, Popen
import hashlib


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
