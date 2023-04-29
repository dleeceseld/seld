#!/usr/bin/env python3

# Author Doug Leece dleece @ firstfiretech dot ca
# A simple script to generate both hex strings needed for format preserving encryption
# Generates the data, writes to a file to be read by the rest API as well as printing to screen
# Mar 24, 2023 Updated to address FF3 0 byte in tweak vuln

import random, os, sys, re, datetime


def showkeyvalues(klist):
    print("The python ff3 module requires two strings of hex characters to be used for encryption.\nThe rest API will automatically read these values from a key file on startup.\n")
    print("Record these key values as they would be needed for decryption of SELD processed hostnames and usernames.\n")
    print("32 character key:{}\n".format(klist[0]))
    print("16 character key:{}\n".format(klist[1]))

    return

def testnull(tweakstr):
    if re.search('00',tweakstr):
        newtweak=True    
        while newtweak:
            tweakstr=''.join(random.choices('0123456789abcdef',k=16))
            if not re.search('00',tweakstr):
                newtweak=False
    return tweakstr


def generatekeys():
    # Generate two strings that represent hex byte values
    keylist=[]
    key16=''.join(random.choices('0123456789abcdef',k=32))
    keylist.append(key16)
    tweak8=''.join(random.choices('0123456789abcdef',k=16))
    tweak8= testnull(tweak8)
    keylist.append(tweak8)
    return keylist

def storekeylist(kpath,klist):
    kfile = kpath + "/keyfile.txt"
    if os.path.isfile(kfile):
        print("WARNING: encryption file already in place.\n")
        print("Please archive and remove before generating new file")
        exit(1)
    # Assuming this is a new or reworked installation
    with open(kfile,'w') as fh:
        for val in klist:
            fh.write("{}\n".format(val))
    return


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: fpekeys.py path-to-store-keyfile")
        exit
    else:
        keyfilepath = sys.argv[1]
        if keyfilepath.startswith('/'):
            thiskeylist = generatekeys()
            storekeylist(keyfilepath,thiskeylist)
            showkeyvalues(thiskeylist)
        else:
            print("key file storage location must be an absolute path\n")
            exit(1)




