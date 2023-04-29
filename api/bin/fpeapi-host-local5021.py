#!/usr/bin/env python3
#
# Author Doug Leece  dleece @ firstfiretech dot ca 
# Feb 4th/2023 Breaking out encryption rest services to reflect the differences in valid characters in
# the encryption alphabet. An all inclusive alphabet can include invalid characters in the encrypted output.
# Apr 8th/2023 Extending the functions so all api services implemented on every port instance. 
#
# Specifc to Microsoft, alphabets may need to be adjusted for other types of field data
# https://learn.microsoft.com/en-US/troubleshoot/windows-server/identity/naming-conventions-for-computer-domain-site-ou
# 
# Note: Due to the large amount of encryption required on field names, 
# the rest API can be a 15-25% bottleneck on Windows event log processing
# start one rest API for each ruby module using encryption, run on localhost 
# only to avoid exposing the decrption API on several ports
#
# Modify this reset service to accept a hostname, fqdn or domain
# split the input on the "." character, pass each element to the encryption
# load into second list, rejoin with dot delims and return ecrypted string.


import flask, os, re
from flask import request, jsonify, json


# The file containing keys will be stored on disk. use fpekeys.py to create keys, note the path provided as this will need
# to match the settings below for format preserving encryption to work
kpath='/opt/seld/api/secrets'
def readkeys(kpath):
    kfile=kpath + "/keyfile.txt"
    if not os.path.isfile(kfile):
        print("Encryption file missing, run fpekeys and confirm path")
    else:
        keyfile = open(kfile,'r')
        klist=keyfile.read().replace('\n',',').split(',')
    return klist

# use ff3 
from ff3 import FF3Cipher
# Use the built in alpha numeric library plus special characters observed in usernames and hostnames 
# Also note, URL encodeing may result in a %XX value, EG a space in a username would be LOCAL%20SERVICE
# but you may need to also include the actual character rather than the URL encoding because the decoded
# value is what is sent to the encryption process.

# Windows account names ( invalid chars are / \ [] :;|=,+*?<>@)
#compnamealpha=FF3Cipher.BASE62 + "._ -"  # Note there is a space in this intentionally
# Windows domain and hostnames - removing period, Win2000 convention is over 20 years
compnamealpha=FF3Cipher.BASE62 + "_-"  # Note there is a space in this intentionally
# Retrieve the FPE key values and instantiate the cipher object
thisklist=readkeys(kpath)
key=thisklist[0]
tweak=thisklist[1]
fpename = FF3Cipher.withCustomAlphabet(key,tweak,compnamealpha)

# Create a second encryption object for encrypting numbers only, EG Windows SID
fpenumonly = FF3Cipher(key,tweak)

# FPE has minimum lengths, 4 chars for alpha, 6 chars for radix10 ( digits)
def testelemalpha(thiselem):
    if len(thiselem) < 4:
        thiselem = thiselem.rjust(4,"_")
    return thiselem

def testelemdigit(thiselem):
    if len(thiselem) < 6:
        thiselem = thiselem.rjust(6,"0")
    return thiselem

# The two methods for processing text strings
def encdata(compname):
    compname=testelemalpha(compname)
    encname=fpename.encrypt(compname)
    return encname

def decdata(encdata):
    decname=fpename.decrypt(encdata)
    return decname

# two additional methods for processing digit only strings
def encdigits(digistring):
    digistring=testelemdigit(digistring)
    encnum=fpenumonly.encrypt(digistring)
    return encnum

def decdigits(encdigstr):
    decnum=fpenumonly.decrypt(encdigstr)
    return decnum

# Special method for encrypting dot delimited alpha like FQDNs while retaining dot delimited structure
# Using if condition to deal with strings that don't have a dot delim
def encddalpha(ddalpha):
    encddalist = []
    ddalist = ddalpha.split(".")
    for elem in ddalist:
        taelem = testelemalpha(elem)
        encddalist.append(fpename.encrypt(taelem))
    # 
    if len(encddalist) > 1:
        encddastr = ".".join(encddalist)
        return encddastr
    else:
        return encddalist[0]

# Decryption for above
def decddalpha(encddalpha):
    decddalist = []
    encddalist = encddalpha.split(".")
    for elem in encddalist:
       decddalist.append(fpename.decrypt(elem))
    #
    if  len(decddalist) > 1:
        decddastr = ".".join(decddalist)
        return decddastr
    else:
        return decddalist[0]

# Special method for encrypting "-"" delimited digit strings like SIDs while retaining "-" delimited structure
def encdddigit(dddigit):
    encdddlist = []
    dddlist = dddigit.split("-")
    for elem in dddlist:
        # Don't encrypt kerberos or local admin
        if elem == "1000" or elem == "502":
            encdddlist.append((elem))
        else:
            tdelem = testelemdigit(elem)
            encdddlist.append(fpenumonly.encrypt(tdelem))
    # 
    encdddstr = "-".join(encdddlist)
    return encdddstr
# Decryption for above
def decdddigit(encdddigit):
    decdddlist = []
    encdddlist = encdddigit.split("-")
    for elem in encdddlist:
       # Don't decrypt kerberos or local admin
        if elem == "1000" or elem == "502":
            decdddlist.append((elem))
        else:
            decdddlist.append(fpenumonly.decrypt(elem))
    # 
    decdddstr = "-".join(decdddlist)
    return decdddstr
   
# Special method for encrypting "@" delimted username strings like UPNs or email while retaining "@" format
def encatdelimdata(encatalpha):
    # Match email addresses or UPNs, including computer account UPNs
    atdelim=re.match('([\.\w-]+)(@|\$@)([\.\w-]+)', encatalpha)
    if atdelim is not None:
        # dump tuple to three element list, encrypt each alpha peice (post processing for dots),then rejoin
        deidentlist=list(atdelim.groups())
        deidentlist[0] = encddalpha(deidentlist[0])
        deidentlist[2] = encddalpha(deidentlist[2])
        # rejoin the list elements and return string
        encatdelimstr=''.join(deidentlist)
        return encatdelimstr
    # address usernames ending with $
    dolterm = re.match('([\.\w\-]+)(\$)',encatalpha)
    if dolterm is not None:
        encdoltermstr= encddalpha(dolterm.groups()[0])
        encdoltermstr = encdoltermstr + '$'
        return encdoltermstr
    # address legacy  8.3 naming convention
    tildeterm = re.match('([\.\w\-]+)(~\d+)',encatalpha)
    if tildeterm is not None:
        enctildetermstr= encddalpha(tildeterm.groups()[0])
        enctildetermstr = enctildetermstr + tildeterm.groups()[1]
        return enctildetermstr
    # address usernames with dots in them but no $, legal but inconvenient
    dotdelim= re.match('([\.\w-]+)',encatalpha)
    if dotdelim is not None:
        encdotdelimstr= encddalpha(dotdelim.groups()[0])
        return encdotdelimstr

def decatdelimdata(encatalpha):
    # Match email addresses or UPNs, including computer account UPNs
    atdelim=re.match('([\.\w-]+)(@|\$@)([\.\w-]+)', encatalpha)
    if atdelim is not None:
        # dump tuple to three element list, encrypt each alpha peice (post processing for dots),then rejoin
        deidentlist=list(atdelim.groups())
        deidentlist[0] = decddalpha(deidentlist[0])
        deidentlist[2] = decddalpha(deidentlist[2])
        # rejoin the list elements and return string
        encatdelimstr=''.join(deidentlist)
        return encatdelimstr
    # address usernames ending with $
    dolterm = re.match('([\.\w\-]+)(\$)',encatalpha)
    if dolterm is not None:
        encdoltermstr= decddalpha(dolterm.groups()[0])
        encdoltermstr = encdoltermstr + '$'
        return encdoltermstr
    # address legacy  8.3 naming convention
    tildeterm = re.match('([\.\w\-]+)(~\d+)',encatalpha)
    if tildeterm is not None:
        enctildetermstr= encddalpha(tildeterm.groups()[0])
        enctildetermstr = enctildetermstr + tildeterm.groups()[1]
        return enctildetermstr
    # address usernames with dots in them but no $, legal but inconvenient
    dotdelim= re.match('([\.\w-]+)',encatalpha)
    if dotdelim is not None:
        encdotdelimstr= decddalpha(dotdelim.groups()[0])
        return encdotdelimstr


######################   HTTP Routing & Runtime ###############################
app = flask.Flask(__name__)
# Change to False if url monitoring is not required
app.config["DEBUG"] = True


@app.route('/', methods=['GET'])
def home():
    return "<h1>Format Preserving encryption</h1><p>This is a work around until we can figure out FPE in ruby </p>"

# URI request, parse name from param passed, writing two methods that take a single param as the value to return
@app.route('/api/v1/updatedata', methods=['GET'])
def update_data():
    dataresult='invalid_method'
    # Encrypt a single aphanumeric string with no delimiters
    if 'encname' in request.args:
        dataresult = encdata(str(request.args['encname']))
        print(dataresult)
    if 'decname' in request.args:
        dataresult = decdata(str(request.args['decname']))
        print(dataresult)
    # Encrypt a s single digit only string with no delimeters
    if 'encnum' in request.args:
        dataresult = encdigits(str(request.args['encnum']))
        print(dataresult)
    if 'decnum' in request.args:
        dataresult = decdigits(str(request.args['decnum']))
        print(dataresult)
    # Encrypt an aphanumeric string with "." delimiters
    if 'encdotdelimalpha' in request.args:
        dataresult = encddalpha(str(request.args['encdotdelimalpha']))
        print(dataresult)
    if 'decdotdelimalpha' in request.args:
        dataresult = decddalpha(str(request.args['decdotdelimalpha']))
        print(dataresult)
    # Encrypt a digit string with "-" delimiters ( Windows SID)
    if 'encdashdelimdigit' in request.args:
        dataresult = encdddigit(str(request.args['encdashdelimdigit']))
        print(dataresult)
    if 'decdashdelimdigit' in request.args:
        dataresult = decdddigit(str(request.args['decdashdelimdigit']))
        print(dataresult)
      # Encrypt a single aphanumeric string with @ or $ delimiters
    if 'encatdelimalpha' in request.args:
        dataresult = encatdelimdata(str(request.args['encatdelimalpha']))
        print(dataresult)
    if 'decatdelimalpha' in request.args:
        dataresult = decatdelimdata(str(request.args['decatdelimalpha']))
        print(dataresult)

    # Collect data from rest function, present as JSON/dictionary      
    resultdict={'fpedata':dataresult}
    return jsonify(resultdict)

app.run(port=5021,host='127.0.0.1')