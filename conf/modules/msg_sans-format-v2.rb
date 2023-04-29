# Author: Doug Leece   dleece @ firstfiretech dot ca
# Jan 27/2023  V0 Module for removing tab and newline formatting in long strings like Windows Event Log "message" fields
#
# Presumes the data is already extracted from a log record and is the content from a free form field
# Minimum requirement is deidentifying account names, non-default domains and sids

# Feb 17th, changed message content replacement to using GSUB
# 2023-04-03,  start moving to single parser section per event ID (applicable till overlaps)

# Ruby gem imports
require 'ipaddr'
require 'net/http'
require 'json'


# According to logstash documentation these values are loaded at startup.
    # FPE web service  URL, hardcoded to use the encrypt function
    @fpeapinameuri = 'http://127.0.0.1:5030/api/v1/updatedata?encatdelimalpha='
    # rest service for encrypting hosts and domains
    @fpeapihostdomuri = 'http://127.0.0.1:5033/api/v1/updatedata?encdotdelimalpha='
    # Second API URL for SID deident
    @fpeapidigituri = 'http://127.0.0.1:5032/api/v1/updatedata?encdashdelimdigit='
def register(params)
    @thiseventid = params["eventidfield"]
end

# ################   Lists needed for filtering in various methods ############################
#@sensitivenames = IO.readlines("/opt/seld/conf/sensitivenames.txt",chomp: true)
@domain_list = IO.readlines("/opt/seld/conf/lists/domain_list.txt",chomp: true)
@winreserved_list = IO.readlines("/opt/seld/conf/lists/winreserved_list.txt",chomp: true)
@winsvcs_list = IO.readlines("/opt/seld/conf/lists/winsvcs_list.txt",chomp: true)

# Function to convert json lines file to hash table
def getwinrex()
    winrexht = Hash.new
    jlines=IO.readlines("/opt/seld/conf/lists/winrex.jsonl",chomp: true)
    jlines.each do |jline|
        tmphash = JSON.parse(jline)
        winrexht.merge!(tmphash) 
    end
    return winrexht
end
# convert JSON lines file of Windows message parsing characters into hashtable holding regex 
@winrex_hashes = getwinrex()


## IP deidentification keyset
# Extract deidentification keys from yaml file
File.open('/opt/seld/api/sitekeyset.yml') {
    |kv| @keyset = YAML.load(kv)
}

def readkeyset(sitekeyset)
    thiskeyset = Array.new
    if sitekeyset['rrev']
        thiskeyset[1] = sitekeyset['of3'].to_i
        thiskeyset[0] = sitekeyset['of2'].to_i
    else
        thiskeyset[1] = sitekeyset['of2'].to_i
        thiskeyset[0] = sitekeyset['of3'].to_i
    end
    thiskeyset[2] = sitekeyset['sd'].to_i
    thiskeyset[3] = sitekeyset['flip']
    thiskeyset[4] = sitekeyset['siterandseed'].to_i
    # Return positional array
    return thiskeyset
end

@sitekeyset = readkeyset(@keyset) # Instance varible since the keys never change after load. 

# IP Ranges that should be deidentified, ( can include non-rfc1918 if needed)
@net192 = IPAddr.new("192.168.0.0/16")
@net172 = IPAddr.new("172.16.0.0/12")
@net10 = IPAddr.new("10.0.0.0/8")


############################  Account Name processing
# Ignore all usernames that match Windows reseved words
def testwinreserved(acctname)
    revmatch=false
    @winreserved_list.each do |revname|
      if acctname.downcase == revname.downcase
        revmatch = true
      end
      break if revmatch
    end
    return revmatch
  end
# Windows has a number of built in accounts that have common prefixes but various suffixes.
# Use regex and anchor as starting with,  also don't case correct
  def testwinservices(acctname)
    svcmatch=false
    @winsvcs_list.each do |svcname|
      if acctname.match(%r{#{svcname}})
        svcmatch = true
      end
      break if svcmatch
    end
    return svcmatch
  end


# Format preserving encryption needs a minimum size data value to perfom the algorithm
# the python ff3 implmentation of FPE requires a minimum of 4 chars and max of 30,
# this function adjusts if required but data strings between 4 & 30 chars pass through
def testnamesize(thisname)
    if thisname.size() < 4
       #padlength = 4 - thisname.size()
       padname = thisname.rjust(4,"_")
       return padname
    elsif thisname.size() > 30
        truncname = thisname[0..29]
        return truncname 
    else
        return thisname
    end 
end

# This method accepts a single input, the data string to be encrypted, and returns a single string of the same length and character set 
# currently making a rest API call to a python webservice as there were no format preserving encryption implementations found in native ruby 
def deidentifyacctdata(thisname)
    # Adding paddding/truncating method to protect FPE algorithm
    thisname = testnamesize(thisname)
    requesturi = URI.parse(@fpeapinameuri + thisname)
    requestresponse = Net::HTTP.get_response(requesturi)
    # Confirm results were recieved
    if requestresponse.code == '200'
        restdata = JSON.parse(requestresponse.body)
        encresult = restdata['fpedata']
    else
        encresult = ''
    end

    return encresult
end

# Test account fields in the message content before encrypting anything, there are often
# blank fields, - as a place holder or a reserved name like SYSTEM or NT AUTHORITY which should
# remain unencrypted. 
def testacctdeident(evalname)
    if evalname == "-"
      return evalname
    end
    # Ignore all usernames that match Windows reseved words
    if testwinreserved(evalname)
        return evalname
    end
    if testwinservices(evalname)
        return evalname
    end
    # Likely user account or computer account, deidentify
    #if evalname.match(/\S+\$/)
    if rexobj=evalname.match(/(\S+)?\$/)
        #acctportion = evalname.match(/(\S+)\$/).captures[0]
        acctportion=rexobj.captures()[0]
        encacct = deidentifyacctdata(acctportion)
        encacct = encacct + "$"
        return encacct
    elsif rexobj=evalname.match(/(\S+)?\/(\S+)/)
        acctportion=rexobj.captures()[0]
        domportion=rexobj.captures()[1]
        # need to retest for reserved accounts because combo account\domains or domain\account can't be predefined --buggy
        if testwinreserved(acctportion)
            encacct = acctportion
        else
            encacct = deidentifyacctdata(acctportion)
        end
        encdom = deidentifydomainnamedata(domportion)
        encacctdom = encacct + "/" + encdom
        return encacctdom
    # test for multiword space separated
    elsif evalname.match?(/\S++\s++\S++/)
        # Temp patch while working through multi-word field data
        evalname=evalname.gsub('<','')
        evalname=evalname.gsub('>','')
        deidentarray = Array.new
        mword=evalname.split
        mword.each do |welem|
            deidentwelem=deidentifyacctdata(welem)
            deidentarray.push(deidentwelem)
        end
        # Reconstruct the string with deidentified data
        deidentstr=''
        deidentarray.each do |didwelem|
            deidentstr=deidentstr + " " + didwelem
        end
        return deidentstr.strip()
    else 
        encacct = deidentifyacctdata(evalname)
        return encacct
    end
end


#############   SID processing #######################################

# This method accepts a single input, the data string to be encrypted, and returns a single string of the same length and character set 
# currently making a rest API call to a python webservice as there were no format preserving encryption implementations found in native ruby 
def deidentifydigitdata(thisdigits)
    requesturi = URI.parse(@fpeapidigituri + thisdigits)
    requestresponse = Net::HTTP.get_response(requesturi)
    # Confirm results were recieved
    if requestresponse.code == '200'
        restdata = JSON.parse(requestresponse.body)
        encresult = restdata['fpedata']
    else
        encresult = ''
    end
    return encresult
end

# Windows Event ID specific functions, ignore well known SIDs  (saves processing and removes 
# known text crypto attack opportunities ) 
# Domain unique SIDS have 32 characters for the domain section, well known sids less than 20
def deidentifywinsid(evalsid)
    if evalsid.size > 36
        # test the SID to determine if it's a domain or user value, very important to investigations
        if evalsid.start_with?("S-1-5-21")
            sidelemarray=evalsid.split('-')
            sidprefix=sidelemarray[0,4].join("-") + "-" 
            # test for domain + rid or just domain
            if sidelemarray.size == 8
                sidsuffix = sidelemarray[-4,7].join("-")
            else 
                sidsuffix = sidelemarray[-4,6].join("-")
            end
            # confirm the array slicing went ok and send the partial SID to FPE rest service
            if !sidsuffix.nil? && sidsuffix.size > 3
                encsidsuffix = deidentifydigitdata(sidsuffix)
            end
            # Presuming everthing cam back correctly build the deidentified SID
            if !encsidsuffix.nil? && encsidsuffix.size > 5
                return sidprefix + encsidsuffix
            else 
                return evalsid   # returns clear text SID but log format is retained
            end       
        else
            # Catch other types of SIDs other than 5-21
            File.open('/opt/seld/debuglogs/seld_wknsid-debug.log','a') { |fh| fh.puts evalsid }
            return evalsid   # returns clear text SID but log format is retained
        end
    else
        return evalsid
    end # End of test for well known SID exclusion
end # sid check method

#################  Domain name processing #######################
# pass the individual names from a list to perform a regex check, return a boolean
def testregex(listelement,evalstr)
    if evalstr.match?(listelement)
      return true
    else
        return false
    end
end

# Send complete host / domain name as needed
def deidentifydomainnamedata(thisdomainname)
    requesturi = URI.parse(@fpeapihostdomuri + thisdomainname)
    requestresponse = Net::HTTP.get_response(requesturi)
    # Confirm results were recieved
    if requestresponse.code == '200'
        restdata = JSON.parse(requestresponse.body)
        encresult = restdata['fpedata']
    else
        encresult = ''
    end
  
    return encresult
  end
  
# Test for domain names that are in list of known organization domains, ignore Windows defaults
# Extended to work with hostnames following predefined naming conventions and default machine names created at build time.
def testdomaindeident(thisdomainname)
    domlistmatch=false
    if thisdomainname == "-"
        return thisdomainname
    end
    # Test to see if if it an FQDN or domain name, if not just deidentify the single name
    if thisdomainname.match(/\S+\.\S+/)
      @domain_list.each do |thisdom|
        if testregex(thisdom,thisdomainname.downcase())
          encdomname = deidentifydomainnamedata(thisdomainname)
          domlistmatch=true
          return encdomname
        end
      end  # end of first each do
    else
      @domain_list.each do |thisdom|
        domelem = thisdom.split('.')[0]
        if testregex(domelem,thisdomainname.downcase())
          encdomname = deidentifydomainnamedata(thisdomainname)
          domlistmatch=true
          return encdomname
        end
      end  # end of second each do  
    end  # end of dom regex test
    # Certain local functions and pre domain joined assets can have local workstation name as the domain
    # Domain can also be reserved windows names like workgroup, NT AUTHORITY etc, exclude these from encryption
    if !domlistmatch
        winrsvname=false
        @winreserved_list.each do |thisrsv|
          if testregex(thisrsv.downcase(),thisdomainname.downcase())
            winrsvname=true
          end
          break if winrsvname
        end
        # If domain value is not on prelist and not excluded because of reserved windows name, encrypt
        if !winrsvname
          encdomname = deidentifydomainnamedata(thisdomainname)
          domlistmatch=false
          return encdomname
        end
    end # end of windows reserved name check
    return thisdomainname
end # testdomain method

#################  IP and port processing #######################

def testiprange(ipstring)
    deidentify = false
    if ipstring.match?(/-/)
        return false
    end
    # exception handling for strings that can't be converted to IP
    # Both mapped 4 and dotted quads seems to work in original format, process IPv6 string in deident
    begin
        testip= IPAddr.new(ipstring)
        #exit early if loopback
        if testip.loopback?()
            return false
        end
        # using include function rather than private to allow more flexibility
        # on which addresses fit deidentification criteria
        if @net192.include?(testip)
            deidentify = true
        elsif @net172.include?(testip)
            deidentify = true
        elsif @net10.include?(testip)
            deidentify = true
        else
            deidentify = false
    end
    rescue
        puts "invalid IP address"
    end
    return deidentify
end


# The second offset is bits 8-16 in RFC1918 trickier to calculate where the rollover is,
# Using the IP integers but only passing the masked portion to keep middle rotor fairly stable
def setrotor2(ipint,offset,ipintmin,ipintmax)
    hostsize=ipintmax - ipintmin
    ipint = ipint + offset
    if  (ipint + 256) > ipintmax
        return (ipint - (hostsize + 256))
    elsif ipint < ipintmin
        return (ipint + (hostsize - 256))
    else
        return ipint
    end
end

# IP is split on 4th octet & remainder of 8-16 based on RFC range, Enigma machine like rotation using a set of key values presumably kept secret
def deidentifyipdata(ipstring,tks)
    # get offset rotor values, and entropy seed and random , if keyset incomplete return original IP 
    if tks.size < 5
        puts("deident failure, check keyset") 
        return ipstring
    end
    #remove IPV6 mapping if applied
    if ipstring.match(/(::ffff:)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/)
        sixprefix=$1
        ip4str=$2
        ip4obj=IPAddr.new(ip4str)
    elsif  ipstring.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/) 
        ip4str=$1
        ip4obj=IPAddr.new(ip4str)
    else
        puts("no ipstring match")
        return ipstring        
    end
    
    # Divide dotted quad into an array
    dqarray=ip4str.split('.')
    # RFC1918 /16 requires last two octets to be offset
    if dqarray[0].to_i == 192 && ip4obj.ipv4?()
        #Get the numeric value of the dotted quad first three octets
        maskstr=dqarray[0,3].join('.')+'.0'
        ip4maskstrobj = IPAddr.new(maskstr)
        ipintval = ip4maskstrobj.to_i
        # Min and max for 192.168.0.0/16
        imin=3232235520
        imax=3232301055
        # flip variable to change whether an octet is added or subtracted ( further obfuscation option)
        if tks[3]     
            # rotor 2 value 257 to 1033 * 256( all bits in fourth octet ), 
            # divide by the seed to shrink the number and add in site random for more entropy
            of2=((tks[1] * 256) /tks[2]) + tks[4]    
            deidentintval = setrotor2(ipintval,of2,imin,imax)
            #Adjust the value for the 4th octet ( rotor 1)
            rotor1 = (dqarray[3].to_i + ( (tks[0] * 3 ) - (tks[4]/tks[2]) )) % 256
            # Add outside rotor to deidentified third octet + prefix 
            deidentintval  = deidentintval + rotor1
        else
            # send offet negative
            of2=( ((tks[1] * 256) /tks[2]) * -1)  + tks[4]
            deidentintval = setrotor2(ipintval,of2,imin,imax)
            #Adjust the value for the 4th octet (  rotor 1)
            rotor1 = (dqarray[3].to_i - ( (tks[0] * 3 ) + (tks[4]/tks[2]) )) % 256
            # Add outside rotor to deidentified second and third octets + prefix  
            deidentintval  = deidentintval + rotor1
        end
    end
    # RFC1918 /8 
    if dqarray[0].to_i == 10
        #Get the numeric value of the dotted quad first three octets 
        maskstr=dqarray[0,3].join('.')+'.0'
        ip4maskstrobj = IPAddr.new(maskstr)
        ipintval = ip4maskstrobj.to_i
        # Min and max for 10.0.0.0/8
        imin=167772160
        imax=184549375
        # flip variable to change whether an octet is added or subtracted (further obfuscation option)
        if tks[3]     
            # rotor 2 value 257 to 1033 * 256( all bits in fourth octet ), 
            # Multiple by the seed to increase distance from original IP, also add in site random for more entropy
            of2=((tks[1] * 256) * tks[2] + dqarray[1].to_i) + (tks[4] *  tks[2])   
            deidentintval = setrotor2(ipintval,of2,imin,imax)
            #Adjust the value for the 4th octet (  rotor 1)
            rotor1 = (dqarray[3].to_i + ( (tks[0] * 3 ) - (tks[4]/tks[2]) )) % 256
            # Add outside rotor to deidentified second and third octets + prefix 
            deidentintval  = deidentintval + rotor1
        else
            # send offet negative
            of2=( ((tks[1] * 256) * tks[2] + dqarray[1].to_i ) * -1)  + (tks[4] * tks[2] )
            deidentintval = setrotor2(ipintval,of2,imin,imax)
            #Adjust the value for the 4th octet (rotor 1)
            rotor1 = (dqarray[3].to_i - ( (tks[0] * 3 ) + (tks[4]/tks[2]) )) % 256
            # Add outside rotor to deidentified second and third octets + prefix  
            deidentintval  = deidentintval + rotor1
        end
    end
    # RFC 1918 / 12   
    if dqarray[0].to_i == 172
        #Get the numeric value of the dotted quad
        #ipintval = ip4obj.to_i
        maskstr=dqarray[0,3].join('.')+'.0'
        ip4maskstrobj = IPAddr.new(maskstr)
        ipintval = ip4maskstrobj.to_i
        # Min and max for 172.16.0.0/12
        imin=2886729728
        imax=2887778273
        # flip variable to change whether an octet is added or subtracted ( further obfuscation option)
        if tks[3]   
            # rotor 2 value 257 to 1033 * 256( all bits in fourth octet ), 
            # Multiple by the seed to increase distance from original IP, aslo add in site random for more entropy
            of2=((tks[1] * 256) * tks[2] ) + tks[4]    
            deidentintval = setrotor2(ipintval,of2,imin,imax)
            #Adjust the value for the 4th octet (  rotor 1)
            rotor1 = (dqarray[3].to_i + ( (tks[0] * 3 ) - (tks[4]/tks[2]) )) % 256
            # Add outside rotor to deidentified partial second, full third octet + prefix 
            deidentintval  = deidentintval + rotor1
        else
            # send offet negative
            of2=( ((tks[1] * 256) * tks[2] ) * -1)  + tks[4]
            deidentintval = setrotor2(ipintval,of2,imin,imax)
            #Adjust the value for the 4th octet (  rotor 1)
            rotor1 = (dqarray[3].to_i - ( (tks[0] * 3 ) + (tks[4]/tks[2]) )) % 256
            # Add second to external 
            deidentintval  = deidentintval + rotor1
        end
    end
    #Convert integer back to IP string -- amazing module Ruby devs!!
    deidentipstr = IPAddr.new(deidentintval, Socket::AF_INET).to_s
    # Rejoin the octet values back into a dotted quad, include v6 prefix if original IP string was IPV4mapped
    if !sixprefix.nil?
        return sixprefix + deidentipstr
    else
        return deidentipstr
    end
end

def deidentifyportdata(ipport,tksp)
    if ipport.match?(/-/)
        return ipport
    end
    if ipport.match?(/0/)
        return ipport
    end
    #tksp = readkeyset(keyset) # get offest rotors and seed, if keyset incomplete return original IP port
    if tksp.size < 5
        puts("deident failure, check keyset") 
        return ipport
    end
    if ipport.to_i % 2 == 0
        didport = (((tksp[0] + tksp[1] + tksp[4]) / 5) * 2) + ipport.to_i
    else
        didport = (((tksp[0] - tksp[1] + tksp[4]) / 5) * 3) + ipport.to_i
    end
    if didport > 65000
        return didport - (12000 + 5)
    elsif didport < 1024 
        return didport + (10000 + 5)
    else
        return didport
    end
end # End deident port

#######################################  Message prep ######################################
# Use ruby built in string manipulation methods idiomatically to reduce code size for such intuitive functions 
# as bulk removal of unwanted/needed characters from a string. Also saves one more for loop
# To-do: find efficient way to replace \\ with \, sadly not trivial in ruby because it's an escape character
  
def replacetab(thisstring)
    return thisstring.gsub(/\t/," ").squeeze(" ")
end

def replacenl(thisstring)
    return thisstring.gsub(/\n/," ").squeeze(" ")
end

#####################  Free Form Message Section ###########################################
# Message content parsing to remove sensitive fields relies on regex and captures

# Process activity 
#Define the various regex observed in 4688 sample set, test each and exit on first match
def msgpars4688(msgstr)
    rexmatch=false
    rex00=%r{#{@winrex_hashes["rex04688"]}}
    rex001=%r{#{@winrex_hashes["rex04688-1"]}}
    rex002=%r{#{@winrex_hashes["rex04688-2"]}}
    
    # Optimzation, place most common events before infrequent, extract regex only once
    # place more specific before more general incase there are two variants with similar content
    rexobj = rex002.match(msgstr)
    if !rexobj.nil?
        resultarray = rexobj.captures
        rexmatch=true
        deidentsid0=deidentifywinsid(resultarray[0])
        if deidentsid0 != resultarray[0]
            msgstr = msgstr.gsub(resultarray[0],deidentsid0)
        end
        deidentacct0=testacctdeident(resultarray[1])
        if deidentacct0 != resultarray[1]
            msgstr = msgstr.gsub(resultarray[1],deidentacct0)
        end
        deidentdom0=testdomaindeident(resultarray[2])
        if deidentdom0 != resultarray[2]
            msgstr = msgstr.gsub(resultarray[2],deidentdom0)
        end
        deidentsid1=deidentifywinsid(resultarray[3])
        if deidentsid1 != resultarray[3]
            msgstr = msgstr.gsub(resultarray[3],deidentsid1)
        end
        deidentacct1=testacctdeident(resultarray[4])
        if deidentacct1 != resultarray[4]
            msgstr = msgstr.gsub(resultarray[4],deidentacct1)
        end
        deidentdom1=testdomaindeident(resultarray[5])
        if deidentdom1 != resultarray[5]
            msgstr = msgstr.gsub(resultarray[5],deidentdom1)
        end
        deidentsid2=deidentifywinsid(resultarray[6])
        if deidentsid2 != resultarray[6]
            msgstr = msgstr.gsub(resultarray[6],deidentsid2)
        end
        # Simplified rewrite option because of gsub
        return msgstr
    end
    rexobj = rex001.match(msgstr)
    if !rexobj.nil?
        resultarray = rexobj.captures
        rexmatch=true
        deidentsid0=deidentifywinsid(resultarray[0])
        if deidentsid0 != resultarray[0]
            msgstr = msgstr.gsub(resultarray[0],deidentsid0)
        end
        deidentacct0=testacctdeident(resultarray[1])
        if deidentacct0 != resultarray[1]
            msgstr = msgstr.gsub(resultarray[1],deidentacct0)
        end
        deidentdom0=testdomaindeident(resultarray[2])
        if deidentdom0 != resultarray[2]
            msgstr = msgstr.gsub(resultarray[2],deidentdom0)
        end
        deidentacct1=testacctdeident(resultarray[1])
        if deidentacct1 != resultarray[3]
            msgstr = msgstr.gsub(resultarray[3],deidentacct1)
        end
        deidentdom1=testdomaindeident(resultarray[3])
        if deidentdom1 != resultarray[3]
            msgstr = msgstr.gsub(resultarray[3],deidentdom1)
        end
        # Simplified rewrite because of gsub
        return msgstr
    end
    # Catch remaining process execution conditions for debugging, many variations expected
    rexobj = rex00.match(msgstr)
    if !rexobj.nil?
        resultarray = rexobj.captures
        rexmatch=true
        #deident functions for sensitive strings extracted
        deidentsid=deidentifywinsid(resultarray[1]) # Windows Security Identifier
        deidentacct=testacctdeident(resultarray[2]) # User Account name
        deidentdom=testdomaindeident(resultarray[3]) # Windows Domain if needed
    
        # recreate message with deidentified data, and return message string
        newmsgstr = resultarray[0] + " Security ID: " + deidentsid + " Account Name: " + deidentacct + " Account Domain: " + deidentdom + " " + resultarray[4]
        return newmsgstr
    end
    # write unparsed messages to debug file
    if !rexmatch
            ile.open('/opt/seld/debuglogs/seld_winmsg_rex-reident-assessment.log','a') { |fh| fh.puts msgstr }
    end
end  # End msgparse 4688

# Account authentication messages
# Extract just enough regex to get all the key fields,
# run the deidentification test for each, if deidentified then gsub the message string
# watch for order of operations,  eg do YMMV.LOCAL before YMMV or the .local will be left behind
# Single set of parsers for each message based on event ID
def msgpars4625(msgstr)
    rexmatch=false
    # First pattern in message parsing 1 group,  1/0 
    rex10=%r{#{@winrex_hashes["rex14625"]}}
    rex11=%r{#{@winrex_hashes["rex14625-1"]}}
    rexobj = rex10.match(msgstr)
    if !rexobj.nil?
        resultarray = rexobj.captures
        rexmatch=true
        deidentsid=deidentifywinsid(resultarray[0]) # Windows Security Identifier
            if deidentsid != resultarray[0]
                msgstr = msgstr.gsub(resultarray[0],deidentsid)
            end
        deidentsid1=deidentifywinsid(resultarray[1]) # Windows Security Identifier
            if deidentsid1 != resultarray[1]
                msgstr = msgstr.gsub(resultarray[1],deidentsid1)
            end    
        deidentacct=testacctdeident(resultarray[2])
            if deidentacct != resultarray[2]
                msgstr = msgstr.gsub(resultarray[2],deidentacct)
            end
        deidentdom = deidentifydomainnamedata(resultarray[3])
            if deidentdom != resultarray[3]
                msgstr = msgstr.gsub(resultarray[3],deidentdom)
            end
        deidenthost = deidentifydomainnamedata(resultarray[4])
            if deidenthost != resultarray[4]
                msgstr = msgstr.gsub(resultarray[4],deidenthost)
            end
        if testiprange(resultarray[5]) 
            deidentip=deidentifyipdata(resultarray[5],@sitekeyset) #extract IP info
                if deidentip != resultarray[5]
                    msgstr = msgstr.gsub(resultarray[5],deidentip)
                end
        end
        return msgstr
    end # end rex10
    
    rexobj = rex11.match(msgstr)
    if !rexobj.nil?
        resultarray = rexobj.captures
        rexmatch=true
        deidentsid0=deidentifywinsid(resultarray[0]) # Windows Security Identifier
            if deidentsid0 != resultarray[0]
                msgstr = msgstr.gsub(resultarray[0],deidentsid0)
            end
        deidentacct0=testacctdeident(resultarray[1])
        if deidentacct0 != resultarray[1]
            msgstr = msgstr.gsub(resultarray[1],deidentacct0)
        end
        deidentdom = testdomaindeident(resultarray[2])
        if deidentdom != resultarray[2]
            msgstr = msgstr.gsub(resultarray[2],deidentdom)
        end
        deidentsid1=deidentifywinsid(resultarray[3]) 
        if deidentsid1 != resultarray[3]
            msgstr = msgstr.gsub(resultarray[3],deidentsid1)
        end  
        # Source workstation name  
        deidenthost = testdomaindeident(resultarray[4])
        if deidenthost != resultarray[4]
            msgstr = msgstr.gsub(resultarray[4],deidenthost)
        end
        # Source network address
        if testiprange(resultarray[5]) 
            deidentip=deidentifyipdata(resultarray[5],@sitekeyset) 
                if deidentip != resultarray[5]
                    msgstr = msgstr.gsub(resultarray[5],deidentip)
                end
        end
        return msgstr
    end # end rex11
    # write unparsed messages to debug file
    if !rexmatch
    File.open('/opt/seld/debuglogs/seld_winmsg_rex-reident-assessment.log','a') { |fh| fh.puts msgstr }
    end
end  # End msg parse 4625

# password change events, 
def msgpars4720(msgstr)
    rexmatch=false
    # First pattern in message parsing 1 group,  1/0 
    rex10=%r{#{@winrex_hashes['rex14720']}}
    rexobj = rex10.match(msgstr)
    if !rexobj.nil?
        resultarray = rexobj.captures
        rexmatch=true
        # Track deident results and update message string if a field is deidentified
        deidentsid=deidentifywinsid(resultarray[0]) # Windows Security Identifier
        if deidentsid != resultarray[0]
            msgstr = msgstr.gsub(resultarray[0],deidentsid)
        end
        deidentacct0=testacctdeident(resultarray[1])
        if deidentacct0 != resultarray[1]
            msgstr = msgstr.gsub(resultarray[1],deidentacct0)
        end
        deidentdom0=testdomaindeident(resultarray[2])
        if deidentdom0 != resultarray[2]
            msgstr = msgstr.gsub(resultarray[2],deidentdom0)
        end
        deidentsid1=deidentifywinsid(resultarray[3]) # Windows Security Identifier
        if deidentsid1 != resultarray[3]
            msgstr = msgstr.gsub(resultarray[3],deidentsid1)
        end
        deidentacct1=testacctdeident(resultarray[4])
        if deidentacct1 != resultarray[4]
            msgstr = msgstr.gsub(resultarray[4],deidentacct1)
        end
        deidentdom1=testdomaindeident(resultarray[5])
        if deidentdom1 != resultarray[5]
        msgstr = msgstr.gsub(resultarray[5],deidentdom1)
        end
        # Display name, (using multi work regex and deidentification function)
        deidentdispname=testacctdeident(resultarray[6])
        if deidentdispname != resultarray[6]
            msgstr = msgstr.gsub(resultarray[6],deidentdispname)
        end
        # User principal name
        deidentupn=testacctdeident(resultarray[7])
        if deidentupn != resultarray[7]
            msgstr = msgstr.gsub(resultarray[7],deidentupn)
        end
        # Home directory name, (using multi work regex and deidentification function)
        deidenthomedir=testacctdeident(resultarray[8])
        if deidenthomedir != resultarray[8]
            msgstr = msgstr.gsub(resultarray[8],deidenthomedir)
        end
        # Home drive name, (using multi work regex and deidentification function)
        deidenthomedrv=testacctdeident(resultarray[9])
        if deidenthomedrv != resultarray[9]
            msgstr = msgstr.gsub(resultarray[9],deidenthomedrv)
        end
        # Workstation(s) assigned, (using multi work regex and deidentification function)
        deidentworkstn=testacctdeident(resultarray[10])
        if deidentworkstn != resultarray[10]
            msgstr = msgstr.gsub(resultarray[10],deidentworkstn)
        end
        # return message string with the sensitive fields deidentified
        return msgstr
    end
    # write unparsed messages to debug file
    if !rexmatch
        File.open('/opt/seld/debuglogs/seld_winmsg_rex-reident-assessment.log','a') { |fh| fh.puts msgstr }
    end  
end  # End msg parse 4720

# password change events, 
def msgpars4722(msgstr)
    rexmatch=false
    # First pattern in message parsing 1 group,  1/0 
    rex10=%r{#{@winrex_hashes['rex14722']}}
    rexobj = rex10.match(msgstr)
    if !rexobj.nil?
        resultarray = rexobj.captures
        rexmatch=true
        # Track deident results and update message string if a field is deidentified
        deidentsid0=deidentifywinsid(resultarray[0]) # Windows Security Identifier
        if deidentsid0 != resultarray[0]
            msgstr = msgstr.gsub(resultarray[0],deidentsid0)
        end
        deidentacct0=testacctdeident(resultarray[1])
        if deidentacct0 != resultarray[1]
            msgstr = msgstr.gsub(resultarray[1],deidentacct0)
        end
        deidentdom0=testdomaindeident(resultarray[2])
        if deidentdom0 != resultarray[2]
            msgstr = msgstr.gsub(resultarray[2],deidentdom0)
        end
        deidentsid1=deidentifywinsid(resultarray[3]) # Windows Security Identifier
        if deidentsid1 != resultarray[3]
            msgstr = msgstr.gsub(resultarray[3],deidentsid1)
        end
        deidentacct1=testacctdeident(resultarray[4])
        if deidentacct1 != resultarray[4]
            msgstr = msgstr.gsub(resultarray[4],deidentacct1)
        end
        deidentdom1=testdomaindeident(resultarray[5])
        if deidentdom1 != resultarray[5]
        msgstr = msgstr.gsub(resultarray[5],deidentdom1)
        end
        # return message string with the sensitive fields deidentified
        return msgstr
    end
    # write unparsed messages to debug file
    if !rexmatch
        File.open('/opt/seld/debuglogs/seld_winmsg_rex-reident-assessment.log','a') { |fh| fh.puts msgstr }
    end
end  # End msg parse 4722

# password change events, 
def msgpars4724(msgstr)
    rexmatch=false
    # First pattern in message parsing 1 group,  1/0 
    rex10=%r{#{@winrex_hashes['rex14724']}}
    rexobj = rex10.match(msgstr)
    if !rexobj.nil?
        resultarray = rexobj.captures
        rexmatch=true
        # Track deident results and update message string if a field is deidentified
        deidentsid=deidentifywinsid(resultarray[0]) # Windows Security Identifier
        if deidentsid != resultarray[0]
            msgstr = msgstr.gsub(resultarray[0],deidentsid)
        end
        deidentacct0=testacctdeident(resultarray[1])
        if deidentacct0 != resultarray[1]
            msgstr = msgstr.gsub(resultarray[1],deidentacct0)
        end
        deidentdom0=testdomaindeident(resultarray[2])
        if deidentdom0 != resultarray[2]
            msgstr = msgstr.gsub(resultarray[2],deidentdom0)
        end
        deidentsid1=deidentifywinsid(resultarray[3]) # Windows Security Identifier
        if deidentsid1 != resultarray[3]
            msgstr = msgstr.gsub(resultarray[3],deidentsid1)
        end
        deidentacct1=testacctdeident(resultarray[4])
        if deidentacct1 != resultarray[4]
            msgstr = msgstr.gsub(resultarray[4],deidentacct1)
        end
        deidentdom1=testdomaindeident(resultarray[5])
        if deidentdom1 != resultarray[5]
        msgstr = msgstr.gsub(resultarray[5],deidentdom1)
        end
        # return message string with the sensitive fields deidentified
        return msgstr
    end
    # write unparsed messages to debug file
    if !rexmatch
        File.open('/opt/seld/debuglogs/seld_winmsg_rex-reident-assessment.log','a') { |fh| fh.puts msgstr }
    end 
end  # End msg parse 4724

# User deleted events, 
def msgpars4726(msgstr)
    rexmatch=false
    # First pattern in message parsing 1 group,  1/0 
    rex10=%r{#{@winrex_hashes['rex14726']}}
    rexobj = rex10.match(msgstr)
    if !rexobj.nil?
        resultarray = rexobj.captures
        rexmatch=true
        # Track deident results and update message string if a field is deidentified
        deidentsid0=deidentifywinsid(resultarray[0]) # Windows Security Identifier
        if deidentsid0 != resultarray[0]
            msgstr = msgstr.gsub(resultarray[0],deidentsid0)
        end
        deidentacct0=testacctdeident(resultarray[1])
        if deidentacct0 != resultarray[1]
            msgstr = msgstr.gsub(resultarray[1],deidentacct0)
        end
        deidentdom0=testdomaindeident(resultarray[2])
        if deidentdom0 != resultarray[2]
            msgstr = msgstr.gsub(resultarray[2],deidentdom0)
        end
        deidentsid1=deidentifywinsid(resultarray[3]) # Windows Security Identifier
        if deidentsid1 != resultarray[3]
            msgstr = msgstr.gsub(resultarray[3],deidentsid1)
        end
        deidentacct1=testacctdeident(resultarray[4])
        if deidentacct1 != resultarray[4]
            msgstr = msgstr.gsub(resultarray[4],deidentacct1)
        end
        deidentdom1=testdomaindeident(resultarray[5])
        if deidentdom1 != resultarray[5]
        msgstr = msgstr.gsub(resultarray[5],deidentdom1)
        end
        # return message string with the sensitive fields deidentified
        return msgstr
    end
    # write unparsed messages to debug file
    if !rexmatch
        File.open('/opt/seld/debuglogs/seld_winmsg_rex-reident-assessment.log','a') { |fh| fh.puts msgstr }
    end
end  # End msg parse 4726

# Global group member removal password change events, 
def msgpars4729(msgstr)
    rexmatch=false
    # First pattern in message parsing 1 group,  1/0 
    rex10=%r{#{@winrex_hashes['rex14729']}}
    rexobj = rex10.match(msgstr)
    if !rexobj.nil?
        resultarray = rexobj.captures
        rexmatch=true
        # Track deident results and update message string if a field is deidentified
        deidentsid=deidentifywinsid(resultarray[0]) # Windows Security Identifier
        if deidentsid != resultarray[0]
            msgstr = msgstr.gsub(resultarray[0],deidentsid)
        end
        deidentacct0=testacctdeident(resultarray[1])
        if deidentacct0 != resultarray[1]
            msgstr = msgstr.gsub(resultarray[1],deidentacct0)
        end
        deidentdom0=testdomaindeident(resultarray[2])
        if deidentdom0 != resultarray[2]
            msgstr = msgstr.gsub(resultarray[2],deidentdom0)
        end
        deidentsid1=deidentifywinsid(resultarray[3]) # Windows Security Identifier
        if deidentsid1 != resultarray[3]
            msgstr = msgstr.gsub(resultarray[3],deidentsid1)
        end
        deidentacct1=testacctdeident(resultarray[4])
        if deidentacct1 != resultarray[4]
            msgstr = msgstr.gsub(resultarray[4],deidentacct1)
        end
        deidentsid2=deidentifywinsid(resultarray[5]) # Windows Security Identifier
        if deidentsid2 != resultarray[5]
            msgstr = msgstr.gsub(resultarray[5],deidentsid2)
        end
        deidentacct2=testacctdeident(resultarray[6])
        if deidentacct2 != resultarray[6]
            msgstr = msgstr.gsub(resultarray[6],deidentacct2)
        end
        deidentdom1=testdomaindeident(resultarray[7])
        if deidentdom1 != resultarray[7]
        msgstr = msgstr.gsub(resultarray[7],deidentdom1)
        end
        # return message string with the sensitive fields deidentified
        return msgstr
    end
    # write unparsed messages to debug file
    if !rexmatch
        File.open('/opt/seld/debuglogs/seld_winmsg_rex-reident-assessment.log','a') { |fh| fh.puts msgstr }
    end   
end  # End msg parse 4729

# Local group member removal, 
def msgpars4733(msgstr)
    rexmatch=false
    # First pattern in message parsing 1 group,  1/0 
    rex10=%r{#{@winrex_hashes['rex14733']}}
    rexobj = rex10.match(msgstr)
    if !rexobj.nil?
        resultarray = rexobj.captures
        rexmatch=true
        # Track deident results and update message string if a field is deidentified
        deidentsid=deidentifywinsid(resultarray[0]) # Windows Security Identifier
        if deidentsid != resultarray[0]
            msgstr = msgstr.gsub(resultarray[0],deidentsid)
        end
        deidentacct0=testacctdeident(resultarray[1])
        if deidentacct0 != resultarray[1]
            msgstr = msgstr.gsub(resultarray[1],deidentacct0)
        end
        deidentdom0=testdomaindeident(resultarray[2])
        if deidentdom0 != resultarray[2]
            msgstr = msgstr.gsub(resultarray[2],deidentdom0)
        end
        deidentsid1=deidentifywinsid(resultarray[3]) # Windows Security Identifier
        if deidentsid1 != resultarray[3]
            msgstr = msgstr.gsub(resultarray[3],deidentsid1)
        end
        deidentacct1=testacctdeident(resultarray[4])
        if deidentacct1 != resultarray[4]
            msgstr = msgstr.gsub(resultarray[4],deidentacct1)
        end
        deidentsid2=deidentifywinsid(resultarray[5]) # Windows Security Identifier
        if deidentsid2 != resultarray[5]
            msgstr = msgstr.gsub(resultarray[5],deidentsid2)
        end
        deidentacct2=testacctdeident(resultarray[6])
        if deidentacct2 != resultarray[6]
            msgstr = msgstr.gsub(resultarray[6],deidentacct2)
        end
        deidentdom1=testdomaindeident(resultarray[7])
        if deidentdom1 != resultarray[7]
        msgstr = msgstr.gsub(resultarray[7],deidentdom1)
        end
        # return message string with the sensitive fields deidentified
        return msgstr
    end
    # write unparsed messages to debug file
    if !rexmatch
        File.open('/opt/seld/debuglogs/seld_winmsg_rex-reident-assessment.log','a') { |fh| fh.puts msgstr }
    end 
end  # End msg parse 4733

def msgpars4648(msgstr)
    rexmatch=false
    # First pattern in message parsing 1 group,  1/0 
    rex10=%r{#{@winrex_hashes['rex14648']}}
    rex101=%r{#{@winrex_hashes['rex14648-1']}}
    rexobj = rex10.match(msgstr)
    if !rexobj.nil?
        resultarray = rexobj.captures
        rexmatch=true
        # Track deident results and update message string if a field is deidentified
        deidentsid=deidentifywinsid(resultarray[0]) # Windows Security Identifier
            if deidentsid != resultarray[0]
                msgstr = msgstr.gsub(resultarray[0],deidentsid)
            end
        deidentacct0=testacctdeident(resultarray[1])
            if deidentacct0 != resultarray[1]
                msgstr = msgstr.gsub(resultarray[1],deidentacct0)
            end
        deidentdom0=testdomaindeident(resultarray[2])
        if deidentdom0 != resultarray[2]
            msgstr = msgstr.gsub(resultarray[2],deidentdom0)
        end
        deidentacct1=testacctdeident(resultarray[3])
        if deidentacct1 != resultarray[3]
            msgstr = msgstr.gsub(resultarray[3],deidentacct1)
        end
        deidentdom1=testdomaindeident(resultarray[4])
        if deidentdom1 != resultarray[4]
            msgstr = msgstr.gsub(resultarray[4],deidentdom1)
        end
        deidentacct2=testacctdeident(resultarray[5])  # target server name
        if deidentacct2 != resultarray[5]
            msgstr = msgstr.gsub(resultarray[5],deidentacct2)
        end
        if testiprange(resultarray[6]) 
            deidentip=deidentifyipdata(resultarray[6],@sitekeyset) #extract IP info
            if deidentip != resultarray[6]
                msgstr = msgstr.gsub(resultarray[6],deidentip)
            end
            # return message string with the sensitive fields deidentified
            return msgstr
        end
    end
    rexobj = rex101.match(msgstr)
    if !rexobj.nil?
        resultarray = rexobj.captures
        rexmatch=true
            # Track deident results and update message string if a field is deidentified
        deidentsid=deidentifywinsid(resultarray[0]) # Windows Security Identifier
            if deidentsid != resultarray[0]
                msgstr = msgstr.gsub(resultarray[0],deidentsid)
            end
        deidentacct=testacctdeident(resultarray[1])
            if deidentacct != resultarray[1]
                msgstr = msgstr.gsub(resultarray[1],deidentacct)
            end
        deidentdom0=testdomaindeident(resultarray[2])
            if deidentdom0 != resultarray[2]
                msgstr = msgstr.gsub(resultarray[2],deidentdom0)
            end        
        deidentdom1=testdomaindeident(resultarray[3])
            if deidentdom1 != resultarray[3]
                msgstr = msgstr.gsub(resultarray[3],deidentdom1)
            end
        deidentacct1=testacctdeident(resultarray[4])
            if deidentacct1 != resultarray[4]
                msgstr = msgstr.gsub(resultarray[4],deidentacct1)
            end
        # return message string with the sensitive fields deidentified
        return msgstr
    end    
    # write unparsed messages to debug file
    if !rexmatch
        File.open('/opt/seld/debuglogs/seld_winmsg_rex-reident-assessment.log','a') { |fh| fh.puts msgstr }
        end
end  # End msg parse 4648

# A member added to al local security group
def msgpars4732(msgstr)
    rexmatch=false
    # First pattern in message parsing 1 group,  1/0 
    rex10=%r{#{@winrex_hashes['rex14732']}}
    rexobj = rex10.match(msgstr)
    if !rexobj.nil?
        resultarray = rexobj.captures
        rexmatch=true
        # Track deident results and update message string if a field is deidentified
        deidentsid0=deidentifywinsid(resultarray[0]) # Windows Security Identifier
        if deidentsid0 != resultarray[0]
            msgstr = msgstr.gsub(resultarray[0],deidentsid0)
        end
        deidentacct0=testacctdeident(resultarray[1])
        if deidentacct0 != resultarray[1]
            msgstr = msgstr.gsub(resultarray[1],deidentacct0)
        end
        deidentdom0=testdomaindeident(resultarray[2])
        if deidentdom0 != resultarray[2]
            msgstr = msgstr.gsub(resultarray[2],deidentdom0)
        end
        deidentsid1=deidentifywinsid(resultarray[3]) # Windows Security Identifier
        if deidentsid1 != resultarray[3]
            msgstr = msgstr.gsub(resultarray[3],deidentsid1)
        end
        deidentacct1=testacctdeident(resultarray[4])
        if deidentacct1 != resultarray[4]
            msgstr = msgstr.gsub(resultarray[4],deidentacct1)
        end
        deidentsid2=deidentifywinsid(resultarray[5]) # Windows Security Identifier
        if deidentsid2 != resultarray[5]
            msgstr = msgstr.gsub(resultarray[5],deidentsid1)
        end
        deidentgroup=testacctdeident(resultarray[6])
        if deidentgroup != resultarray[6]
            msgstr = msgstr.gsub(resultarray[6],deidentgroup)
        end
        deidentdom1=testdomaindeident(resultarray[7])
        if deidentdom0 != resultarray[7]
            msgstr = msgstr.gsub(resultarray[7],deidentdom1)
        end
        # return message string with the sensitive fields deidentified
        return msgstr
    end
    
    # write unparsed messages to debug file
    if !rexmatch
        File.open('/opt/seld/debuglogs/seld_winmsg_rex-reident-assessment.log','a') { |fh| fh.puts msgstr }
    end
end  # End msg parse 4732



def msgpars1(msgstr)
    rexmatch=false
    # First pattern in message parsing 1 group,  1/0 
    rex10=%r{#{@winrex_hashes['rex14648']}}
    rex101=%r{#{@winrex_hashes['rex14648-1']}}
    rex11=%r{#{@winrex_hashes["rex14776"]}}
    rex12=%r{#{@winrex_hashes["rex14672"]}}
    rex13=%r{#{@winrex_hashes["rex14647"]}}
 
    rexobj = rex10.match(msgstr)
    if !rexobj.nil?
        resultarray = rexobj.captures
        rexmatch=true
        # Track deident results and update message string if a field is deidentified
        deidentsid=deidentifywinsid(resultarray[0]) # Windows Security Identifier
            if deidentsid != resultarray[0]
                msgstr = msgstr.gsub(resultarray[0],deidentsid)
            end
        deidentacct0=testacctdeident(resultarray[1])
            if deidentacct0 != resultarray[1]
                msgstr = msgstr.gsub(resultarray[1],deidentacct0)
            end
        deidentdom0=testdomaindeident(resultarray[2])
        if deidentdom0 != resultarray[2]
            msgstr = msgstr.gsub(resultarray[2],deidentdom0)
        end
        deidentacct1=testacctdeident(resultarray[3])
        if deidentacct1 != resultarray[3]
            msgstr = msgstr.gsub(resultarray[3],deidentacct1)
        end
        deidentdom1=testdomaindeident(resultarray[4])
        if deidentdom1 != resultarray[4]
            msgstr = msgstr.gsub(resultarray[4],deidentdom1)
        end
        deidentacct2=testacctdeident(resultarray[5])  # target server name
        if deidentacct2 != resultarray[5]
            msgstr = msgstr.gsub(resultarray[5],deidentacct2)
        end
        if testiprange(resultarray[6]) 
            deidentip=deidentifyipdata(resultarray[6],@sitekeyset) #extract IP info
            if deidentip != resultarray[6]
                msgstr = msgstr.gsub(resultarray[6],deidentip)
            end
        end
        # return message string with the sensitive fields deidentified
        return msgstr
    end
    rexobj = rex101.match(msgstr)
    if !rexobj.nil?
        resultarray = rexobj.captures
        rexmatch=true
            # Track deident results and update message string if a field is deidentified
        deidentsid=deidentifywinsid(resultarray[0]) # Windows Security Identifier
            if deidentsid != resultarray[0]
                msgstr = msgstr.gsub(resultarray[0],deidentsid)
            end
        deidentacct=testacctdeident(resultarray[1])
            if deidentacct != resultarray[1]
                msgstr = msgstr.gsub(resultarray[1],deidentacct)
            end
        deidentdom0=testdomaindeident(resultarray[2])
            if deidentdom0 != resultarray[2]
                msgstr = msgstr.gsub(resultarray[2],deidentdom0)
            end        
        deidentdom1=testdomaindeident(resultarray[3])
            if deidentdom1 != resultarray[3]
                msgstr = msgstr.gsub(resultarray[3],deidentdom1)
            end
        deidentacct1=testacctdeident(resultarray[4])
            if deidentacct1 != resultarray[4]
                msgstr = msgstr.gsub(resultarray[4],deidentacct1)
            end
        # return message string with the sensitive fields deidentified
        return msgstr
    end
    rexobj = rex11.match(msgstr)
    if !rexobj.nil?
        resultarray = rexobj.captures
        rexmatch=true
        deidentacct=testacctdeident(resultarray[0])
            if deidentacct != resultarray[0]
                msgstr = msgstr.gsub(resultarray[0],deidentacct)
            end
        deidenthost = deidentifydomainnamedata(resultarray[1])
            if deidenthost != resultarray[1]
                msgstr = msgstr.gsub(resultarray[1],deidenthost)
            end
        return msgstr
    end
    rexobj = rex12.match(msgstr)
    if !rexobj.nil?
        resultarray = rexobj.captures
        rexmatch=true
        deidentsid=deidentifywinsid(resultarray[0]) # Windows Security Identifier
            if deidentsid != resultarray[0]
                msgstr = msgstr.gsub(resultarray[0],deidentsid)
            end
        deidentacct=testacctdeident(resultarray[1])
            if deidentacct != resultarray[1]
                msgstr = msgstr.gsub(resultarray[1],deidentacct)
            end
        deidenthost = deidentifydomainnamedata(resultarray[2])
            if deidenthost != resultarray[2]
                msgstr = msgstr.gsub(resultarray[2],deidenthost)
            end
        return msgstr
    end
    rexobj = rex13.match(msgstr)
    if !rexobj.nil?
        resultarray = rexobj.captures
        rexmatch=true
        deidentsid=deidentifywinsid(resultarray[0]) # Windows Security Identifier
            if deidentsid != resultarray[0]
                msgstr = msgstr.gsub(resultarray[0],deidentsid)
            end
        deidentacct=testacctdeident(resultarray[1])
            if deidentacct != resultarray[1]
                msgstr = msgstr.gsub(resultarray[1],deidentacct)
            end
        deidenthost = deidentifydomainnamedata(resultarray[2])
            if deidenthost != resultarray[2]
                msgstr = msgstr.gsub(resultarray[2],deidenthost)
            end
        return msgstr
    end
    
    # write unparsed messages to debug file
    if !rexmatch
        File.open('/opt/seld/debuglogs/seld_winmsg_rex-reident-assessment.log','a') { |fh| fh.puts msgstr }
    end
end  # End msg parse 1

# Kerberos related messages
def msgpars2(msgstr)
    rexmatch=false
    # define parsing regex up front for Kerberos realted messages
    rex20=%r{#{@winrex_hashes['rex24768']}}
    rex201=%r{#{@winrex_hashes['rex24768-1']}}
    rex21=%r{#{@winrex_hashes['rex24770']}}
    rex211=%r{#{@winrex_hashes['rex24770-1']}}
    rex22=%r{#{@winrex_hashes['rex24769']}}
    rex23=%r{#{@winrex_hashes['rex24771']}}

    # for now treat each event unique,  result array is different for each message
    # counting on the order to stay the same is frailfor the sake of 20-30 lines of code
    rexobj = rex20.match(msgstr)
    if !rexobj.nil?
        resultarray = rexobj.captures
        rexmatch=true
        deidentacct=testacctdeident(resultarray[0])
        if deidentacct != resultarray[0]
            msgstr = msgstr.gsub(resultarray[0],deidentacct)
        end
        deidentdom1=testdomaindeident(resultarray[1])
        if deidentdom1 != resultarray[1]
            msgstr = msgstr.gsub(resultarray[1],deidentdom1)
        end
        deidentsid0=deidentifywinsid(resultarray[2]) # Windows Security Identifier
        if deidentsid0 != resultarray[2]
            msgstr = msgstr.gsub(resultarray[2],deidentsid0)
        end
        deidentsid1=deidentifywinsid(resultarray[3]) # Windows Security Identifier
        if deidentsid1 != resultarray[3]
            msgstr = msgstr.gsub(resultarray[3],deidentsid0)
        end
        if testiprange(resultarray[4]) 
            deidentip=deidentifyipdata(resultarray[4],@sitekeyset) #extract IP info
            if deidentip != resultarray[4]
                msgstr = msgstr.gsub(resultarray[4],deidentip)
            end
        end
        deidentport=deidentifyportdata(resultarray[5],@sitekeyset)
        if deidentport.to_s != resultarray[5].to_s
            msgstr = msgstr.gsub(resultarray[5],deidentport.to_s)
        end
            # return message string with the sensitive fields deidentified
        return msgstr
    end
    rexobj = rex201.match(msgstr)
    if !rexobj.nil?
        resultarray = rexobj.captures
        rexmatch=true
        deidentacct=testacctdeident(resultarray[0])
        if deidentacct != resultarray[0]
            msgstr = msgstr.gsub(resultarray[0],deidentacct)
        end
        deidentdom1=testdomaindeident(resultarray[1])
        if deidentdom1 != resultarray[1]
            msgstr = msgstr.gsub(resultarray[1],deidentdom1)
        end
        deidentsid0=deidentifywinsid(resultarray[2]) # Windows Security Identifier
        if deidentsid0 != resultarray[2]
            msgstr = msgstr.gsub(resultarray[2],deidentsid0)
        end
        deidentsid1=deidentifywinsid(resultarray[3]) # Windows Security Identifier
        if deidentsid1 != resultarray[3]
            msgstr = msgstr.gsub(resultarray[3],deidentsid0)
        end
        # return message string with the sensitive fields deidentified
        return msgstr
    end        
    rexobj = rex21.match(msgstr)
    if !rexobj.nil?
        resultarray = rexobj.captures
        rexmatch=true
        deidentacct=testacctdeident(resultarray[0])
        if deidentacct != resultarray[0]
            msgstr = msgstr.gsub(resultarray[0],deidentacct)
        end
        deidentdom=testdomaindeident(resultarray[1])
        if deidentdom != resultarray[1]
            msgstr = msgstr.gsub(resultarray[1],deidentdom)
        end
        deidentsid=deidentifywinsid(resultarray[2]) # Windows Security Identifier
        if deidentsid != resultarray[2]
            msgstr = msgstr.gsub(resultarray[2],deidentsid)
        end
        # return message string with the sensitive fields deidentified
        return msgstr
    end
    
    rexobj = rex211.match(msgstr)
    if !rexobj.nil?
        resultarray = rexobj.captures
        rexmatch=true
        deidentacct=testacctdeident(resultarray[0])
        if deidentacct != resultarray[0]
            msgstr = msgstr.gsub(resultarray[0],deidentacct)
        end
        deidentdom=testdomaindeident(resultarray[1])
        if deidentdom != resultarray[1]
            msgstr = msgstr.gsub(resultarray[1],deidentdom)
        end
        deidentsid=deidentifywinsid(resultarray[2]) # Windows Security Identifier
        if deidentsid != resultarray[2]
            msgstr = msgstr.gsub(resultarray[2],deidentsid)
        end
        if testiprange(resultarray[3]) 
            deidentip=deidentifyipdata(resultarray[3],@sitekeyset) #extract IP info
            if deidentip != resultarray[3]
                msgstr = msgstr.gsub(resultarray[3],deidentip)
            end
        end
        deidentport=deidentifyportdata(resultarray[4],@sitekeyset)
        if deidentport.to_s != resultarray[4].to_s
            msgstr = msgstr.gsub(resultarray[4],deidentport.to_s)
        end
        # return message string with the sensitive fields deidentified
        return msgstr
    end
    
    rexobj = rex22.match(msgstr)
    if !rexobj.nil?
        resultarray = rexobj.captures
        rexmatch=true
        deidentacct0=testacctdeident(resultarray[0])
        if deidentacct0 != resultarray[0]
            msgstr = msgstr.gsub(resultarray[0],deidentacct0)
        end
        deidentdom=testdomaindeident(resultarray[1])
        if deidentdom != resultarray[1]
            msgstr = msgstr.gsub(resultarray[1],deidentdom)
        end
        deidentacct1=testacctdeident(resultarray[2])
        if deidentacct1 != resultarray[2]
            msgstr = msgstr.gsub(resultarray[2],deidentacct1)
        end
        deidentsid=deidentifywinsid(resultarray[3]) # Windows Security Identifier
        if deidentsid != resultarray[3]
            msgstr = msgstr.gsub(resultarray[3],deidentsid)
        end
        if testiprange(resultarray[4])
            deidentip=deidentifyipdata(resultarray[4],@sitekeyset) #extract IP info
            if deidentip != resultarray[4]
                msgstr = msgstr.gsub(resultarray[4],deidentip)
            end
        end
        deidentport=deidentifyportdata(resultarray[5],@sitekeyset)
        if deidentport.to_s != resultarray[5].to_s
            msgstr = msgstr.gsub(resultarray[5],deidentport.to_s)
        end
        # return message string with the sensitive fields deidentified
        return msgstr
    end

    rexobj = rex23.match(msgstr)
    if !rexobj.nil?
        resultarray = rexobj.captures
        rexmatch=true
        deidentsid=deidentifywinsid(resultarray[0]) # Windows Security Identifier
        if deidentsid != resultarray[0]
            msgstr = msgstr.gsub(resultarray[0],deidentsid)
        end
        deidentacct0=testacctdeident(resultarray[1])
        if deidentacct0 != resultarray[1]
            msgstr = msgstr.gsub(resultarray[1],deidentacct0)
        end
        deidentacct1=testacctdeident(resultarray[2])
        if deidentacct1 != resultarray[2]
            msgstr = msgstr.gsub(resultarray[2],deidentacct1)
        end           
        if testiprange(resultarray[3])
            deidentip=deidentifyipdata(resultarray[3],@sitekeyset) #extract IP info
            if deidentip != resultarray[3]
                msgstr = msgstr.gsub(resultarray[3],deidentip)
            end
        end
        deidentport=deidentifyportdata(resultarray[4],@sitekeyset)
        if deidentport.to_s != resultarray[4].to_s
            msgstr = msgstr.gsub(resultarray[4],deidentport.to_s)
        end
        # return message string with the sensitive fields deidentified
        return msgstr
    end
    # write unparsed messages to debug file
    if !rexmatch
        File.open('/opt/seld/debuglogs/seld_winmsg_rex-reident-assessment.log','a') { |fh| fh.puts msgstr }
    end
end # end msgpars2

# LOLBAS specific monitoring capabilities
def msgpars3(msgstr)   
    rexmatch=false 
    rex30=%r{#{@winrex_hashes['rex34104']}}
    rex31=%r{#{@winrex_hashes["rex34799"]}}
    rex32=%r{#{@winrex_hashes["rex34798"]}}
    rex33=%r{#{@winrex_hashes["rex35140"]}}
    rexobj = rex30.match(msgstr)
    if !rexobj.nil?
        resultarray = rexobj.captures
        rexmatch=true
        # leaving script block as is for now, far to many variations
        return msgstr
    end
    
    rexobj = rex31.match(msgstr)
    if !rexobj.nil?
        resultarray = rexobj.captures
        rexmatch=true
        # Use new inline gsub approach
        deidentsid=deidentifywinsid(resultarray[0]) # Windows Security Identifier
            if deidentsid != resultarray[0]
                msgstr = msgstr.gsub(resultarray[0],deidentsid)
            end
        deidentacct=testacctdeident(resultarray[1])
            if deidentacct != resultarray[1]
                msgstr = msgstr.gsub(resultarray[1],deidentacct)
            end
        deidentdom = deidentifydomainnamedata(resultarray[2])
            if deidentdom != resultarray[2]
                msgstr = msgstr.gsub(resultarray[2],deidentdom)
            end
        deidentsid1=deidentifywinsid(resultarray[3]) # Windows Security Identifier
            if deidentsid1 != resultarray[3]
                msgstr = msgstr.gsub(resultarray[3],deidentsid1)
            end
        deidentacct1=testacctdeident(resultarray[4])
            if deidentacct != resultarray[4]
                msgstr = msgstr.gsub(resultarray[4],deidentacct1)
            end
        deidentdom1 = deidentifydomainnamedata(resultarray[5])
            if deidentdom1 != resultarray[5]
                msgstr = msgstr.gsub(resultarray[5],deidentdom1)
            end
        return msgstr
    end
    
    rexobj = rex32.match(msgstr)
    if !rexobj.nil?
        resultarray = rexobj.captures
        rexmatch=true
        # Use new inline gsub approach
        deidentsid=deidentifywinsid(resultarray[0]) # Windows Security Identifier
            if deidentsid != resultarray[0]
                msgstr = msgstr.gsub(resultarray[0],deidentsid)
            end
        deidentacct=testacctdeident(resultarray[1])
            if deidentacct != resultarray[1]
                msgstr = msgstr.gsub(resultarray[1],deidentacct)
            end
        deidentdom = deidentifydomainnamedata(resultarray[2])
            if deidentdom != resultarray[2]
                msgstr = msgstr.gsub(resultarray[2],deidentdom)
            end
        deidentsid1=deidentifywinsid(resultarray[3]) # Windows Security Identifier
            if deidentsid1 != resultarray[3]
                msgstr = msgstr.gsub(resultarray[3],deidentsid1)
            end
        deidentacct1=testacctdeident(resultarray[4])
            if deidentacct != resultarray[4]
                msgstr = msgstr.gsub(resultarray[4],deidentacct1)
            end
        deidentdom1 = deidentifydomainnamedata(resultarray[5])
            if deidentdom1 != resultarray[5]
                msgstr = msgstr.gsub(resultarray[5],deidentdom1)
            end
        return msgstr
    end
    rexobj = rex33.match(msgstr)
    if !rexobj.nil?
        resultarray = rexobj.captures
        rexmatch=true
        deidentsid=deidentifywinsid(resultarray[0]) # Windows Security Identifier
        if deidentsid != resultarray[0]
            msgstr = msgstr.gsub(resultarray[0],deidentsid)
        end
        deidentacct=testacctdeident(resultarray[1])
        if deidentacct != resultarray[1]
            msgstr = msgstr.gsub(resultarray[1],deidentacct)
        end
        deidentdom=testdomaindeident(resultarray[2])
        if deidentdom != resultarray[2]
            msgstr = msgstr.gsub(resultarray[2],deidentdom)
        end
        if testiprange(resultarray[3])
            deidentip=deidentifyipdata(resultarray[3],@sitekeyset) #extract IP info
            if deidentip != resultarray[3]
                msgstr = msgstr.gsub(resultarray[3],deidentip)
            end
        end
        deidentport=deidentifyportdata(resultarray[4],@sitekeyset)
        if deidentport.to_s != resultarray[4].to_s
            msgstr = msgstr.gsub(resultarray[4],deidentport.to_s)
        end
        # return message string with the sensitive fields deidentified
        return msgstr
    end
        # End of regex parsers, write remainder to debug log for reidentification analysis
    if !rexmatch
        File.open('/opt/seld/debuglogs/seld_winmsg_rex-reident-assessment.log','a') { |fh| fh.puts msgstr }
        return msgstr
    end
end  # End msgparse3

##########################################################################################
# Read the message file from each log record and remove visual formatting with single spaces
def filter(event)
    msgstring = event.get('[winlog][message]')
    if msgstring.size() > 1
        # replace tabs and newline
        msgstring = replacetab(msgstring)
        msgstring = replacenl(msgstring)    
    else
        File.open('/opt/seld/debuglogs/seld_jsonevtmsg-debug.log','a') { |fh| fh.puts "no message extracted"}
        File.open('/opt/seld/debugogs/seld_jsonevtmsg-debug.log','a') { |fh| fh.puts event }
    end

    # Retrive event ID and call correct parsing function. 
    # If event ID message parser not found, write to log for analysis.  ( Potentially filtering at source or drop filter on deident)
    evtid = event.get(@thiseventid)
    if evtid == "4688"
        deidentmsgstring=msgpars4688(msgstring)
    elsif evtid == "4625"
        deidentmsgstring=msgpars4625(msgstring)
    elsif evtid == "4648"
        deidentmsgstring=msgpars4648(msgstring)
    elsif evtid == "4720"
        deidentmsgstring=msgpars4720(msgstring)
    elsif evtid == "4722"
        deidentmsgstring=msgpars4722(msgstring)
    elsif evtid == "4724"
        deidentmsgstring=msgpars4724(msgstring)
    elsif evtid == "4726"
        deidentmsgstring=msgpars4726(msgstring)
    elsif evtid == "4729"
        deidentmsgstring=msgpars4729(msgstring)
    elsif evtid == "4733"
        deidentmsgstring=msgpars4733(msgstring)
    elsif evtid == "4732"
        deidentmsgstring=msgpars4732(msgstring)            
    elsif evtid == "4776" or evtid == "4672" or evtid == "4647"
        deidentmsgstring=msgpars1(msgstring)
    elsif evtid == "4768" or evtid == "4769" or evtid == "4770" or evtid == "4771"
        deidentmsgstring=msgpars2(msgstring)
    elsif evtid == "4104" or evtid == "4799" or evtid == "4798" or evtid == "5140"
        deidentmsgstring=msgpars3(msgstring)
    else
        evtidmsg = evtid.to_s + ": " + msgstring
        File.open('/opt/seld/debuglogs/seld_winmsg_evtid-reident-assessment.log','a') { |fh| fh.puts evtidmsg }
    end

    # write sans-formating message data back into event. Test for deidentified status, 
    # else write flattened string to message
    if !deidentmsgstring.nil? && deidentmsgstring.size > 1
        event.set("[winlog][message]",deidentmsgstring)
    else
        event.set("[winlog][message]",msgstring)
    end
    #  End of the ruby event filter
    return[event]
end