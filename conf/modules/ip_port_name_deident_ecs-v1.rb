# Author: Doug Leece   dleece @ firstfiretech dot ca
# Dec 29/2022  V0 Inital POC code to be called from a logstash pipeline:
#             - Queries the event API to retrieve specifc data elements within each log event (line)
#             - version 0 deidentifies designated IP addresses, source ports and usernames
#             - data obfuscation inputs are currently hard coded, later versions will utilize a 
#               secret key provided during inital deidentification processing.  
#               
# April 7/2023 Modifying IP rotor setup 
#
# Debug functions append the original log line and the processed/not processed value to a temporary log file.
# Marked in the code,  comment out when running performance tests or production

# Currently avoiding the installation of ruby gems outside of the logstash development tree, best chance of maintaining 
# functionality in future logstash versions.
#
# - ipaddr is a gem included in the logstash deployment, use for initial IP format valdiation
#    and testing of IP address being within a subnet that needs to be deidentified
# -  net/http and json are also gems included with the logstash deployment and required for rest API
#    connections. This allows certain log enrichment functions to be moved to a web service if they are
#    are not readily avaliable with the default ruby libraries,  E.G., format preserving encryption 

# Ruby gem imports
require 'ipaddr'
require 'net/http'
require 'json'
require 'yaml'

def register(params)
    @thisipaddress = params["ipaddressfield"]
    @thisportnumber = params["portnumberfield"]
    @thishostname = params["hostnamefield"]
    @thisusername = params["usernamefield"]
    @thissourcehostname = params["sourcehostnamefield"]
    # mixed field could be IP or host
    @thissource_host = params["source_hostfield"]
end


# Read filtering lists
@linwellknown_list = IO.readlines("/opt/seld/conf/lists/linwellknown_list.txt",chomp: true)

# Extract deidentification keys from yaml file
File.open('/opt/seld/api/sitekeyset.yml') {
    |kv| @keyset = YAML.load(kv)
}

# Extract the variables from the keyset, define rotor order, 
# return positional array, cast integers for rotors, seed and random, just in case the yaml source has strings
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


# According to logstash documentation these values are loaded at startup.
    # Define additional network ranges that would require deidentification ( E.G., an organization's public space)
    @net192 = IPAddr.new("192.168.0.0/16")
    @net172 = IPAddr.new("172.16.0.0/12")
    @net10 = IPAddr.new("10.0.0.0/8")
    # leaveing 10/8 out FTM so for testing
    # FPE web service  URL, hardcoded to use the encrypt function
    @fpeapiaccturi = 'http://127.0.0.1:5020/api/v1/updatedata?encname='
    @fpeapihostdomuri = 'http://127.0.0.1:5023/api/v1/updatedata?encdotdelimalpha='


#####################  IP deidentification processing  #####################################################

# first confirm IP string is a valid IP4 address, then test against all networks that must be deidneitfied
# There is an IPAddr method called private that can do this as well, but would not allow the exclusion
# of external perimeter addresses or the use of public ranges within internal networks.
def testiprange(ipstring)
    deidentify = false
    if ipstring.match(/-/)
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
        puts("Invalid IP address: "+ ipstring)
        #File.open('/opt/seld/debuglogs/linuxauth-ip-error-data-debug.log','a') { |fh| fh.puts ipstring)}
    end
    return deidentify
end


# The second offset is bits 8-16 in RFC1918 trickier to calculate where the rollover is
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
    # get offset rotor values, and entropy seed and random  but if keyset incomplete return original IP 
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
        #Get the numeric value of the dotted quad
        #ipintval = ip4obj.to_i
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
            # Add second to external 
            deidentintval  = deidentintval + rotor1
        end
    end
    # RFC1918 /8 
    if dqarray[0].to_i == 10
        #Get the numeric value of the dotted quad
        #ipintval = ip4obj.to_i
        maskstr=dqarray[0,3].join('.')+'.0'
        ip4maskstrobj = IPAddr.new(maskstr)
        ipintval = ip4maskstrobj.to_i
        # Min and max for 10.0.0.0/8
        imin=167772160
        imax=184549375
        # flip variable to change whether an octet is added or subtracted ( further obfuscation option)
        if tks[3]     
            # rotor 2 value 257 to 1033 * 256( all bits in fourth octet ), 
            # Multiple by the seed to increase distance from original IP, aslo add in site random for more entropy
            of2=((tks[1] * 256) * tks[2] + dqarray[1].to_i ) + (tks[4] *  tks[2])   
            deidentintval = setrotor2(ipintval,of2,imin,imax)
            #Adjust the value for the 4th octet (  rotor 1)
            rotor1 = (dqarray[3].to_i + ( (tks[0] * 3 ) - (tks[4]/tks[2]) )) % 256
            # Add outside rotor to deidentified second and third octets + prefix 
            deidentintval  = deidentintval + rotor1
        else
            # send offet negative
            of2=( ((tks[1] * 256) * tks[2] + dqarray[1].to_i ) * -1)  + (tks[4] * tks[2] )
            deidentintval = setrotor2(ipintval,of2,imin,imax)
            #Adjust the value for the 4th octet (  rotor 1)
            rotor1 = (dqarray[3].to_i - ( (tks[0] * 3 ) + (tks[4]/tks[2]) )) % 256
            # Add second to external 
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

# Modify the source port using the key values and seed to obscure the source port 
# recorded in the log connection since that is an element an attacker can observe and potentially control
# Hard coding additional mulitpliers to increase the gap and bring the +/- outcomes closer together
def deidentifyportdata(ipport,tksp)
    if ipport.match(/-/)
        return ipport
    end
    # Anchors required to avoid returning exact port attacker sent. By default ruby match is greedy
    if ipport.match(/^0$/)
        return ipport
    end
    # get offest rotors and seed, if keyset incomplete return original IP port
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

def testsrchost(srchoststr)
    # handle the processing depending whether it is an IP or FQDN 
    if srchoststr.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)
        if testiprange(srchoststr)
            # pass eventip to deident module
            deidentipstr=deidentifyipdata(srchoststr,@sitekeyset)
            thissrchost = deidentipstr
        else
            thissrchost = srchoststr
        end
    else
        thissrchost=deidentifyhostdata(srchoststr)
    end
    #
    return thissrchost
end 


#####################################  Account deidentification processing ###################################

# Ignore all usernames that match Linux reseved accounts and common lists used in cred stuffing & spraying
def testlinwellknown(acctname)
    revmatch=false
    @linwellknown_list.each do |wkname|
      if acctname.downcase == wkname.downcase
        wkmatch = true
        revmatch= true
      end
      break if wkmatch
    end
    return revmatch
  end


# This method accepts a single input, the data string to be encrypted, and returns a single string of the same length and character set 
# currently making a rest API call to a python webservice as there were no format preserving encryption implementations found in native ruby 
def deidentifyacctdata(thisacct)
    # Adding paddding/truncating method to protect FPE algorithm
    thisacct = testnamesize(thisacct)
    requesturi = URI.parse(@fpeapiaccturi + thisacct)
    requestresponse = Net::HTTP.get_response(requesturi)
    # Confirm results were recieved
    if requestresponse.code == '200'
        restdata = JSON.parse(requestresponse.body)
        encresult = restdata['fpedata']
    else
        encresult = thisacct + '_df'
    end

    return encresult
end

def deidentifyhostdata(thishost)    
    # Adding paddding/truncating method to protect FPE algorithm
    thishost = testnamesize(thishost)
    requesturi = URI.parse(@fpeapihostdomuri + thishost)
    requestresponse = Net::HTTP.get_response(requesturi)
    # Confirm results were recieved
    if requestresponse.code == '200'
        restdata = JSON.parse(requestresponse.body)
        encresult = restdata['fpedata']
    else
        encresult = thishost + '_df'
    end
  
    return encresult
  end


# Format preserving encryption needs a minimum size data value to perfom the algorithm
# the python ff3 implmentation of FPE requires a minimum of 4 chars and max of 30,
# this function adjusts if required but data strings between 4 & 30 chars pass through
def testnamesize(thisname)
    if thisname.size() < 4
       padlength = 4 - thisname.size()
       padname = thisname.rjust(4,"_")
       return padname
    elsif thisname.size() > 30
        truncname = thisname[0..29]
        return truncname 
    else
        return thisname
  end 
end




# retrieve the address included in the event, ( source, destination, other)
# confirm if the IP is within one the subnets identifed for deidentification
def filter(event)
    # First check for IP addresses, almost all cyber event data will have IP address information
    ipaddress = event.get(@thisipaddress)
    portnumber = event.get(@thisportnumber)
    # Test for multiple conditions, in list of sensitive IP subnets? Blank value or loopback?
    if !ipaddress.nil?
        if testiprange(ipaddress)
            # pass eventip to deident module
            deidentipstr=deidentifyipdata(ipaddress,@sitekeyset)
            if !portnumber.nil?
                deidentportstr=deidentifyportdata(portnumber,@sitekeyset)
                event.set(@thisportnumber, deidentportstr)
            end
        else
            deidentipstr = ipaddress
            # offset the port value since an external address would not be deidentified
            # but an adversary could still track source port and time provide external context
            # for a reidentification attack
            if !portnumber.nil?
                deidentportstr = deidentifyportdata(portnumber,@sitekeyset)
                event.set(@thisportnumber, deidentportstr)
            end
        end # end IP testing
        ###################  Send back updated IP field #################
        event.set(@thisipaddress, deidentipstr)
    end
        
    # Check for usernames in event, dependent on grok results but will create a field called user_name if parsing was successful
    # user_name then must be checked to determine if it needs to be deidentified, SELD will retain common operating system usernames
    # like root, admin, oracle, postgres etc, since they are not unique to an organization
    # Note, all usernames will be deidentifed, regardless of the whether the IP is being deidentified or not. 
    acctname = event.get(@thisusername)
    if !acctname.nil? && acctname.size() > 3
        if !testlinwellknown(acctname)
            encdata = deidentifyacctdata(acctname)
            if !encdata.nil? && encdata.size() > 3
                event.set(@thisusername,encdata)
            end
        end
    end
    # Almost all log sources will have at least the system host name recorded, if present this value should be deidentified.
    hostname = event.get(@thishostname)
    if !hostname.nil? && hostname.size() > 0
        encdata = deidentifyhostdata(hostname)
        if !encdata.nil? && encdata.size() > 0
            event.set(@thishostname,encdata)
        end
    end
    sourcehostname = event.get(@thissourcehostname)
    if !sourcehostname.nil? && sourcehostname.size() > 0
        encdata = deidentifyhostdata(sourcehostname)
        if !encdata.nil? && encdata.size() > 0
            event.set(@thissourcehostname,encdata)
        end
    end
    # Some logs will have and IP or FQDN in the same place, need to deidentify differently dependding on type
    src_host = event.get(@thissource_host)
    if !src_host.nil? && src_host.size() > 0
        deidentsrc_host = testsrchost(src_host)
        event.set(@thissource_host,deidentsrc_host)
    end
    #  End of the ruby event filter
    return[event]
end