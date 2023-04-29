# Author: Doug Leece   dleece @ firstfiretech dot ca
# Feb 23/2023  RFC5424 PFSense event deidentification module


# Ruby gem imports
require 'ipaddr'
require 'net/http'
require 'json'
require 'yaml'



# According to logstash documentation these values are loaded at startup.
    # FPE web service  URL, hardcoded to use the encrypt function
    @fpeapiuri = 'http://127.0.0.1:5021/api/v1/updatedata?encdotdelimalpha='
def register(params)
    @thishostname = params["hostnamefield"]
    @thisruleevent = params["ruleeventfield"]
end

#############################  IP & Port deidentification #######################
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

# This method accepts a single input, the data string to be encrypted, and returns a single string of the same length and character set 
# currently making a rest API call to a python webservice as there were no format preserving encryption implementations found in native ruby
# Moved dot delimiting format preservation into rest API by adding another function to the service 
def deidentifyhostnamedata(thostname)
    thostname = testnamesize(thostname)  
    requesturi = URI.parse(@fpeapiuri + thostname)
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


# IP Ranges that should be deidentified, ( can include non-rfc1918 if needed)
@net192 = IPAddr.new("192.168.0.0/16")
@net172 = IPAddr.new("172.16.0.0/12")
@net10 = IPAddr.new("10.0.0.0/8")

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
            of2=((tks[1] * 256)  / tks[2]) + tks[4]    
            deidentintval = setrotor2(ipintval,of2,imin,imax)
            #Adjust the value for the 4th octet ( rotor 1)
            rotor1 = (dqarray[3].to_i + ( (tks[0] * 3 ) - (tks[4]/tks[2]) )) % 256
            # Add outside rotor to deidentified third octet + prefix 
            deidentintval  = deidentintval + rotor1
        else
            # send offet negative
            of2=( ((tks[1] * 256) / tks[2]) * -1)  + tks[4]
            deidentintval = setrotor2(ipintval,of2,imin,imax)
            #Adjust the value for the 4th octet (  rotor 1)
            rotor1 = (dqarray[3].to_i - ( (tks[0] * 3 ) + (tks[4]/tks[2]) )) % 256
            # Add prefix and deidnetifed middle octet to rotated 3rd octet
            deidentintval  = deidentintval + rotor1
        end
    end
    # RFC1918 /8 
    if dqarray[0].to_i == 10
        #Get the numeric value of the dotted quad from the first three octets
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
            # Add prefix and deidnetifed middle octets to rotated 3rd octet 
            deidentintval  = deidentintval + rotor1
        end
    end
    # RFC 1918 / 12   
    if dqarray[0].to_i == 172
        #Get the numeric value of the dotted quad
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
            # Add prefix and deidnetifed middle octet to rotated 3rd octet 
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

# Extract IP and port info from the rule data and deidentifiy as needed
def deidentifyruleeventdata(ruleevtcsv)
    fwrearray=ruleevtcsv.split(',')
    # Deal with source IP and port
    if testiprange(fwrearray[18])
        deidentsrcip=deidentifyipdata(fwrearray[18],@sitekeyset)
        deidentsrcport=deidentifyportdata(fwrearray[20],@sitekeyset)
        fwrearray[18]=deidentsrcip
        fwrearray[20]=deidentsrcport
    else
        deidentsrcport=deidentifyportdata(fwrearray[20],@sitekeyset)
        fwrearray[20]=deidentsrcport
    end
    # test destination ip, destination port should remain original
    if testiprange(fwrearray[19])
        #puts("deident target side:" + fwrearray[19])
        deidentdstip=deidentifyipdata(fwrearray[19],@sitekeyset)
        fwrearray[19]=deidentdstip
    end
    return fwrearray.join(',')
end


#####################   Hostname deidentification #################################

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


# Read the message file from each log record and remove visual formatting with single spaces
def filter(event)
    hostname = event.get(@thishostname)
    rulefwevent = event.get(@thisruleevent)

    # check for hostname field not being blank,  nil in rfc5424 is a - character
    if !hostname.nil? && hostname.size() > 1
        enchostname = deidentifyhostnamedata(hostname)
        # use the rest service to do this, send complete string
        if !enchostname.nil? && enchostname.size() > 3 
          event.set(@thishostname,enchostname)
        end 
    else
        File.open('/opt/seld/deblogs/seld_fwsyslog-debug.log','a') { |fh| fh.puts "hostname-extraction-failure:" + event}
    end
    if !rulefwevent.nil? && rulefwevent.size() > 1
        deidentrfwe = deidentifyruleeventdata(rulefwevent)
        # use the rest service to do this, send complete string
        if !deidentrfwe.nil? && deidentrfwe.size() > 3 
          event.set(@thisruleevent,deidentrfwe)
        end 
    else
        File.open('/opt/seld/debuglogs/seld_fwsyslog-debug.log','a') { |fh| fh.puts "fw_rule-extraction-failure:" + event}
    end

    #  End of the ruby event filter
    return[event]
end