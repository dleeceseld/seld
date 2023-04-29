# Author: Doug Leece   dleece @ firstfiretech dot ca
# Jan 9/2023  V0 fourth module for ruby code to be called from a logstash pipeline:
#             - intended for log lines that contain multiple usernames that may need to be deidentifed
#             - Queries the event API to retrieve specifc data elements within each log event (line)
#             - Each extra name is tested for length, confirmed not on don't encrypt list and passed to FPE rest service
#
#             - This module relies on format preserving encryption so usernames could be reidentified if 
#               third party analysis identifes an potential security incident.  
#  April 10/2023  debuging led to json array name being wrong. Removed most of the print outs               
#

require 'net/http'
require 'json'

# According to logstash documentation these values are loaded at startup.
    # FPE web service  URL, hardcoded to use the encrypt function
    @fpeapiaccturi = 'http://127.0.0.1:5020/api/v1/updatedata?encname='
        
    
# Read filtering lists
@linwellknown_list = IO.readlines("/opt/seld/conf/lists/linwellknown_list.txt",chomp: true)


# This method accepts a single input, the data string to be encrypted, and returns a single string of the same length and character set 
# currently making a rest API call to a python webservice as there were no format preserving encryption implementations found in native ruby 
def deidentifynamedata(thisname)
    # Adding paddding/truncating method to protect FPE algorithm
    thisname = testnamesize(thisname)
    requesturi = URI.parse(@fpeapiaccturi + thisname)
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

# Method accepts an array of clear text usernames, passes each to validation and FPE methods and returns results
def testunamearray(thisarray)
    encnamearray=["none"]
    for uname in thisarray
        if !testlinwellknown(uname)
            encdata = deidentifynamedata(uname)
            if !encdata.nil? && encdata.size() > 0
                encnamearray.append(encdata)
            end
        end
    end
    return encnamearray
end


def filter(event)
    #File.open('/var/tmp/seld_muser-debug.log','a') { |fh| fh.puts event.get("message")}
    cnt=1
    unamev = "user.name" + cnt.to_s
    uname = event.get(unamev)
    #File.open('/var/tmp/seld_muser-debug.log','a') { |fh| fh.puts uname }
    if !uname.nil? && uname.size > 0
        allnames = [uname]
        # after first username is retreived the object can be used to drive a while loop, 
        # the respective counter value corresponds with the extension of the username.  
        # Caveat, this is reliant on proper parsing of additional usernames and ensuring continuous numeric sequence)
        while !uname.nil?
            cnt+=1
            unamev = "user.name" + cnt.to_s
            uname = event.get(unamev)
            if !uname.nil? && uname.size > 0
                #File.open('/var/tmp/seld_muser-debug.log','a') { |fh| fh.puts uname }
                allnames.append(uname)
            end
        end
    end
    #Test usernames, format and deidentify as required
    deidentarray=testunamearray(allnames)
    # Write the deidentified usernames into named fields, need to provide the correct field name
    # count backward through the array and stop at 1 since the first multi-username would alwasy be user.name1
    enccnt = deidentarray.size - 1  # Array counting starts at 0 but size starts at 1
    while enccnt >= 1
        deidentname = deidentarray[enccnt]
        fieldname = "user.name" + enccnt.to_s
        event.set(fieldname,deidentname) 
        enccnt -=1
    end
    #  End of the ruby event filter
    return[event]
end