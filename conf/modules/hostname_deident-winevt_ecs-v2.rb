# Author: Doug Leece   dleece @ firstfiretech dot ca
# Jan 27/2023  V1 Updated module for ruby code to be called from a logstash pipeline:
#             - intended for windows event log records that contain a computer name or username that may need to be deidentifed but no IP was observed
#             - Queries the event API to retrieve specifc data elements within each log event (line)
#             - version 1 deidentifies computer names and accepts the computer_name field extracted using JSON codec 
#             - This module relies on format preserving encryption so computer host names could be reidentified if 
#               third party analysis identifes an potential security incident.
#              - Also need to address fully qualified domain names  
#  Jan 4/2023 Modified to use Elastic Common Schema    
# Feb 5/2023   Modified to make a single JSON request for encryption. Host or domain name sent as FQDN
#                       
#
# Debug functions append the original log line and the processed/not processed value to a temporary log file.
# Marked in the code,  comment out when running performance tests or production

# Currently avoiding the installation of ruby gems outside of the logstash development tree, best chance of maintaining 
# functionality in future logstash versions.
#
# -  net/http and json are  gems included with the logstash deployment and required for rest API
#    connections. This allows certain log enrichment functions to be moved to a web service if they are
#    are not readily avaliable with the default ruby libraries,  E.G., format preserving encryption 

# Ruby gem imports
require 'net/http'
require 'json'


# According to logstash documentation these values are loaded at startup.
    # FPE web service  URL, hardcoded to use the encrypt function
    @fpeapiuri = 'http://127.0.0.1:5021/api/v1/updatedata?encdotdelimalpha='
def register(params)
    @thiscompname = params["compnamefield"]
    @thiswkstnname = params["wkstnnamefield"]
    @thiswkstn = params["wkstnfield"]
end


# This method accepts a single input, the data string to be encrypted, and returns a single string of the same length and character set 
# currently making a rest API call to a python webservice as there were no format preserving encryption implementations found in native ruby
# Moved dot delimiting format preservation into rest API by adding another function to the service 
def deidentifyhostnamedata(thishostname)  
    requesturi = URI.parse(@fpeapiuri + thishostname)
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

# pass the individual names from a list to perform a regex check, return a boolean
def testregex(listelement,evalstr)
  if evalstr.match(listelement)
    return true
  else
      return false
  end
end

#Split the domain into single names, encrypt each individually then reconstruct the domain or fqdn
def encfqdn(fqdn)
  encdomelem = Array.new
  domelem = fqdn.split('.')
  domelem.each do |nameelem|
    encelem = deidentifynamedata(nameelem)
    encdomelem.append(encelem)
  end
  return(encdomelem.join('.'))
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


def filter(event)
    # Almost all log sources will have at least the system host name recorded, if present this value should be deidentified.
    enccompname = '' # empty string to multiple hostname formats to be checked and single write at end
    compname = event.get(@thiscompname)
    wkstnname = event.get(@thiswkstnname)
    wkstn = event.get(@thiswkstn)

    # Ignore all blank and single dash values for computer, Adjust if people start naming computers "1","2" & "3"
    if !compname.nil? && compname.size() > 1
      enccompname = deidentifyhostnamedata(compname)
      # use the rest service to do this, send complete string
      if !enccompname.nil? && enccompname.size() > 3 
        event.set(@thiscompname,enccompname)
      end
    end # end of compname check
    if !wkstnname.nil? && wkstnname.size() > 1
      enccompname = deidentifyhostnamedata(wkstnname)
      # use the rest service to do this, send complete string
      if !enccompname.nil? && enccompname.size() > 3 
        event.set(@thiswkstnname,enccompname)
      end
    end # end of workstation name check
    if !wkstn.nil? && wkstn.size() > 1
      enccompname = deidentifyhostnamedata(wkstn)
      # use the rest service to do this, send complete string
      if !enccompname.nil? && enccompname.size() > 3 
        event.set(@thiswkstn,enccompname)
      end
    end # end of workstation check

    ######################### return updated record content ############################## 
    return[event]
end #  End of the ruby event filter