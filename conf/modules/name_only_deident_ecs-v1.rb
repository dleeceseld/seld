# Author: Doug Leece   dleece @ firstfiretech dot ca
# Dec 29/2022  V0 Second module for ruby code to be called from a logstash pipeline:
#             - intended for log lines that contain a computer name or username that may need to be deidentifed but no IP was observed
#             - Queries the event API to retrieve specifc data elements within each log event (line)
#             - version 0 deidentifies usernames and accepts the user_name field valid based on GROK parsing 
#             - This module relies on format preserving encryption so usernames and computer host names could be reidentified if 
#               third party analysis identifes an potential security incident.  
#  Jan 4/2023 Modified to use Elastic Common Schema             
#  Feb 28/2023 Moved host and name deident to seperate services to limit serialization,  converting IP module as well
# 
#  Apr 7       - Added new parser for anotehr IOA variant, moved hostname check to second API service, 
# Debug functions append the original log line and the processed/not processed value to a temporary log file.
# Marked in the code,  comment out when running performance tests or production

# Currently avoiding the installation of ruby gems outside of the logstash development tree, best chance of maintaining 
# functionality in future logstash versions.
#
# -  net/http and json are  gems included with the logstash deployment and required for rest API
#    connections. This allows certain log enrichment functions to be moved to a web service if they are
#    are not readily avaliable with the default ruby libraries,  E.G., format preserving encryption 

# Ruby gem imports
#require 'ipaddr'
require 'net/http'
require 'json'


# According to logstash documentation these values are loaded at startup.
    # FPE web service  URL, hardcoded to use the encrypt function
    @fpeapiaccturi = 'http://127.0.0.1:5020/api/v1/updatedata?encname='
    @fpeapihostdomuri = 'http://127.0.0.1:5033/api/v1/updatedata?encdotdelimalpha='

def register(params)
    @thisusername = params["usernamefield"]
    @thishostname = params["hostnamefield"]
end

# Read filtering lists
@linwellknown_list = IO.readlines("/opt/seld/conf/lists/linwellknown_list.txt",chomp: true)


#############################   Account name processing ###################################################
# Ignore all usernames that match Linux reseved accounts and common lists used in cred stuffing & sparaying
def testlinwellknown(acctname)
  revmatch=false
  @linwellknown_list.each do |wkname|
    if acctname.downcase == wkname.downcase
      wkmatch = true
      revmatch=true
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
    username = event.get(@thisusername)
    if !username.nil? && username.size() > 0
        # username isn't a common OS or opportunistic attack target
        if !testlinwellknown(username)
            encdata = deidentifyacctdata(username)
            if !encdata.nil? && encdata.size() > 0
                event.set(@thisusername,encdata)
            end
        end
    end
    #
    # Almost all log sources will have at least the system host name recorded, if present this value should be deidentified.
    hostname = event.get(@thishostname)
    if !hostname.nil? && hostname.size() > 0
        encdata = deidentifyhostdata(hostname)
        if !encdata.nil? && encdata.size() > 0
            event.set(@thishostname,encdata)
        end
    end
    #  End of the ruby event filter
    return[event]
end