# Author: Doug Leece   dleece @ firstfiretech dot ca
# Jan 27/2023  V1 Updated module for ruby code to be called from a logstash pipeline:
#             - intended for windows event log records that contain a computer name or username that may need to be deidentifed but no IP was observed
#             - Queries the event API to retrieve specifc data elements within each log event (line)
#             - version 1 deidentifies computer names and accepts the computer_name field extracted using JSON codec 
#             - This module relies on format preserving encryption so computer host names could be reidentified if 
#               third party analysis identifes an potential security incident.
#              - Also need to address fully qualified domain names  
#  Jan 4/2023 Modified to use Elastic Common Schema 
#  Apr 2/2023 Refactoring, list locations, comment and cruft cleanup            
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

@winreserved_list = IO.readlines("/opt/seld/conf/lists/winreserved_list.txt",chomp: true)
#Ensure all entries on the list being with ^ then the prefix, also observe case, ^dwm-  and ^DWM- would be differnt
@winsvcs_list = IO.readlines("/opt/seld/conf/lists/winsvcs_list.txt",chomp: true)

# According to logstash documentation these values are loaded at startup.
    # FPE web service  URL, hardcoded to use the encrypt function
    @fpeapiuri = 'http://127.0.0.1:5020/api/v1/updatedata?encatdelimalpha='
# Define the JSON path to target user name and subject user name
def register(params)
    @thistuname = params["tunamefield"]
    @thissuname = params["sunamefield"]
    @thistsname = params["tsnamefield"]
    @thistinfo = params["tinfofield"]
    @thissvcname = params["svcnamefield"]
    @thistouname = params["tounamefield"]
    @thissamname = params["samnamefield"]
end


# This method accepts a single input, the data string to be encrypted, and returns a single string of the same length and character set 
# currently making a rest API call to a python webservice as there were no format preserving encryption implementations found in native ruby 
def deidentifyaccountdata(thisname)
    encresult = ''
    # first test for reserved usernames and exit early, returning the original name
    if testwinreserved(thisname)
      return thisname
    end
    # Next test for OS built in and common service accounts that have known prefix but variable suffix 
    # EG DWM-1, DWM-2  etc
    if testwinservices(thisname)
      return thisname
    end
    # Adding paddding/truncating method to protect FPE algorithm
    thisname = testnamesize(thisname)
    requesturi = URI.parse(@fpeapiuri + thisname)
    requestresponse = Net::HTTP.get_response(requesturi)
    # Confirm results were recieved
    if requestresponse.code == '200'
        restdata = JSON.parse(requestresponse.body)
        encresult = restdata['fpedata']
    else
        # handle reset service down or failing
        encresult = ''
    end

    return encresult
end

# Ignore all usernames that match Windows reseved words or well known accounts
def testwinreserved(acctname)
  rsvmatch=false
  @winreserved_list.each do |rsvname|
    if acctname.downcase == rsvname.downcase
      rsvmatch = true
    end
    break if rsvmatch
  end
  return rsvmatch
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


# pass the individual names from a list to perform a regex check, return a boolean
def testregex(listelement,evalstr)
  if evalstr.match(listelement)
    return true
  else
      return false
  end
end

# test the username to determine if it's a computer account, very important to investigations
# split the $ character from the name, encrypt then reassemble and return
# Also seperate account / domain names into two parts.  
def getencacct(evalname)
  # Moved this test back to inital field checking that calls this method. 
  # Opens a hole for people naming accounts with a single number or letter but assuming that is rare
  if evalname == "-"
    return evalname
  end
  if rexobj=evalname.match(/(\S+)?\$/)
    #acctportion = evalname.match(/(\S+)\$/).captures[0]
    acctportion = rexobj.captures[0]
    encacct = deidentifyaccountdata(acctportion)
    encacct = encacct + "$"
    return encacct
  elsif rexobj=evalname.match(/(\S+)?\/(\S+)/)
    acctportion=rexobj.captures()[0]
    domportion=rexobj.captures()[1]
    encacct = deidentifyaccountdata(acctportion)
    encdom = deidentifyaccountdata(domportion)
    encacctdom = encacct + "/" + encdom
    return encacctdom
  else 
    encacct = deidentifyaccountdata(evalname)
    return encacct
  end
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
    # Almost all log sources will have at least one account name recorded, if present this value should be deidentified.
    tgtuname = event.get(@thistuname)
    subuname = event.get(@thissuname)
    tgtsname = event.get(@thistsname)
    tgtinfo = event.get(@thistinfo)
    svcname = event.get(@thissvcname)
    tgtouname = event.get(@thistouname)
    samname = event.get(@thissamname)

    # Ignore all dash values and empty fields. 
    # -- target username -----------
    if !tgtuname.nil? && tgtuname.size() > 1
      deidenttgtname = getencacct(tgtuname)
      event.set(@thistuname, deidenttgtname)
    end
    # -- subject username -------------------
    if !subuname.nil? && subuname.size() > 1
      deidentsubname = getencacct(subuname)
      event.set(@thissuname, deidentsubname)
    end
    # -- service username -------------------
    if !svcname.nil? && svcname.size() > 1
      deidentsvcname = getencacct(svcname)
      event.set(@thissvcname, deidentsvcname)
    end
    # -- target server name -------------------
    if !tgtsname.nil? && tgtsname.size() > 1
      deidenttgtsname = getencacct(tgtsname)
      event.set(@thistsname, deidenttgtsname)
    end
    # -- target info name -------------------
    if !tgtinfo.nil? && tgtinfo.size() > 1
      deidenttgtinfo = getencacct(tgtinfo)
      event.set(@thistinfo, deidenttgtinfo)
    end
    # -- target outbound username -------------------
    if !tgtouname.nil? && tgtouname.size() > 1
      deidenttgtouname = getencacct(tgtouname)
      event.set(@thistouname, deidenttgtouname)
    end
    # -- sam account name / local username -------------------
    if !samname.nil? && samname.size() > 1
      deidentsamname = getencacct(samname)
      event.set(@thissamname, deidentsamname)
    end


    ######################### return updated record content ############################## 
    return[event]
end #  End of the ruby event filter