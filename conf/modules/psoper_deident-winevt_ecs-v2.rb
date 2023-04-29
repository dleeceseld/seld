# Author: Doug Leece   dleece @ firstfiretech dot ca
# Jan 27/2023  V1 Updated module for ruby code to be called from a logstash pipeline:
#             - intended for windows event log records that contain a computer name or username that may need to be deidentifed but no IP was observed
#             - Queries the event API to retrieve specifc data elements within each log event (line)
#             - version 1 deidentifies computer names and accepts the computer_name field extracted using JSON codec 
#             - This module relies on format preserving encryption so computer host names could be reidentified if 
#               third party analysis identifes an potential security incident.
#              - Also need to address fully qualified domain names  
#  Jan 4/2023 Modified to use Elastic Common Schema
#  Mar 23/2023 Copy of acctname_deident tailored for powershell script block logging output            
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
#require 'ipaddr'
require 'net/http'
require 'json'

#@sensitivenames = IO.readlines("/opt/seld/conf/sensitivenames.txt",chomp: true)
@domain_list = IO.readlines("/opt/seld/conf/lists/domain_list.txt",chomp: true)
@winreserved_list = IO.readlines("/opt/seld/conf/lists/winreserved_list.txt",chomp: true)
#Ensure all entries on the list being with ^ then the prefix, also observe case, ^dwm-  and ^DWM- would be differnt
@winsvcs_list = IO.readlines("/opt/seld/conf/lists/winsvcs_list.txt",chomp: true)

# According to logstash documentation these values are loaded at startup.
    # FPE web service  URL, hardcoded to use the encrypt function
    @fpeapiaccturi = 'http://127.0.0.1:5020/api/v1/updatedata?encatdelimalpha='
    #  Required for SID deidentification
    @fpeapidigituri = 'http://127.0.0.1:5022/api/v1/updatedata?encdashdelimdigit='
    #  Required for domain idenfication ( may contain FQDN )
    @fpeapidomainuri = 'http://127.0.0.1:5023/api/v1/updatedata?encdotdelimalpha='
# Define the JSON path to target user name and subject user name
def register(params)
    @thisuseridentifierfield = params["useridentifierfield"]
    @thisusernamefield = params["usernamefield"]
    @thisuserdomainfield = params["userdomainfield"]
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
    requesturi = URI.parse(@fpeapiaccturi + thisname)
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
def getencacct(evalname)
  # Moved this test back to inital field checking that calls this method. 
  # Opens a hole for people naming accounts with a single number or letter but assuming that is rare
  if evalname == "-"
    return evalname
  end
  if evalname.match(/\S+\$/)
      acctportion = evalname.match(/(\S+)\$/).captures[0]
      encacct = deidentifyaccountdata(acctportion)
      encacct = encacct + "$"
      return encacct
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
# ---------------------------   SID deidentification ----------------------------------------------------
# This method accepts a single input, the data string to be encrypted, and returns a single string of the same length and character set 
# currently making a rest API call to a python webservice as there were no format preserving encryption implementations found in native ruby 
def deidentifydigitdata(thisdigits)
  requesturi = URI.parse(@fpeapidigituri + thisdigits)
  requestresponse = Net::HTTP.get_response(requesturi)
  # Confirm results were recieved
  if requestresponse.code == '200'
      restdata = JSON.parse(requestresponse.body)
      # to-do, refactor so it's alpha or digit string generic
      encresult = restdata['fpedata']
  else
      encresult = ''
  end
  return encresult
end

# Format preserving encryption needs a minimum size data value to perfom the algorithm
# the python ff3 implmentation of FPE radix 10 requires a minimum of 10 chars and max of 30,
# this function adjusts if required but data strings between 4 & 30 chars pass through
def testdigitsize(thisdigits)
  if thisdigits.size() < 6
     paddigits = thisdigits.rjust(6,"0")
     return paddigits
  elsif thisdigits.size() > 30
      truncdigits = thisdigit[0..29]
      return truncdigits 
  else
      return thisdigits
  end 
end


# test the SID to determine if it's a domain or user value, very important to investigations
# split the $ character from the name, encrypt then reassemble and return
def encsid(evalsid)
  #
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
  end

end

#--------------------------- Domain deidentification ------------------------------------
def deidentifydomainnamedata(thisdomainname)    
  requesturi = URI.parse(@fpeapidomainuri + thisdomainname)
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

# When data field containing domain is populated, test to see if it needs deidentification, pass to rest service as needed.
def getencdom(psoudom)
  enctdomname = '' # empty string to allow early exit from domain search
  # Test to see if if it an FQDN or domain name, if not just deidentify the single name
  if psoudom.match(/\S+\.\S+/)
    @domain_list.each do |thisdom|
      if testregex(thisdom,psoudom.downcase())
        enctdomname = deidentifydomainnamedata(psoudom)
      end
      break if enctdomname.size() > 3
    end  # end of first each do
  else
    @domain_list.each do |thisdom|
      domelem = thisdom.split('.')[0]
      if testregex(domelem,psoudom.downcase())
        enctdomname = deidentifydomainnamedata(psoudom)
      end
      break if enctdomname.size() > 3
    end  # end of second each do
  end  # end of dom regex test
  #
  if enctdomname.size() > 3
    return enctdomname
  else
    return psoudom
  end
end  # End encdomdata



def filter(event)
    # Almost all log sources will have at least one account name recorded, if present this value should be deidentified.
    psouserident = event.get(@thisuseridentifierfield)
    psousername = event.get(@thisusernamefield)
    psouserdomain = event.get(@thisuserdomainfield)
    
    # --  user identifier (SID) -----------
    if !psouserident.nil? && psouserident.size() > 36
      deidentpsouserident = encsid(psouserident)
      event.set(@thisuseridentifierfield, deidentpsouserident)
    end
    # Ignore all dash values and empty fields. 
    # --  user name -----------
    if !psousername.nil? && psousername.size() > 1
      deidentpsousername = getencacct(psousername)
      event.set(@thisusernamefield, deidentpsousername)
    end
    # -- user domain  -------------------
    if !psouserdomain.nil? && psouserdomain.size() > 1
      deidentpsouserdomain = getencdom(psouserdomain)
      event.set(@thisuserdomainfield, deidentpsouserdomain)
    end
    
    
     


    ######################### return updated record content ############################## 
    return[event]
end #  End of the ruby event filter