# Author: Doug Leece   dleece @ firstfiretech dot ca
# Apr 3/2023  V1 Additional module to deal with group modifications,to be called from a logstash pipeline:
#             - intended for windows event log records that contain modifications to groups
#             - User SIDS, user names and the admins making changes must be deidentified,
#             - Inital version will not attempt to deidentify group names, could be some internal info here
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

@winreserved_list = IO.readlines("/opt/seld/conf/lists/winreserved_list.txt",chomp: true)
#Ensure all entries on the list being with ^ then the prefix, also observe case, ^dwm-  and ^DWM- would be differnt
@winsvcs_list = IO.readlines("/opt/seld/conf/lists/winsvcs_list.txt",chomp: true)

# According to logstash documentation these values are loaded at startup.
    # FPE web service  URL, hardcoded to use the encrypt function
    @fpeapiuri = 'http://127.0.0.1:5020/api/v1/updatedata?encatdelimalpha='
    # rest service for encrypting hosts and domains
    @fpeapihostdomuri = 'http://127.0.0.1:5023/api/v1/updatedata?encdotdelimalpha='
    # Second API URL for SID deident
    @fpeapidigituri = 'http://127.0.0.1:5022/api/v1/updatedata?encdashdelimdigit='

# Define the JSON path to target user name and subject user name
def register(params)
    @thismembersid = params["membersidfield"]
    @thismembername = params["membernamefield"]
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

# test the username to determine if it's a computer account, very important to investigations
# split the $ character from the name, encrypt then reassemble and return
# Also seperate account / domain names into two parts.  
def getencacct(evalname)
  # Moved this test back to inital field checking that calls this method. 
  # Opens a hole for people naming accounts with a single number or letter but assuming that is rare
  #if evalname == "-"
  #  return evalname
  #end
  if rexobj=evalname.match(/(\S+)?\$/)
    #acctportion = evalname.match(/(\S+)\$/).captures[0]
    acctportion = rexobj.captures[0]
    encacct = deidentifyaccountdata(acctportion)
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
    encdom = deidentifyaccountdata(domportion)
    encacctdom = encacct + "/" + encdom
    return encacctdom
  else 
    encacct = deidentifyaccountdata(evalname)
    return encacct
  end
end



#################################  SID testing and Deidentification ##########################
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
def getencsid(evalsid)
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


##########################   Event API  Get/Set ###################
def filter(event)
    # Specific fields appearing in group changes,in addition to target and subject fields.
    membersid = event.get(@thismembersid)
    membername = event.get(@thismembername)
  
    # Ignore all dash values and empty fields. 
    # -- member sid  -----------
    if !membersid.nil? && membersid.size() > 1
      deidentmembersid = getencsid(membersid)
      event.set(@thismembersid, deidentmembersid)
    end
    # -- member name -------------------
    if !membername.nil? && membername.size() > 1
      deidentmembername = getencacct(membername)
      event.set(@thismembername, deidentmembername)
    end
    
    ######################### return updated record content ############################## 
    return[event]
end #  End of the ruby event filter