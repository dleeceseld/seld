# Author: Doug Leece   dleece @ firstfiretech dot ca
# Jan 29/2023  V1 Updated module for ruby code to be called from a logstash pipeline:
#             - intended for windows event log records that contain one or more domain names that may need to be deidentifed
#             - Queries the event API to retrieve specifc data elements within each log event (line)
#             - version 1 deidentifies computer names and accepts the targetDomainName and SubjectDomainName fields extracted using JSON codec 
#             - This module relies on format preserving encryption so domain names could be reidentified if 
#               third party analysis identifes an potential security incident.
#              - Also need to address fully qualified domain names  
 
# Feb 5th  reconfigure domain name encryption to use one JSON request
# April 4th Adding additional check for domains not in windows reserved list 
#           using domprelist as a condtional lock to avoid testing windows reserved up front since these doms <  5%

# Currently avoiding the installation of ruby gems outside of the logstash development tree, best chance of maintaining 
# functionality in future logstash versions.
#
# -  net/http and json are  gems included with the logstash deployment and required for rest API
#    connections. This allows certain log enrichment functions to be moved to a web service if they are
#    are not readily avaliable with the default ruby libraries,  E.G., format preserving encryption 

# Ruby gem imports
require 'net/http'
require 'json'

@domain_list = IO.readlines("/opt/seld/conf/lists/domain_list.txt",chomp: true)
@winreserved_list = IO.readlines("/opt/seld/conf/lists/winreserved_list.txt",chomp: true)

# According to logstash documentation these values are loaded at startup.
    # FPE web service  URL, hardcoded to use the encrypt function
    @fpeapiuri = 'http://127.0.0.1:5023/api/v1/updatedata?encdotdelimalpha='
def register(params)
    @thistdname = params["tdname"]
    @thissdname = params["sdname"]
end


# This method accepts a single input, the data string to be encrypted, and returns a single string of the same length and character set 
# currently making a rest API call to a python webservice as there were no format preserving encryption implementations found in native ruby 
def deidentifydomainnamedata(thisdomainname)
    
  requesturi = URI.parse(@fpeapiuri + thisdomainname)
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
#def encfqdn(fqdn)
#  encdomelem = Array.new
#  domelem = fqdn.split('.')
#  domelem.each do |nameelem|
#    encelem = deidentifynamedata(nameelem)
#    encdomelem.append(encelem)
#  end
#  return(encdomelem.join('.'))
#end

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
    tgtdname = event.get(@thistdname)
    subdname = event.get(@thissdname)
    # -- target domain -------------
    if !tgtdname.nil? && tgtdname.size() > 1 
      enctdomname = '' # empty string to allow early exit from domain search
      # Test to see if if it an FQDN or domain name, if not just deidentify the single name
      if tgtdname.match(/\S+\.\S+/)
        @domain_list.each do |thisdom|
          if testregex(thisdom,tgtdname.downcase())
            enctdomname = deidentifydomainnamedata(tgtdname)
          end
          break if enctdomname.size() > 3
        end  # end of first each do
      else
        @domain_list.each do |thisdom|
          domelem = thisdom.split('.')[0]
          if testregex(domelem,tgtdname.downcase())
            enctdomname = deidentifydomainnamedata(tgtdname)
          end
          break if enctdomname.size() > 3
        end  # end of second each do
      end  # end of dom prelist regex test
      # Certain local functions and pre domain joined assets can have local workstation name as the domain
      # Domain can also be reserved windows names like workgroup, NT AUTHORITY etc, exclude these from encryption
      if enctdomname.size == 0
        winrsvname=false
        @winreserved_list.each do |thisrsv|
          if testregex(thisrsv.downcase(),tgtdname.downcase())
            winrsvname=true
          end
          break if winrsvname
        end
        # If domain value is not on prelist and not excluded because of reserved windows name, encrypt
        if !winrsvname
          enctdomname = deidentifydomainnamedata(tgtdname)
        end
      end # end of windows reserved name check 

      # Update the target domain name field with the deidentified data  ( Minimum 4 chars in size)
      if !enctdomname.nil? && enctdomname.size() > 3 
        event.set(@thistdname,enctdomname)
      end
    end # end of target domain name check
    
    # -- subject domain -----------
    if !subdname.nil? && subdname.size() > 1
      encsdomname = '' # empty string to allow early exit from domain search
      # Test to see if if it an FQDN or domain name, if not just deidentify the single name
      if subdname.match(/\S+\.\S+/)
        @domain_list.each do |thisdom|
          if testregex(thisdom,subdname.downcase())
            encsdomname = deidentifydomainnamedata(subdname)
          end
          break if encsdomname.size() > 3
        end  # end of first each do
      else
        @domain_list.each do |thisdom|
          domelem = thisdom.split('.')[0]
          if testregex(domelem,subdname.downcase())
            encsdomname = deidentifydomainnamedata(subdname)
          end
          break if encsdomname.size() > 3
        end  # end of second each do
      end  # end of dom regex test
      # Certain local functions and pre domain joined assets can have local workstation name as the domain
      # Domain can also be reserved windows names like workgroup, NT AUTHORITY etc, exclude these from encryption
      if encsdomname.size == 0
        winrsvname=false
        @winreserved_list.each do |thisrsv|
          if testregex(thisrsv.downcase(),subdname.downcase())
            winrsvname=true
          end
          break if winrsvname
        end
        # If domain value is not on prelist and not excluded because of reserved windows name, encrypt
        if !winrsvname
          encsdomname = deidentifydomainnamedata(subdname)
        end
      end # end of windows reserved name check
      # Update the computer name field with the deidentified data  ( Minimum 4 chars in size)
      if !encsdomname.nil? && encsdomname.size() > 3 
        event.set(@thissdname,encsdomname)
      end
    end # end of target domain name check
    
    ######################### return updated record content ############################## 
    return[event]
end #  End of the ruby event filter