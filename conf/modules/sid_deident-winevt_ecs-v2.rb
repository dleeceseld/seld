# Author: Doug Leece   dleece @ firstfiretech dot ca
# Feb/2/2023
#
# The domain portion of a SID is globally unique, the relaitive identifier is locally unique
# as a result both values must be deidentified to prevent reidentification if a SID is disclosed 
# through a database or an internal user gains access to the deidentified data and attempts to 
# reidentify user accounts using one of many freely avaliable SID to user programs and scripts
#
# FPE for digits requires at least six characters, rids can be as small as 3,  prepend with 0's as needed
# should make reidentification through decryption fairly easy to reassemble the valid SID
#
# Feb 5/2023,  modifying SID extraction into prefix  & suffix, send suffix to FPE rest service 
#              to do deidentification in a single JSON call instead of 3-4 


# Ruby gem imports
#require 'ipaddr'
require 'net/http'
require 'json'

# According to logstash documentation these values are loaded at startup.
    # FPE web service  URL, hardcoded to use the encrypt function
    @fpeapidigituri = 'http://127.0.0.1:5022/api/v1/updatedata?encdashdelimdigit='
# Define the JSON path to target user name and subject user name
def register(params)
    @thistgtusid = params["tgtusidfield"]
    @thissubusid = params["subusidfield"]
    @thissvcsid = params["svcsidfield"]
    @thistgtsid = params["tgtsidfield"]
end

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


def filter(event)
    # Most Windows events will have a SID, many are well known SIDS and should not be 
    # deidentified.  Domain SIDs and user RIDS need to be encrypted
    # Domain and user SIDs are much longer than well known SIDS so length check will greatly
    # reduce the number of records that need to be processed
    
    tgtusid = event.get(@thistgtusid)
    subusid = event.get(@thissubusid)
    svcsid = event.get(@thissvcsid)
    tgtsid = event.get(@thistgtsid)
    # -- target user SID -----------
    if !tgtusid.nil? && tgtusid.size() > 36
      deidenttgtusid = encsid(tgtusid)
      event.set(@thistgtusid, deidenttgtusid)
    end
    # -- subject user SID -------------------
    if !subusid.nil? && subusid.size() > 36
      deidentsubusid = encsid(subusid)
      event.set(@thissubusid, deidentsubusid)
    end
    # --- service SID ---------------------
    if !svcsid.nil? && svcsid.size() > 36
        deidentsvcsid = encsid(svcsid)
        event.set(@thissvcsid, deidentsvcsid)
    end
    # --- target SID ---------------------
    if !tgtsid.nil? && tgtsid.size() > 36
        deidenttgtsid = encsid(tgtsid)
        event.set(@thistgtsid, deidenttgtsid)
    end
    #  End of the ruby event filter
    return[event]
end  