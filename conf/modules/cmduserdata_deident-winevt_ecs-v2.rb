# Author: Doug Leece   dleece @ firstfiretech dot ca
# Mar 30/2023 - Additional deidentification module for ruby code to be called from a logstash pipeline:
#             - Limited to parsing fields from process paths and command lines captured when 4688 is enabled.
#             - Call module only for process data that may contain user names as this can be a slow module
#             - ideally limit the username checks to 100 or less, ( seldproject_sensitiveusernames.txt)           
#
# Debug functions append the original log line and the processed/not processed value to a temporary log file.


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


@sensitivenames_list = IO.readlines("/opt/seld/conf/lists/seldproject_sensitiveusernames.txt",chomp: true)
@winreserved_list = IO.readlines("/opt/seld/conf/lists/winreserved_list.txt",chomp: true)
#Ensure all entries on the list being with ^ then the prefix, also observe case, ^dwm-  and ^DWM- would be differnt
@winsvcs_list = IO.readlines("/opt/seld/conf/lists/winsvcs_list.txt",chomp: true)

# According to logstash documentation these values are loaded at startup.
    # FPE web service  URL, hardcoded to use the encrypt function
    @fpeapiuri = 'http://127.0.0.1:5020/api/v1/updatedata?encatdelimalpha='

    # Define the JSON path to target user name and subject user name
def register(params)
    @thisnewprocessnamefield = params["newprocessnamefield"]
    @thisparentprocessnamefield = params["parentprocessnamefield"]
    @thiscommmandlinefield = params["commandlinefield"]
end

# Function to convert json lines file to hash table
def getwinrex()
    winrexht = Hash.new
    jlines=IO.readlines("/opt/seld/conf/lists/winrex.jsonl",chomp: true)
    jlines.each do |jline|
        tmphash = JSON.parse(jline)
        winrexht.merge!(tmphash) 
    end
    return winrexht
end
# convert JSON lines file of Windows message parsing characters into hashtable holding regex 
@winrex_hashes = getwinrex()

############################  Account Name processing
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


# Flag any of top 100 usernames that could appear in process paths or commands
def testsensitivenames(acctname)
    sensmatch=false
    if acctname.size > 6
        acctname=acctname[0,6]
    end
    acctname=acctname.downcase
    testrex=%r{.*#{acctname}.*}
    @sensitivenames_list.each do |sensname|
        if testrex.match(sensname.downcase)
            sensmatch = true
        end
        break if sensmatch
    end
    return sensmatch
end

# Format preserving encryption needs a minimum size data value to perfom the algorithm
# the python ff3 implmentation of FPE requires a minimum of 4 chars and max of 30,
# this function adjusts if required but data strings between 4 & 30 chars pass through
def testnamesize(thisname)
    if thisname.size() < 4
       #padlength = 4 - thisname.size()
       padname = thisname.rjust(4,"_")
       return padname
    elsif thisname.size() > 30
        truncname = thisname[0..29]
        return truncname 
    else
        return thisname
    end 
end


def deidentifyaccountdata(thisname)
    encresult = '' 
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

def getencacct(evalname)
    # first test for reserved usernames and exit early, returning the original name
    if testwinreserved(evalname)
        return evalname
    elsif testwinservices(evalname)
        return evalname
    elsif testsensitivenames(evalname)
        encacct = deidentifyaccountdata(evalname)
        return encacct
    else
        return evalname
    end
end

def testmessagefield(acctname)
    acctrex=%r{^.+?#{acctname}.++$}
    if acctrex.match(@messagefield)
        return true
    else
        return false
    end
end


def getsensfield(msgstr)
    # account names in home directory paths
    rex003=%r{#{@winrex_hashes["rex04688-3"]}}
    rexobj = rex003.match(msgstr)
    if !rexobj.nil?
        resultarray = rexobj.captures
        rexmatch=true
        deidentacct=getencacct(resultarray[0])
            if deidentacct != resultarray[0]
                msgstr = msgstr.gsub(resultarray[0],deidentacct)
                # Also check the message field for username variations
                if testmessagefield(resultarray[0])
                    @messagefield=@messagefield.gsub(resultarray[0],deidentacct)
                end
            end
        # return message string with the sensitive fields deidentified
        return msgstr
    end
    rex0031=%r{#{@winrex_hashes["rex04688-31"]}}
    rexobj = rex0031.match(msgstr)
    if !rexobj.nil?
        resultarray = rexobj.captures
        rexmatch=true
        deidentacct=getencacct(resultarray[0])
            if deidentacct != resultarray[0]
                msgstr = msgstr.gsub(resultarray[0],deidentacct)
                # Also check the message field for username variations
                if testmessagefield(resultarray[0])
                    @messagefield=@messagefield.gsub(resultarray[0],deidentacct)
                end
            end
        # return message string with the sensitive fields deidentified
        return msgstr
    end
    rex0032=%r{#{@winrex_hashes["rex04688-32"]}}
    rexobj = rex0032.match(msgstr)
    if !rexobj.nil?
        rexmatch=true
        resultarray = rexobj.captures
        deidentacct=getencacct(resultarray[0])
            if deidentacct != resultarray[0]
                msgstr = msgstr.gsub(resultarray[0],deidentacct)
                # Also check the message field for username variations
                if testmessagefield(resultarray[0])
                    @messagefield=@messagefield.gsub(resultarray[0],deidentacct)
                end
            end
        # return message string with the sensitive fields deidentified
        return msgstr
    end
    # track regex misses
    if !rexmatch
        File.open('/opt/seld/debuglogs/seld_wincmd_rex-reident-assessment.log','a') { |fh| fh.puts msgstr }
        return msgstr
    end
end # function end


def filter(event)
    # Additional message parsing may be needed if username is changed to 8 character directory name
    @messagefield = event.get('[winlog][message]')
    # Test all three fields collected by 4688 advanced monitoring if they appear to contain a username path
    newprocessname = event.get(@thisnewprocessnamefield)
    parentprocessname = event.get(@thisparentprocessnamefield)
    commandline = event.get(@thiscommmandlinefield)
    
    # -- new process name -----------
    if !newprocessname.nil? && newprocessname.size() > 1
      deidentnewprocname = getsensfield(newprocessname)
      event.set(@thisnewprocessnamefield, deidentnewprocname)
    end
    # -- parent process name -------------------
    if !parentprocessname.nil? && parentprocessname.size() > 1
      deidentparprocname = getsensfield(parentprocessname)
      event.set(@thisparentprocessnamefield, deidentparprocname)
    end
    # -- command line -------------------
    if !commandline.nil? && commandline.size() > 1
      deidentcommandline = getsensfield(commandline)
      event.set(@thiscommmandlinefield, deidentcommandline)
    end

    # Update the event message field
    event.set('[winlog][message]',@messagefield)
    ######################### return updated record content ############################## 
    return[event]
end #  End of the ruby event filter