# Author: Doug Leece   dleece @ firstfiretech dot ca
# Jan 2/2023  V0 Module for ruby code to be called from a logstash pipeline:
#             - intended for log lines that may contain a sensitive name wihtin a sudo command that may need to be deidentifed
#             - The search reads in a list of sensitive names from a file, then tests if name is in message at all.
#             - If found, the field is extracted, deidentifed and the resulting three peices rebuilt. 
#               since this is slow the option could be to drop these messages.
#             - POC will use /home, extracted data will be passed to the same FPE encryption module and queries the event API 
#               to retrieve the file path element within the log event (line)
#       
#             - This module relies on format preserving encryption so usernames and computer host names could be reidentified if 
#               third party analysis identifes an potential security incident.  
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
#require 'ipaddr'
require 'net/http'
require 'json'


# According to logstash documentation these values are loaded at startup.
    # FPE web service  URL, hardcoded to use the encrypt function
    @fpeapiuri = 'http://192.168.95.59:5000/api/v1/updatedata?encname='
    # Read the list of sensitive names into an array, remove newlines
    @sensitivenames = IO.readlines("/opt/seld/conf/sensitivenames.txt",chomp: true)
    @sensitivepaths = ["/home/","/opt/db/","/var/finance/"]  # Home subdirectories often match usenames, other possiblities like database names
#def register(params)
#    @sudocmd = params["sudocmd"]
#end

# pass the individual names from the list to perform a regex check, return a boolean
def testrex(sensname,evalstr)
    if evalstr.match(sensname)
        return true
    else
        return false
    end
end



def testfpath(thisfpath)
    dirnames=[]
    # First determine if the file path is potentially sensitive.
    if thisfpath.start_with?(*@sensitivepaths)
        # Remove the empty array entry
        dirnames=thisfpath.split('/')[1..(thisfpath.split('/').size()-1)]
        #puts "fpath-decrypt-test"
    end
    # Split out each sensitive directory into it's own function to simplify code
    if dirnames.size() > 0
        if !dirnames[1].nil? && dirnames[0] == "home"
            thisfpath = encrypthome(thisfpath)
        end
    end      
    return thisfpath
end


# Presumes conventionional Linux home directory structure /home/someuser and leaves remaining subdirectories unaffected
def encrypthome(thisfpath)
    #puts "enrypt home: " + thisfpath
    homedirpath=thisfpath.split('/')[1..(thisfpath.split('/').size()-1)]
    # don't encrypt common OS home directories as this can support known cleartext cipher attacks
    if testuname(homedirpath[1])
        enchomedirname = deidentifynamedata(homedirpath[1])
        # overwrite content
        homedirpath[1] = enchomedirname
    end
    # re-assemble array with slash delimiters and prepend leading slash
    thisevalfpath = "/" + homedirpath.join('/')
    #puts thisevalfpath
    # Debug output
    #File.open('/var/tmp/seld_fpath-debug.log','a') { |fh| fh.puts thisevalfpath }
    return thisevalfpath
end


def deidentifynamedata(fname)
    # Adding paddding/truncating method to protect FPE algorithm
    thisfname = testnamesize(fname)
    requesturi = URI.parse(@fpeapiuri + thisfname)
    requestresponse = Net::HTTP.get_response(requesturi)
    # Confirm results were recieved
    if requestresponse.code == '200'
        restdata = JSON.parse(requestresponse.body)
        encresult = restdata['name']
        # monitor for debug, comment out for test & production 
        fpedebug = "directory encryption result: " + encresult  # monitor for debug
        #puts fpedebug  
        #debug output
        #File.open('/var/tmp/seld_fpath-debug.log','a') { |fh| fh.puts fpedebug }
    else
        encresult = ''
        # monitor for debug, comment out for test & production
        fpedebug = "encryption failed: " + encresult  # monitor for debug
        #puts fpedebug
        # debug output
        #File.open('/var/tmp/seld_fpath-debug.log','a') { |fh| fh.puts fpedebug }
    end

    return encresult
end


# List a few common linux accounts to ignore  for testing, 
# to do: bring in a dictionary from a file on load
def testuname(fname)
    if fname.downcase == 'root'
      deidentify = false
    elsif fname.downcase == 'oracle'
      deidentify = false
    elsif fname.downcase == 'www-data'
      deidentify = false
    elsif fname.downcase == 'admin'
      deidentify = false
    else
      deidentify = true
    end
  end


  # Format preserving encryption needs a minimum size data value to perfom the algorithm
# the python ff3 implmentation of FPE requires a minimum of 4 chars and max of 30,
# this function adjusts if required but data strings between 4 & 30 chars pass through
def testnamesize(thisfname)
    if thisfname.size() < 4
       padlength = 4 - thisfname.size()
       padname = thisfname.rjust(4,"_")
       return padname
    elsif thisfname.size() > 30
        truncname = thisfname[0..29]
        return truncname 
    else
        return thisfname
    end 
  end


  # retrieve the address included in the event, ( source, destination, other)
# confirm if the IP is within one the subnets identifed for deidentification
def filter(event)
    thissudocmd = event.get("sudo_cmd")
    File.open('/var/tmp/seld_sudocmd-debug.log','a') { |fh| fh.puts event.get("message")}
    # For each name in the sensitive name list check if it is in the sudo command, if so write to monitoring file
    @sensitivenames.each do |sname|
        #puts(sname)
        if testrex(sname,thissudocmd)
            File.open('/var/tmp/seld_sensitive-sudocmd.log','a') { |fh| fh.puts event.get("message")}
        end
    end
    
    #
    #evalfpath = testfpath(thisfpath)
    #event.set("file.path",evalfpath)
    #  End of the ruby event filter
    return[event]
end
