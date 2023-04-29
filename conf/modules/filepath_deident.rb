# Author: Doug Leece   dleece @ firstfiretech dot ca
# Jan 2/2023  V0 Module for ruby code to be called from a logstash pipeline:
#             - intended for log lines that may contain a sensitive name wihtin a file path that may need to be deidentifed
#             - The search relies on a list of potential directories or paths for whihc the next adjacent directory name should
#               be deidentified. 
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
    @fpeapiuri = 'http://127.0.0.1:5020/api/v1/updatedata?encname='
    @sensitivepaths = ["/home/","/opt/db/","/var/finance/"]  # Home subdirectories often match usenames, other possiblities like database names
def register(params)
    @thisfilepath = params["filepathfield"]
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
        elsif  !dirnames[2].nil? && dirnames[0] == "opt"
            thisfpath = encryptoptdb(thisfpath)
        else
            thisfpath = encryptfinance(thisfpath)
        end
    end      
    return thisfpath
end


# Presumes conventionional Linux home directory structure /home/someuser and leaves remaining subdirectories unaffected
def encrypthome(thisfpath)
    homedirpath=thisfpath.split('/')[1..(thisfpath.split('/').size()-1)]
    # don't encrypt common OS home directories as this can support known cleartext cipher attacks
    if testuname(homedirpath[1])
        enchomedirname = deidentifynamedata(homedirpath[1])
        # overwrite content
        homedirpath[1] = enchomedirname
    end
    # re-assemble array with slash delimiters and prepend leading slash
    thisevalfpath = "/" + homedirpath.join('/')
    return thisevalfpath
end

# Example code for encrypting database home location two directories deep EG.  /opt/db/devoradb
def encryptoptdb(thisfpath)
    optdbpath=thisfpath.split('/')[1..(thisfpath.split('/').size()-1)]
    encoptdbname = deidentifynamedata(optdbpath[2])
    # overwrite content
    optdbpath[2] = encoptdbname
    # re-assemble array with slash delimiters and prepend leading slash
    thisevalfpath = "/" + optdbpath.join('/')
    return thisevalfpath
end

# Example code for encrypting sensitive parent file directory name 
def encryptfinance(thisfpath)
    groupdirpath=thisfpath.split('/')[1..(thisfpath.split('/').size()-1)]
    encgroupdirname = deidentifynamedata(groupdirpath[1])
    # overwrite content
    groupdirpath[1] = encgroupdirname
    # re-assemble array with slash delimiters and prepend leading slash
    thisevalfpath = "/" + groupdirpath.join('/')
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
        encresult = restdata['fpedata']
    else
        encresult = 'fname' + '_df'
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
    filepath = event.get(@thisfilepath)
    evalfilepath = testfpath(filepath)
    event.set(@thisfilepath,evalfilepath)
    #  End of the ruby event filter
    return[event]
end
