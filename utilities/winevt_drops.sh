#!/usr/bin/bash
# Script requires windows events in a json lines file from SELD collector.
# Run on raw logs to validate how many are dropped in the deident process
# by logstash drop filters. Add addional drop conditions as needed, always pipe to word count
#
# 2023-03-26  Drops based on ls_WindowsEvt-JSON-v1-2.conf ( POC QA)

# Todo:  convert to python and make it multi-log with drop rules file

if [ $# -eq 0 ]
    then
      echo "usage: ./winevt_drops.sh windows-events.json1 "
    exit 1
fi

winevtlogfile=$1
# Print total log records,
echo "Total records for : "$winevtlogfile
cat $winevtlogfile | wc -l
echo "File hash (sha256) : "
filehash=$(sha256sum $winevtlogfile)
echo $filehash
echo "Calculating dropped records:"
total=0
row=$(grep '"event_id":"4634"' $winevtlogfile | wc -l)
total=$(($row + $total))
row=$(grep  945A8954-C147 $winevtlogfile | wc -l)
total=$(($row + $total))
row=$(grep '"event_id":"7036"' $winevtlogfile  | grep -i 555908d1-a6d7  | wc -l)
total=$(($row + $total))
row=$(grep '"event_id":"4907"' $winevtlogfile  | grep -i '"ObjectType":"File"'  | wc -l)
total=$(($row + $total))
#include additional grep conditions as record exclusions are identified
row=$(grep '"event_id":"10016"' $winevtlogfile  | grep Microsoft-Windows-DistributedCOM  | wc -l)
total=$(($row + $total))
row=$(grep '"event_id":"4742"' $winevtlogfile | wc -l)
total=$(($row + $total))
row=$(grep '"event_id":"1074"' $winevtlogfile  | grep b0aa8734-56f7  | wc -l)
total=$(($row + $total))
row=$(grep '"event_id":"5823"' $winevtlogfile  | grep -i NETLOGON  | wc -l)
total=$(($row + $total))
row=$(grep '"event_id":"37"' $winevtlogfile  | grep -i 06edcfeb-0fd0  | wc -l)
total=$(($row + $total))
row=$(grep '"event_id":"35"' $winevtlogfile  | grep -i 06edcfeb-0fd0  | wc -l)
total=$(($row + $total))
row=$(grep '"event_id":"16"' $winevtlogfile  | grep -i a68ca8b7-004f  | wc -l)
total=$(($row + $total))
row=$(grep '"event_id":"1500"' $winevtlogfile  | grep Microsoft-Windows-GroupPolicy  | wc -l)
total=$(($row + $total))
row=$(grep '"event_id":"1501"' $winevtlogfile  | grep Microsoft-Windows-GroupPolicy  | wc -l)
total=$(($row + $total))
row=$(grep '"event_id":"1502"' $winevtlogfile  | grep Microsoft-Windows-GroupPolicy  | wc -l)
total=$(($row + $total))
row=$(grep '"event_id":"5379"' $winevtlogfile  | grep 54849625-5478  | wc -l)
total=$(($row + $total))
row=$(grep '"event_id":"4695"' $winevtlogfile  | grep 54849625-5478  | wc -l)
total=$(($row + $total))
row=$(grep '"event_id":"5381"' $winevtlogfile  | grep 54849625-5478  | wc -l)
total=$(($row + $total))
row=$(grep '"channel":"Windows PowerShell"' $winevtlogfile | wc -l)
total=$(($row + $total))
row=$(grep '"event_id":"4799"' $winevtlogfile  | grep -v net1.exe  | wc -l)
total=$(($row + $total))
row=$(grep '"event_id":"4798"' $winevtlogfile  | grep -v net1.exe  | wc -l)
total=$(($row + $total))
row=$(grep '"channel":"System"' $winevtlogfile | grep '"event_id":"10154"'| wc -l)
total=$(($row + $total))
row=$(grep '"channel":"System"' $winevtlogfile | grep '"event_id":"1014"'| wc -l)
total=$(($row + $total))
row=$(grep '"channel":"System"' $winevtlogfile | grep '"event_id":"5774"'| wc -l)
total=$(($row + $total))
row=$(grep '"channel":"Security"' $winevtlogfile | grep '"event_id":"4719"'| wc -l)
total=$(($row + $total))
row=$(grep '"channel":"System"' $winevtlogfile | grep '"event_id":"3260"'| wc -l)
total=$(($row + $total))
row=$(grep '"channel":"System"' $winevtlogfile | grep '"event_id":"6011"'| wc -l)
total=$(($row + $total))
row=$(grep '"channel":"System"' $winevtlogfile | grep '"event_id":"4200"'| wc -l)
total=$(($row + $total))
row=$(grep '"channel":"System"' $winevtlogfile | grep '"event_id":"16"'| wc -l)
total=$(($row + $total))
row=$(grep '"channel":"System"' $winevtlogfile | grep '"event_id":"4096"'| wc -l)
total=$(($row + $total))
row=$(grep '"channel":"System"' $winevtlogfile | grep '"event_id":"4097"'| wc -l)
total=$(($row + $total))
row=$(grep '"channel":"Security"' $winevtlogfile | grep '"event_id":"5058"'| wc -l)
total=$(($row + $total))
row=$(grep '"channel":"Security"' $winevtlogfile | grep '"event_id":"4797"'| wc -l)
total=$(($row + $total))
row=$(grep '"channel":"Application"' $winevtlogfile | grep '"event_id":"4625"'| wc -l)
total=$(($row + $total))
row=$(grep '"channel":"Application"' $winevtlogfile | grep '"event_id":"455"'| wc -l)
total=$(($row + $total))
row=$(grep '"channel":"Application"' $winevtlogfile | grep '"event_id":"1001"'| wc -l)
total=$(($row + $total))
row=$(grep '"channel":"Security"' $winevtlogfile | grep '"event_id":"4694"'| wc -l)
total=$(($row + $total))
row=$(grep '"channel":"Security"' $winevtlogfile | grep '"event_id":"4692"'| wc -l)
total=$(($row + $total))
row=$(grep '"channel":"Security"' $winevtlogfile | grep '"event_id":"4738"'| wc -l)
total=$(($row + $total))
row=$(grep '"channel":"Security"' $winevtlogfile | grep '"event_id":"4739"'| wc -l)
total=$(($row + $total))
row=$(grep '"channel":"Security"' $winevtlogfile | grep '"event_id":"4741"'| wc -l)
total=$(($row + $total))
row=$(grep '"channel":"Security"' $winevtlogfile | grep '"event_id":"5059"'| wc -l)
total=$(($row + $total))
row=$(grep '"channel":"Security"' $winevtlogfile | grep '"event_id":"5061"'| wc -l)
total=$(($row + $total))




echo "total dropped records: "$total