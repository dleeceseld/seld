#!/usr/bin/bash
# Script requires two arguments, a file with sensitive terms and the deidentified logfile
# 
# For each line in script check entire log using grep , print lines found and search word 
# Todo: Add a summing feature at some point
# Todo:  convert to python and make it multi-log with drop rules file

if [ $# -eq 0 ]
    then
      echo "usage: ./testdatadeident.sh sensitiveterms.txt deidentifed_data.file "
    exit 1
fi

# File Collection and validation
sensitivetermsfile=$1
deidentdatafile=$2
senstermfilehash=$(sha256sum $sensitivetermsfile | awk '{print $1}')
deidentfilehash=$(sha256sum $deidentdatafile | awk '{print $1}')


termcount=$(wc -l $sensitivetermsfile | awk '{print $1}')
# Address end of file marker requirement
termcount=$(($termcount -1))
deidentdatacount=$(wc -l $deidentdatafile | awk '{print $1}')


echo " "
echo "Testing deidentifed data output for ["$termcount"] potentially sensitive/reidentifiable terms"
echo "Sensitive terms file hash: " $senstermfilehash 

#open sensitive terms file
while IFS= read -r sterm ; do
    records=$(grep -i $sterm $deidentdatafile  | wc -l)
    if (( $records  > 0 )); then  
      echo $sterm ":" $records
    fi
done < $sensitivetermsfile
echo "End of senstive term test"
echo " "
# Provide total record count to assist with calculating percentage ( )
echo "Number of records in deidentifed data set: "$deidentdatacount
echo "File hash (sha256) : "
echo $deidentfilehash
