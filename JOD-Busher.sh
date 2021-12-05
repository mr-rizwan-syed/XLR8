#!/bin/bash
#title:         JOD-XLR8.sh
#description:   Automated and Modular Shell Script to Automate Security Vulnerability Scans
#author:        R12W4N
#version:       1.0.1
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

trap "trap_ctrlc" 4

banner(){
    echo '
    
     ██╗ ██████╗ ██████╗      ██╗  ██╗██╗     ██████╗  █████╗ 
     ██║██╔═══██╗██╔══██╗     ╚██╗██╔╝██║     ██╔══██╗██╔══██╗
     ██║██║   ██║██║  ██║█████╗╚███╔╝ ██║     ██████╔╝╚█████╔╝
██   ██║██║   ██║██║  ██║╚════╝██╔██╗ ██║     ██╔══██╗██╔══██╗
╚█████╔╝╚██████╔╝██████╔╝     ██╔╝ ██╗███████╗██║  ██║╚█████╔╝
 ╚════╝  ╚═════╝ ╚═════╝      ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚════╝                                                               

        '
}
####Add Functions Here


function subdomain(){
    subfinder -silent -d $domain > $project/subdomains.txt
    cat $project/subdomains.txt | httpx -o $project/sd-httpx.txt
    httpx -l $project/sd-httpx.txt -title -tech-detect -status-code -ip -fc 403,401,404 -o $project/sd-httpx-details.txt
    httpx -l $project/sd-httpx.txt -fr -fc 403,401,404 -o sd-potentials.txt
    httpx -l $project/sd-httpx.txt -follow-redirects -fc 403,401,404 -no-color -o $project/httpx-redirect.csv
}

function find_ips(){
    echo -e "Now doing massdns on the domain"
    #Do masscanning only when massdns is finished working
    resolversFile=./50resolvers.txt
    massdnsOutput=$project/ips.txt
    allSubdomainsOutput=$project/subdomains.txt
    massdns_temp=$project/massdns.tmp
    massdns -r $resolversFile -t A -w $massdns_temp $allSubdomainsOutput
    cat $massdns_temp | cut -d " " -f3 | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" >> $massdnsOutput
    rm $massdns_temp
    echo -e "Massdns complete"
}


#Menu options
options[0]="Gather Subdomains"
options[1]="Resolve IP's"
options[2]="Run XSS Scan on Single URL"
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
        echo "[1] Gathering Subdomain"
	    subdomain
    fi
    if [[ ${choices[1]} ]]; then
        echo "[2] Finding IP Addresses"
        find_ips
    fi
    if [[ ${choices[2]} ]]; then
        echo "[3] Option 1 selected; Need a Single URL"
	    JOD_XSS
    fi
    if [[ ${choices[3]} ]]; then
        echo "Option 4 selected"
        rustscan1
    fi
}

projectdirectorycheck(){
    read -p "${RED}Project Name: ${RESET}" project
    echo $project

    if [ -d $project ]
    then
        echo -e
        echo -e "[${RED}I${RESET}] $project Directory already exists...${RESET}"
    else
        mkdir -p $project
    fi
    read -p "${RED}Domain: ${RESET}" domain && echo -e
}

banner
projectdirectorycheck
ACTIONS