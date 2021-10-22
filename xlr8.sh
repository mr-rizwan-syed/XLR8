#!/bin/bash
#title:         XLR8.sh
#description:   Automated Script to Scan Vulnerability in Network
#author:        R12W4N
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

function progressBar()
{
    echo -ne "Please wait\n"
    while true
    do
        echo -n "${BLUE}#"
        sleep 2
    done
}

banner(){
echo -e "${GREEN}

██╗  ██╗██╗     ██████╗  █████╗ 
╚██╗██╔╝██║     ██╔══██╗██╔══██╗
 ╚███╔╝ ██║     ██████╔╝╚█████╔╝
 ██╔██╗ ██║     ██╔══██╗██╔══██╗
██╔╝ ██╗███████╗██║  ██║╚█████╔╝
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚════╝ 
                                                        	    
 _           _ _              ()            _            ____  
//\utomated  \\/ulnerability  []ntegrated  //\ssessment   L| ool ${RESET}"                                                               
Author: R12W4N
}
trap "trap_ctrlc" 2 

WORKING_DIR="$(cd "$(dirname "$0")" ; pwd -P)"
RESULTS_PATH="$WORKING_DIR/results"

echo $WORKING_DIR
echo $RESULTS_PATH

#Menu options
options[0]="${GREEN}Nmap Host Discovery Scan${RESET}"
options[1]="${GREEN}Nmap Port Scan${RESET}"
options[2]="${GREEN}Detailed Nmap Port Scan${RESET}"
options[3]="${GREEN}Rustscan${RESET}"
options[4]="${GREEN}Advance Vulnerability Scan Scan${RESET}"



nmap1(){
	nmap -sn -T4 --min-parallelism 100 $cidr -oG $site/$site.txt
	cat $site/$site.txt | cut -d " " -f 2 | grep -v Nmap > $site/$site.lst
	cat $site/$site.lst
	echo "${BLUE}Nmap Scan Done${RESET}"

	iplist=$(cat $site/$site.lst | paste -d',' -s)
	echo "${GREEN} $iplist ${RESET}"
}


nmap2(){
	file="$site/$site.lst"
		
	while IFS= read line
	do
		echo "${BLUE}Scanning $line Now ${RESET}"
		nmap -T4 $line -Pn --open -oN $site/$line.nps
		eports=$(cat $site/$line.nps | cut -d " " -f 1 | grep -o '[[:digit:]]*' | sed ':a;{N;s/\n/,/};ba')
		
		#re='^[0-9]+$'
		#if ! [[ $eports =~ $re ]] ; then
	   	#	echo "${RED}No Ports Found in $line ${RESET}" >&2;
		#fi
		
		echo "${RED}[+] $line >> $eports ${RESET}"
		case $eports in
		    ''|^[0-9,.]*$) echo "${RED}No Ports Found on $line :( ${RESET}" ;;
		    *) echo "nmap -sVC -p $eports --open -v -Pn -n -T4 $line -oX $site/$line.xml" >> $site/$site-nmap.log ;;
		esac
		
	done <"$file"
	echo "${RED}Please Save This <<<< ${RESET}"
}

masscan1(){

	echo -e "${GREEN}[+] Running Masscan.${RESET}"
    	#sudo masscan -p 1-65535 --rate 100000 --wait 0 --open -iL $site/$site.lst -oX $site/$site.mscn.xml
	
	echo "masscan -p1-65535,U:1-65535 -iL $site/$site.lst --rate 10000 -oL $site/$site.mscn.xml"
        masscan -p1-65535,U:1-65535 -iL $site/$site.lst --rate 10000 -oL $site/$site.mscn.xml
	
	if [ -f "$site/paused.conf" ] ; then
        	sudo rm "$site/paused.conf"
    	fi
    	open_ports=$(cat $site/$site.mscn.xml | grep portid | cut -d "\"" -f 10 | sort -n | uniq | paste -sd,)
    	cat $site/$site.mscn.xml | grep portid | cut -d "\"" -f 4 | sort -V | uniq > $site/nmap_targets.tmp
    	echo -e "${RED}[*] Masscan Done!${RESET}"
}

rustscan1(){
	echo "rustscan -a $iplist"
	rustscan -a $iplist > $site/$site.rsc
}

nmap3(){

    echo -e "${GREEN}[+] Running Nmap.${RESET}"
    sudo nmap -sVC -p $eports --open -v -Pn -n -T4 -iL $site/nmap_targets.tmp -oX $site/nmap.xml
    sudo rm $site/nmap_targets.tmp
    #xsltproc -o $site/nmap-native.html $site/nmap.xml
    #xsltproc -o $site/nmap-bootstrap.html $site/bootstrap-nmap.xsl $RESULTS_PATH/nmap.xml
    echo -e "${RED}[*] Nmap Done! View the reports at $RESULTS_PATH${RESET}"

}

nmap4(){

	nmaplog="$site/$site-nmap.log"
	if test -f "$nmaplog"; then
    		echo "$FILE exists."
    		while IFS= read vnmap
        	do
                	echo "${BLUE}Detailed Port Scanning ${RED} $vnmap ${RESET} Now"
                	$vnmap
        	done <"$nmaplog"
        	echo "${RED}Done; Please Save This <<<< ${RESET}"
	else
		echo "${RED}Starting Again :/${RESET}"
		nmap1
		nmap2
		nmap4
        	echo "${RED}Done; Please Save This <<<< ${RESET}"
        fi
}



##########
#Run XlR8#
##########

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
        echo "Option 1 selected"
	nmap1
    fi
    if [[ ${choices[1]} ]]; then
        #Option 2 selected
        echo "Option 2 selected"
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

#Starting from here 

read -p 'IP / CIDR: ' cidr
echo $cidr
read -p 'Site Name: ' site
echo $site
banner
echo -e "${GREEN}[+] Checking if results directory already exists.${RESET}"
if [ -d $site ]
    then
        echo -e "${BLUE}[-] Directory already exists. Skipping...${RESET}"
    else
        echo -e "${GREEN}[+] Creating results directory.${RESET}"
        mkdir -p $site
fi

ACTIONS
