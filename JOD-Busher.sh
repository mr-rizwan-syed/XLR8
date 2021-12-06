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

function checker(){
    
    is_subdomain_checker(){
        test -f "$project/subdomains/subdomains.txt"
        test -f "$project/subdomains/sd-potentials.txt"
        test -f "$project/sub-url-stripped.txt"
    }

    is_sd_snap_checker(){
        test -d "$project/sd-screenshot"
    }

    is_webportscan_checker(){
        test -f "$project/$project-webportscan.txt"
    }

    is_uniqueparameter_checker(){
        test -f "$project/$URL/uniqueparam.txt"
    }
    is_uniqueparameter_checker(){
        test -f "$project/$URL/qsinject.txt"
    }
}
function subdomains(){
    mkdir -p $project/subdomains
    subfinder -silent -d $domain > $project/subdomains/subdomains.txt
    cat $project/subdomains/subdomains.txt | httpx -o $project/subdomains/sd-httpx.txt
    httpx -l $project/subdomains/sd-httpx.txt -follow-redirects -title -tech-detect -status-code -ip -fc 403,401,404 -no-color -o $project/subdomains/sd-httpx-details.csv
    httpx -l $project/subdomains/sd-httpx.txt -retries 2 -fc 302,403,401,404 -o $project/subdomains/sd-potentials.txt
    #httpx -silent -l $project/subdomains/sd-httpx.txt -follow-redirects -fc 403,401,404 -no-color -o $project/subdomains/httpx-redirect.csv
    cat $project/subdomains/subdomains.txt | gf interestingsubs > $project/subdomains/interestingsubs.txt
    echo -e
    cat $project/subdomains/sd-potentials.txt | sed 's/https\?:\/\///' > $project/sub-url-stripped.txt
}

function subdomainstart(){
    if is_subdomain_checker; then
    echo "Subdomain File Exist Already" || return
    else
        subdomains
    fi
}

function find_ips(){
    echo -e "Now doing massdns on the domain"
    #Do masscanning only when massdns is finished working
    resolversFile=./50resolvers.txt
    massdnsOutput=$project/ips.txt
    allSubdomainsOutput=$project/subdomains/subdomains.txt
    massdns_temp=$project/massdns.tmp
    massdns -r $resolversFile -t A -w $massdns_temp $allSubdomainsOutput
    cat $massdns_temp | cut -d " " -f3 | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort -u >> $massdnsOutput
    rm $massdns_temp
    echo -e "Massdns complete"
}


askurl(){
        read -p "${RED}URL: ${RESET}" URL && echo -e
    }

function choicemaker(){
    
    if is_subdomain_checker; then
    echo "Subdomain File Already Exist" || return
    else
        echo "${BLUE}Run Subdomain Scan First"
    fi
    
    echo "${RED}Choose on which domain you want to scan${RESET}"
    select d in $(<$project/sub-url-stripped.txt);
    do test "$d\c" && break; 
    echo ">>> Invalid Selection";
    done || askurl;
    URL=$d
}

parametercrawler(){
    
    runpc(){
    
        echo Scannning $URL
        mkdir -p $project/$URL
        mkdir -p $project/$URL/gf-param
        ##waybackurl-gau
        echo -e
        waybackurls $URL > $project/$URL/all-urls.log
        gau $URL >> $project/$URL/all-urls.log
        cat $project/$URL/all-urls.log | sort -u > $project/$URL/all-urls.txt
        cat $project/$URL/all-urls.txt
        echo "[${GREEN}I${RESET}] Done with Waybackurls and Gau${RESET}"
               
        #Stripping
        echo -e
        cat $project/$URL/all-urls.txt | grep "=" | egrep -iv ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt|js)" > $project/$URL/uniqueparam.txt
        echo "[${GREEN}I${RESET}]Extracting URL with Valid Parameters${RESET}"
        cat $project/$URL/all-urls.txt | qsinject -i '"FUZZ"' -iu -decode > $project/$URL/qsinjected.txt

        #gf-patterns
        #Some pattern may find sensitive info that's why string not replaced
        cat $project/$URL/all-urls.txt | gf xss | qsinject -i 'FUZZ' -iu -decode | anew -q $project/$URL/gf-param/xss.txt
        cat $project/$URL/all-urls.txt | gf sqli | qsinject -i 'FUZZ' -iu -decode | anew -q  $project/$URL/gf-param/sqli.txt
        cat $project/$URL/all-urls.txt | gf ssrf | qsinject -i 'FUZZ' -iu -decode | anew -q  $project/$URL/gf-param/ssrf.txt
        cat $project/$URL/all-urls.txt | gf ssti | qsinject -i '"FUZZ"' -iu -decode | anew -q  $project/$URL/gf-param/ssti.txt
        cat $project/$URL/all-urls.txt | gf redirect | qsinject -i 'FUZZ' -iu -decode | anew -q  $project/$URL/gf-param/redirect.txt
        cat $project/$URL/all-urls.txt | gf lfi | qsinject -i 'FUZZ' -iu -decode | anew -q  $project/$URL/gf-param/lfi.txt
        cat $project/$URL/all-urls.txt | gf rce | qsinject -i 'FUZZ' -iu -decode | anew -q  $project/$URL/gf-param/rce.txt
        cat $project/$URL/all-urls.txt | gf upload-fields | qsinject -i 'FUZZ' -iu -decode | anew -q  $project/$URL/gf-param/upload-fields.txt
        cat $project/$URL/all-urls.txt | gf http-auth | anew -q $project/$URL/gf-param/http-auth.txt
        cat $project/$URL/all-urls.txt | gf interestingparams | anew -q $project/$URL/gf-param/interestingparams.txt
        cat $project/$URL/all-urls.txt | gf interestingEXT | anew -q $project/$URL/gf-param/interestingEXT.txt
        cat $project/$URL/all-urls.txt | gf img-traversal | anew -q $project/$URL/gf-param/img-traversal.txt
        cat $project/$URL/all-urls.txt | gf php-sources | anew -q $project/$URL/gf-param/php-sources.txt
        cat $project/$URL/all-urls.txt | gf s3-buckets | anew -q $project/$URL/gf-param/s3-buckets.txt
        cat $project/$URL/all-urls.txt | gf sec | anew -q $project/$URL/gf-param/sec.txt
        cat $project/$URL/all-urls.txt | gf secrets | anew -q $project/$URL/gf-param/secrets.txt
        cat $project/$URL/all-urls.txt | gf servers | anew -q $project/$URL/gf-param/servers.txt
        cat $project/$URL/all-urls.txt | gf strings | anew -q $project/$URL/gf-param/typos.txt
        find $project/$URL/gf-param/ -type f -empty -print -delete

    }
    
    upcvalidator(){
        is_uniqueparameter_checker(){
        test -f "$project/$URL/uniqueparam.txt"
        }

        if is_uniqueparameter_checker; then
        echo "Unique Parameter File Exist Already" || return
        else
            runpc
        fi
    }

    [ -z "$URL" ] && askurl || upcvalidator
    echo Got this $URL
    
}


startp(){
    while true; do
    choicemaker
    parametercrawler
    again
    done
}

Again(){
        while true; do
        read -p "Do you want to run it again on each subdomains [y/n]?" yn
        case $yn in
            [Yy]* ) startp; break;;
            [Nn]* ) break;;
            * ) echo "Please answer yes or no.";;
        esac
        done
}

#Menu options
options[0]="Gather Subdomains"
options[1]="Resolve IP's"
options[2]="Parameter Crawler"
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
	    subdomainstart
    fi
    if [[ ${choices[1]} ]]; then
        echo "[2] Finding IP Addresses"
        find_ips
    fi
    if [[ ${choices[2]} ]]; then
        echo "[3] Option 1 selected; Need a Single URL"
	    startp
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

checker
banner
projectdirectorycheck
ACTIONS