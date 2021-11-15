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
        test -f "$project/$domain-sub.txt"
    }
    
    is_sd_snap_checker(){
        test -d "$project/sd-screenshot"
    }

    is_webportscan_checker(){
        test -f "$project/$project-webportscan.txt"
    }

}


function starter(){
   
    findomainer(){
        echo "${BLUE}[+] Finding SubDomains ${RESET}"
        findomain -t $domain -u $project/$domain-sub.txt
        cat $domain/$domain-sub.txt | httpx -o $project/$domain-sub-url.txt
        #cat $project/$domain-sub.txt
    }
    
    if is_subdomain_checker; then
    echo "Subdomain File Exist Already" || return
    else
        findomainer
    fi

    screenshoter(){
        echo "${BLUE}[+] Taking Screenshot!!! ${RESET}"
        gowitness file -f $project/$domain-sub-url.txt -P $project/sd-screenshot --chrome-path /mnt/c/Program\ Files/Google/Chrome/Application/chrome.exe
    }

    if is_sd_snap_checker; then
    echo "Screenshot Folder Exist Already" || return
    else
        while true; do
        read -p "Do you want to run screenshoter on each subdomains [y/n]?" yn
        case $yn in
            [Yy]* ) screenshoter; break;;
            [Nn]* ) exit;;
            * ) echo "Please answer yes or no.";;
        esac
        done
    fi
        
    webportscanner(){
        findomain -f $project/$domain-sub-url.txt --pscan -u $project/$project-webportscan.txt
    }

    if [[ $? -eq 1 ]]; then
    echo "some_command failed"
    fi

    if is_webportscan_checker; then
    echo "WebPortScan File Exist Already" || return
    else
        while true; do
        read -p "Do you want to run webportscanner on each subdomains [y/n]?" yn
        case $yn in
            [Yy]* ) webportscanner; break;;
            [Nn]* ) exit;;
            * ) echo "Please answer yes or no.";;
        esac
        done
    fi
      
    echo -e
    echo "${RED}Choose on which domain you want to scan${RESET}"
    select d in $(<$project/$domain-sub.txt);
    do test -n "$d\c" && break; 
    echo ">>> Invalid Selection"; 
    done
    URL=$d
}

parametercrawler(){
    
    askurl(){
        read -p "${RED}URL: ${RESET}" URL && echo -e
        #read -p 'Add Custom Parameter like source= ' cparam
        #read -p 'BXSS Hunter URL; xss.ht' bxss
    }

    runpc(){
    
        ## Need help creating folder name with URL stripping http/s 
        echo $URL
        folder(){
            echo $URL | sed 's/https\?:\/\///'
        }
        
        mkdir -p $project/$URLX
        
        ##waybackurl
        echo -e
        waybackurls $URL > $project/$URLX/all-urls.log
        echo "[${GREEN}I${RESET}] Done with Waybackurls${RESET}"
        
        #Stripping
        echo -e
        cat $project/$URLX/all-urls.log | grep "=" | egrep -iv ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt|js)" > $project/$URLX/uniqueparam.txt && echo -e uniqueparam.txt >> $project/$URLX/tmplist
        echo "[${GREEN}I${RESET}]Extracted URL with Valid Parameters${RESET}"
    }
    
    [ -z "$URL" ] && askurl || runpc
    echo Got this $URL
    runpc
}

dpayloadinjector(){
    ##dpayload
    cat $project/$URLX/uniqueparam.txt | qsinject -i '"><script>confirm(1)</script>' -iu -decode > $project/$URLX/qsinject.txt && echo qsinject.txt >> $project/$URLX/tmplist
    echo -e
    echo "[${RED}+${RESET}] ${GREEN}Waybackurl Output file > qsinject > running with default payload...${RESET}"
    echo -e
    echo "${CYAN}${WUL}curl --silent --path-as-is --insecure [eachline] | grep -qs '<script>confirm(1) && echo Vulnerable [each-line] && echo [each-line] >> $project/$URLX/xss-poc-injected.txt${RESET}"

    file="$project/$URLX/qsinject.txt"
    while IFS= read line
        do
            curl --silent --path-as-is --insecure "$line" | grep -qs "<script>confirm(1)" && echo ${RED}Vulnerable${RESET} $line && echo "$line" >> $project/$URLX/xss-poc-injected.txt
        done <"$file" 
}

XSSURLSCAN(){
        
    cat $project/$URLX/uniqueparam.txt | gf xss > $project/$URLX/gfxss.txt && echo -e gfxss.txt >> $project/$URLX/tmplist
    #cat $project/$URLX/uniqueparam.txt | /root/go/bin/kxss | sed 's/=.*/=/' | sed 's/URL: //' | sort -u > $project/$URLX/kxss.txt && echo kxss.txt >> $project/$URLX/tmplist
    
    echo -e
    echo "${MAGENTA}Total Count...${RESET}"
    echo -n "all-urls.log.txt : " & cat $project/$URLX/all-urls.log | wc -l
    echo -n "uniqueparam.txt : " & cat $project/$URLX/uniqueparam.txt | wc -l 
    echo -n "qsinject.txt : " & cat $project/$URLX/qsinject.txt | wc -l
    echo -n "gfxss.txt : " & cat $project/$URLX/gfxss.txt | wc -l
    echo -n "kxss.txt : " & cat $project/$URLX/kxss.txt | wc -l
    
    echo -e
    echo "${RED}Choose which results to run with dalfox...${RESET}"
    select d in $(<$project/$URLX/tmplist);
    do test -n "$d" && break; 
    echo ">>> Invalid Selection"; 
    done
    firstv=$d
    echo -e
    echo "Filename: ${BLUE}$project/$URLX/$firstv ${RESET}" && cat $project/$URLX/$firstv
    echo "${BLUE}Piping Dalfox on $project/$URLX/$firstv! ${RESET}"
    echo -e
    echo "${CYAN}${WUL}cat $project/$URLX/$firstv | dalfox pipe --output $project/xss-poc-dalfox.txt${RESET}"
    
    #running here
    echo -e
    cat $project/$URLX/$firstv | dalfox pipe --output $project/$URLX/xss-poc-dalfox.txt
    echo -e
    echo "${MAGENTA}>>>>JOOOOOOOODDDDDDDDDDD!!!!!<<<< ${RESET}"
}


#Menu options
options[0]="Subdomain and Screenshot"
options[1]="Run Parameter Crawler"
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
        echo "[1] Subdomain and Screenshot"
	    starter
    fi
    if [[ ${choices[1]} ]]; then
        echo "[2] Parameter Crawler"
        parametercrawler
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
checker
projectdirectorycheck
ACTIONS
