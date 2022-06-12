#!/bin/bash
#title:         JOD-ALPHA
#description:   Automated and Modular Shell Script to Automate Security Vulnerability Scans
#author:        R12W4N
#version:       1.0.0
#==============================================================================
RED=`tput setaf 1`
GREEN=`tput setaf 2`
YELLOW=`tput setaf 3`
BLUE=`tput setaf 4`
MAGENTA=`tput setaf 5`
CYAN=`tput setaf 6`
RESET=`tput sgr0`
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
         
     ██  ██████  ██████         █████  ██      ██████  ██   ██  █████  
     ██ ██    ██ ██   ██       ██   ██ ██      ██   ██ ██   ██ ██   ██ 
     ██ ██    ██ ██   ██ █████ ███████ ██      ██████  ███████ ███████ 
██   ██ ██    ██ ██   ██       ██   ██ ██      ██      ██   ██ ██   ██ 
 █████   ██████  ██████        ██   ██ ███████ ██      ██   ██ ██   ██ 
 '                                                                  
}


####Add Functions Here

function counter(){
    sdc=Results/$domain/subdomains.txt
    sdb=Results/$domain/dnsxout.txt 
    apache=Results/$domain/apache-urls.txt
    apachetomcat=Results/$domain/apache-tomcat-urls.txt
    wp=Results/$domain/wordpress-urls.txt
    drupal=Results/$domain/drupal-urls.txt
    joomla=Results/$domain/joomla-urls.txt
    jira=Results/$domain/jira-urls.txt
    gitl=Results/$domain/gitlab-urls.txt
    jboss=Results/$domain/jboss-urls.txt
    bigip=Results/$domain/bigip-urls.txt

    [ -f $sdc ] && echo -e "${GREEN}[+]${RESET}Total Subdomains [$(cat $sdc | wc -l)]"
    [ -f $sdb ] && echo -e "${GREEN}[+]${RESET}Potential Subdomains [$(cat $sdb | wc -l)]"
    [ -f $apache ] && echo -e "${GREEN}[+]${RESET}Apache Subdomains [$(cat $apache | wc -l)]"
    [ -f $apachetomcat ] && echo -e "${GREEN}[+]${RESET}Apache TomcatSubdomains [$(cat $apachetomcat | wc -l)]"
    [ -f $wp ] && echo -e "${GREEN}[+]${RESET}WordPress Subdomains [$(cat $wp | wc -l)]"
    [ -f $drupal ] && echo -e "${GREEN}[+]${RESET}Drupal Subdomains [$(cat $drupal | wc -l)]"
    [ -f $joomla ] && echo -e "${GREEN}[+]${RESET}Joomla Subdomains [$(cat $joomla | wc -l)]"
    [ -f $jira ] && echo -e "${GREEN}[+]${RESET}Jira Subdomains [$(cat $jira | wc -l)]"
    [ -f $gitl ] && echo -e "${GREEN}[+]${RESET}GitLab Subdomains [$(cat $gitl | wc -l)]" 
    [ -f $jboss ] && echo -e "${GREEN}[+]${RESET}JBoss Subdomains [$(cat $jboss | wc -l)]" 
    [ -f $bigip ] && echo -e "${GREEN}[+]${RESET}BigIP Subdomains [$(cat $bigip | wc -l)]" 
}

function subdomains(){
    echo "${GREEN}[1] Gathering Subdomain${RESET}"
    subfinder -d $domain -silent | anew Results/$domain/subdomains.txt
    wait

    sdc=Results/$domain/subdomains.txt
    [ -f $sdc ] && echo -e "${GREEN}[*]${RESET}Passive Subdomains Collected${YELLOW} [$(cat $sdc | wc -l)]${RESET}"

      subdomain_brute(){
      echo "${BLUE}[+]${RESET}Initiating DNSRecon Bruteforcing"
      
      dnsrecon -d $domain -D $(pwd)/MISC/subdomains-top1million-5000.txt -t brt -v > Results/$domain/dnsreconoutput.txt
      cat Results/$domain/dnsreconoutput.txt | cut -d " " -f 4 | grep $domain > Results/$domain/dnsbrute.txt 
      cat Results/$domain/dnsbrute.txt  | anew Results/$domain/subdomains.txt
      

      #dnsx -silent -w MISC/subdomains-top1million-5000.txt -d $domain | anew Results/$domain/dnsxout.txt
      #cat Results/$domain/dnsxout.txt | anew Results/$domain/subdomains.txt

      sdct=Results/$domain/subdomains.txt
      echo "${GREEN}[+]${RESET}Total Subdomains including DNS Brute"
      [ -f $sdct ] && echo -e "${GREEN}[*]${RESET}Total Subdomains ${YELLOW} [$(cat $sdct | wc -l)]${RESET} "
      
      }
    
    subdomain_brute

    echo "${GREEN}[+]${RESET}}Probing all Subdomains [Collecting StatusCode,Title,Tech,cname...]"

    cat Results/$domain/subdomains.txt | httpx -sc -content-type -location -title -server -td -ip -cname -asn -cdn -vhost -pa -random-agent -csv -o Results/$domain/$domain-probed.csv
    cat Results/$domain/$domain-probed.csv | cut -d ',' -f 9 | grep -v 'url' | anew Results/$domain/sd-httpx.txt
    awk -F, '{print $9,$21}' Results/$domain/$domain-probed.csv | egrep -iv "401|403|404" | cut -d ' ' -f 1 | anew Results/$domain/potential-sd.txt

    # Apache Subdomains
    echo "${GREEN}Apache Subdomains: ${RESET}"
    awk -F, '/Apache/ {print}' Results/$domain/$domain-probed.csv | cut -d ',' -f 9,12,31 --output-delimiter=" ${MAGENTA}>>>${RESET} "
    awk -F, '/Tomcat/ {print}' Results/$domain/$domain-probed.csv | cut -d ',' -f 9,12,31 --output-delimiter=" ${MAGENTA}>>>${RESET} "
    awk -F, '/Apache/ {print}' Results/$domain/$domain-probed.csv | cut -d ',' -f 9 | anew Results/$domain/apache-urls.txt
    awk -F, '/Tomcat/ {print}' Results/$domain/$domain-probed.csv | cut -d ',' -f 9 | anew Results/$domain/apache-tomcat-urls.txt

    # Nginx Subdomains
    echo "${GREEN}Nginx  Subdomains: ${RESET}"  
    awk -F, '/Nginx/ {print}' Results/$domain/$domain-probed.csv | cut -d ',' -f 9,12,31 --output-delimiter=" ${MAGENTA}>>>${RESET} "
    awk -F, '/Nginx/ {print}' Results/$domain/$domain-probed.csv | cut -d ',' -f 9 | anew Results/$domain/nginx-urls.txt

    # IIS Subdomains
    echo "${GREEN}IIS  Subdomains: ${RESET}"
    awk -F, '/IIS/ {print}' Results/$domain/$domain-probed.csv | cut -d ',' -f 9,12,31 --output-delimiter=" ${MAGENTA}>>>${RESET} "
    awk -F, '/IIS/ {print}' Results/$domain/$domain-probed.csv | cut -d ',' -f 9 | anew Results/$domain/IIS-urls.txt

    # Wordpress Subdomains
    echo "${GREEN}Wordpress Subdomains: ${RESET}"
    awk -F, '/Wordpress|WordPress/ {print}' Results/$domain/$domain-probed.csv | cut -d ',' -f 9,12,31 --output-delimiter=" ${MAGENTA}>>>${RESET} "
    awk -F, '/Wordpress|WordPress/ {print}' Results/$domain/$domain-probed.csv | cut -d ',' -f 9 | anew Results/$domain/wordpress-urls.txt

    # Joomla Subdomains
    echo "${GREEN}Joomla Subdomains: ${RESET}"
    awk -F, '/Joomla/ {print}' Results/$domain/$domain-probed.csv | cut -d ',' -f 9,12,31 --output-delimiter=" ${MAGENTA}>>>${RESET} "
    awk -F, '/Joomla/ {print}' Results/$domain/$domain-probed.csv | cut -d ',' -f 9 | anew Results/$domain/joomla-urls.txt

    # Drupal Subdomains
    echo "${GREEN}Drupal Subdomains: ${RESET}"
    awk -F, '/Drupal/ {print}' Results/$domain/$domain-probed.csv | cut -d ',' -f 9,12,31 --output-delimiter=" ${MAGENTA}>>>${RESET} "
    awk -F, '/Drupal/ {print}' Results/$domain/$domain-probed.csv | cut -d ',' -f 9 | anew Results/$domain/drupal-urls.txt

    # Jira Subdomains
    echo "${GREEN}Jira Subdomains: ${RESET}"
    awk -F, '/Jira/ {print}' Results/$domain/$domain-probed.csv | cut -d ',' -f 9,12,31 --output-delimiter=" ${MAGENTA}>>>${RESET} "
    awk -F, '/Jira/ {print}' Results/$domain/$domain-probed.csv | cut -d ',' -f 9 | anew Results/$domain/jira-urls.txt

    # Gitlab Subdomains
    echo "${GREEN}GitLab  Subdomains: ${RESET}"
    awk -F, '/GitLab/ {print}' Results/$domain/$domain-probed.csv | cut -d ',' -f 9,12,31 --output-delimiter=" ${MAGENTA}>>>${RESET} "
    awk -F, '/GitLab/ {print}' Results/$domain/$domain-probed.csv | cut -d ',' -f 9 | anew Results/$domain/gitlab-urls.txt

    # JBoss Subdomains
    echo "${GREEN}JBoss Subdomains: ${RESET}"
    awk -F, '/JBoss/ {print}' Results/$domain/$domain-probed.csv | cut -d ',' -f 9,12,31 --output-delimiter=" ${MAGENTA}>>>${RESET} "
    awk -F, '/JBoss/ {print}' Results/$domain/$domain-probed.csv | cut -d ',' -f 9 | anew Results/$domain/jboss-urls.txt

    # BigIP Subdomains
    echo "${GREEN}BigIP Subdomains: ${RESET}"
    awk -F, '/BigIP/ {print}' Results/$domain/$domain-probed.csv | cut -d ',' -f 9,12,31 --output-delimiter=" ${MAGENTA}>>>${RESET} "
    awk -F, '/BigIP/ {print}' Results/$domain/$domain-probed.csv | cut -d ',' -f 9 | anew Results/$domain/bigip-urls.txt

    # Delete Empty Files in domain Folder
    find Results/$domain -type f -empty -print -delete

    counter
}


allbackurls(){
    
  #mkdir -p $project/$URL/gf-param
  ##waybackurl-gau
  echo -e
        
  while IFS= read url
    do
       echo "Getting All URLs of $url"
       mkdir -p Results/$domain/$URL/allurls.txt
       gau $url | anew Results/$domain/$URL/allurls.txt
    done <"Results/$domain/potential-sd.txt"

  echo "[${GREEN}I${RESET}] Done with Waybackurls and Gau${RESET}"
}


## Below functions checks for existence of result directories

domaindirectorycheck(){
    echo Results/$domain

    if [ -d Results/$domain ]
    then
        echo -e
        echo -e "[${RED}I${RESET}] Results/$domain Directory already exists...${RESET}"
    else
        mkdir -p Results/$domain
        echo -e "[${GREEN}I${RESET}] Results/$domain Directory Created${RESET}"
    fi
    
}

function checker(){
    
    is_subdomain_checker(){
        test -f "Results/$domain/subdomains.txt"
        test -f "Results/$domain/$domain-probed.csv"
    }

    is_allurl_checker(){
        test -f "Results/$domain/allurls.txt"
    }


}

function getsubdomains(){
    if is_subdomain_checker; then
        echo "Results/$domain/subdomains.txt File Already Exist" || return

        # Todo: ReRun if requested in argument if rerun=yes then run again

    else
        subdomains
    fi

}

function getallurls(){
    if is_allurl_checker; then
        echo "Results/$domain/allurls.txt File Already Exist" || return

        # Todo: ReRun if requested in argument if rerun=yes then run again

    else
        allbackurls
    fi

}

POSITIONAL_ARGS=()
function usage()
{
    echo "JOD-Alpha Help Menu"
    echo ""
    echo "./jod-alpha.sh -d=domain.com"
    echo "" 
    echo "-h --help"
    echo "-d --domain=domain.com"
    echo ""
}

while [[ $# -gt 0 ]]; do
  case $1 in
    -h|--help)
      usage
      shift 
      shift
      ;;
    -d|--domain)
      domain="$2"
      domaindirectorycheck
      checker
      getsubdomains
      shift 
      shift
      ;;
    -gau|--getallurls)
      getallurls
      shift 
      shift
      ;;
    -rr|--rerun)
      rerun=yes
      shift 
      ;;
    --default)
      DEFAULT=YES
      shift 
      ;;
    -*|--*)
      echo "Unknown option $1"
      exit 1
      ;;
    *)
      POSITIONAL_ARGS+=("$1") # save positional arg
      shift 
      ;;
  esac
done

set -- "${POSITIONAL_ARGS[@]}" # restore positional parameters

#echo "Domain           = ${domain}"
#echo "DEFAULT         =  ${DEFAULT}"
#echo "Number files in SEARCH PATH with EXTENSION:" $(echo "${project}"/*."${domain}")

if [[ -n $1 ]]; then
    usage
fi
