#!/bin/bash
# check for ntp readvar, lpeers, and monlist
# requires ntpdc and ntpq

usage () {
    cat <<END

Connects to each IP listed in a text file (one per line) and attempts checks for the following:
    readvar
    lpeers
    monlist

Usage:
ntpVulns.sh -f [file]

Options:
    -f: file
    -c: check if ntpdc and ntpq are installed
    -v: verbose terminal output
    -h: display this help message

This program requires ntpdc and ntpq to function properly 
END
}

error () {
    echo "Error: $1"
    usage
    exit $2
} >&2


isInstalled () {
    for i in ntpq ntpdc; do
        type $i > /dev/null

        if [ $? -ne 0 ]; then
            echo -e "\nPlease install $i prior to proceeding"
        else
            echo "$i is already installed"
        fi
    done
}

verbosity=
while getopts ":f:chv" opt; do
    case $opt in
        h)
            usage
            exit 0
            ;;
        f)
            file=$OPTARG
            len=`wc -l $file`
            count=0
            ;;
        c)
            isInstalled
            exit 0
            ;;
        v)
            verbosity="2>/dev/null"
            ;;            
        :)
            error "Option -${OPTARG} is missing an argument"
            exit 1
            ;;
        \?)
            error "Unknown option -${OPTARG}"
            exit 1
            ;;
    esac
done


#COLORS
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

while read ip; do
    count=$((count+1))
    echo -e "\nSending requests to $ip: $count/$len"

    #READVAR CHECK
    #readvar=`ntpq -c rv $ip | tee -a ntp-readvar-data.txt`
    readvar=`ntpq -c rv $ip $verbosity`
    if [[ $readvar ==  *'associd='* ]]; then
        #APPEND COMMAND FOR REFERENCE ON FIRST ITERATION 
        if [[ ! -e ntp-readvar-data.txt ]]; then
            echo -e "ntpq -c rv <ip>" >> ntp-readvar-data.txt
        fi        
        echo -e "$ip: ${RED}vulnerable to readvar${NC}"
        echo $ip >> ntp-readvar-ips.txt
    else
        echo -e "${GREEN}not vulnerable to readvar${NC} " >&2
    fi

    #LPEERS CHECK        
    #echo -e "\n$ip" >> ntp-lpeers-data.txt
    #lpeers=`ntpq -c lpeers $ip | tee -a ntp-lpeers-data.txt`
    lpeers=`ntpq -c lpeers $ip $verbosity`
    if [[ $lpeers ==  *'.'* ]]; then
        #APPEND COMMAND FOR REFERENCE ON FIRST ITERATION 
        if [[ ! -e ntp-lpeers-data.txt ]]; then
            echo -e "ntpq -c lpeers <ip>" >> ntp-lpeers-data.txt
        fi
        echo -e "\n$ip" >> ntp-lpeers-data.txt
        echo -e "$lpeers" >> ntp-lpeers-data.txt
        echo -e "$ip: ${RED}vulnerable to lpeers disclosure${NC}"
        echo $ip >> ntp-lpeers-ips.txt
        echo -e "\n" >> ntp-lpeers-data.txt
    else
        echo -e "${GREEN}not vulnerable to lpeers${NC} " >&2
    fi

    #MONLIST CHECK
    #monlist=`ntpdc -n -c monlist $ip | tee -a ntp-monlist-data.txt`
    monlist=`ntpdc -n -c monlist $ip $verbosity`
    if [[ $monlist == *'remote address'* ]]; then
        #APPEND COMMAND FOR REFERENCE ON FIRST ITERATION 
        if [[ ! -e ntp-lpeers-data.txt ]]; then
            echo -e "ntpdc -n -c monlist <ip>" >> ntp-lpeers-data.txt
        fi
        echo -e "$monlist\n\n" >> ntp-lpeers-data.txt
        echo -e "$ip ${RED}vulnerable to monlist${NC}"
        echo $ip >> ntp-monlist-ips.txt
    else
        echo -e "${GREEN}not vulnerable to monlist${NC} " >&2
    fi
done<$file
exit 0
