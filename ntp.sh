#!/bin/bash
# check for ntp readvar, lpeers, and monlist
# requires ntpdc and ntpq

file=$1
len=`wc -l $1`
count=0
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "ntpq -c lpeers <ip>" >> ntp-lpeers-data.txt
while read ip; do
    count=$((count+1))
    echo -e "\nSending requests to $ip: $count/$len"

    # Check for Readvar
    readvar=`ntpq -c rv $ip`
    if [[ $readvar ==  *'associd='* ]]; then
        echo -e "$ip ${RED}vulnerable to readvar${NC}"
        echo $ip >> ntp-readvar.txt
    else
        echo "$ip not vulnerable to readvar"
    fi

    # check for lpeers
    echo -e "\n$ip" >> ntp-lpeers-data.txt
    lpeers=`ntpq -c lpeers $ip | tee -a ntp-lpeers-data.txt`
    if [[ $lpeers ==  *'.'* ]]; then
        echo -e "$ip ${RED}lpeers info disclosure${NC}"
        echo $ip >> ntp-lpeers-ips.txt
    else
        echo "$ip not vulnerable to lpeers"
    echo -e "\n" >> ntp-lpeers-data.txt
    fi

    # Monlist check
    monlist=`ntpdc -n -c monlist $ip`
    if [[ $monlist == *'remote address'* ]]; then
        echo -e "$ip ${RED}vulnerable to monlist${NC}"
        echo $ip >> ntp-monlist.txt
    else
        echo "$ip not vulnerable to monlist"
    fi

done<$1
