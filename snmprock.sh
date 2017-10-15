#!/bin/bash

usage=$(
    echo "--------------------------------Usage----------------------------------"
    echo "-c = Community String. Default is set to 'public'"
    echo "     Must be set as 1st argument if NOT default"
    echo "-t = Target IP"
    echo "-a = Active processes/host resources running"
    echo "-n = Non-default procs running - cleaned-up version of -a"
    echo "-o = OS information"
    echo "-k = Kernel information"
    echo "-b = Brute Force Community String. Only takes Target IP as argument"
    echo "-h = Help (this menu)"
    echo "------------------------------Examples---------------------------------"
    echo "bash snmprock.sh -c private -t 127.0.0.1 -n"
    echo "bash snmprock.sh -t 127.0.0.1 -a -o"
    echo "bash snmprock.sh -b 127.0.0.1"
    echo "bash snmprock.sh -c raiden -t 127.0.0.1 -kano"
    echo "-----------------------------------------------------------------------")

if [ -z "$1" ] || [[ "$1" != "-"* ]]; then
        echo "${usage}"
        exit 1
fi

c='public'

echo "-----------------------------------------------------------------------"
echo "-------------------------------snmprock--------------------------------"



while getopts ':c:t:akonhb:' flag; do
  case "${flag}" in

    c) c="${OPTARG}"
        ;;
    t) t="${OPTARG}"
        echo "-----------------------------------------------------------------------"
        echo "Community String set to: ${c}"
        echo "-----------------------------------------------------------------------"
        echo "Acquiring Target ${t}...."
        nmap=$(nmap -sU -p161 $t)
         case "$nmap" in
          *open*)
             echo "Target Acquired." 
             echo "Nmap shows SNMP OPEN for business"
             check=$(snmpwalk -v1 -c $c $t .1.3.6.1.2.1.1.1.0)

             if [ -z "$check" ]
             then
                echo "-----------------------------------------------------------------------"
                echo "---------------------snmpwalk connection FAILED------------------------"
                echo "-------------------Double check Community String-----------------------"
                exit 1
             else
                echo "snmpwalk connection SUCCESSFUL. Enuming now..."
             fi
             
             #Storing target host resources in tmp txt file.
             snmpwalk -v1 -c $c $t .1.3.6.1.2.1.25.6.3.1.2 |cut -d ':' -f2 |cut  -d '"' -f 2 >> snmp_tmp.txt
             
             if [ -s snmp_tmp.txt ]
             then
                echo "Host resources captured...."
             else
                echo "--No host resources captured. SNMP on target may be limited. Exiting.--"
                rm snmp_tmp.txt
                echo "-----------------------------------------------------------------------"
                exit 1
             fi
             echo "-----------------------------------------------------------------------"
             ;;
           *)
             echo "------------------SNMP seems to be closed or filtered------------------"
             exit 1
             ;;
         esac
       ;;
    a) proc=$(snmpwalk -v1 -c public $t .1.3.6.1.2.1.25.4.2.1.2 |cut -d ':' -f2 |cut  -d '"' -f2)
        echo "-----------------------------------------------------------------------"
        echo "------------------------Do your due diligence--------------------------"
        echo "---------------------------ACTIVE processes----------------------------"
        echo "-----------------Melding out host resource version intel---------------"
        echo "-----------------------------------------------------------------------"
        
        #Matches running process names to stored process verisons in snmp_tmp.txt
        grep -r "${proc}" "snmp_tmp.txt" |sort -u
        osinfo=$(snmpwalk -v1 -On $t -c $c .1.3.6.1.2.1.1.1.0 |cut -d ':' -f2 |cut -d '#' -f1 |cut -d '"' -$
        echo "-----------------------------------------------------------------------"
        echo "----------------Try manual searchsploit queries using------------------"
        echo "------------------ ACTIVE process list from above----------------------"
        echo "-----------------------------------------------------------------------"
       ;;
    k) sysinfo=$(snmpwalk -v1 -c $c $t 1.3.6.1.2.1.1.1 |cut -d ' ' -f4,5,6 |cut -d '"' -f2)
           #This may need to be altered per Linux distro.
           kern=$(echo "${sysinfo}" |cut -d ' ' -f3 |cut -d '.' -f1,2)
           if [ -z "$kern" ]
           then
              printf ".\n.\nNo Kernel info found\n.\nTry a manual check\n.\n"
           else
                echo "--------------------------Kernel Research------------------------------"
                echo "----------------------Searching: Kernel" "${kern}""---------------------------"
                echo "-----------------------------------------------------------------------"
                searchsploit -t kernel "${kern}" | grep -v 'windows/' | grep -v '/dos/' 
           fi

       ;;
    o)  echo "Testing OS.."
        os=$(snmpwalk -v1 -c $c $t 1.3.6.1.2.1.1.1 |cut -d ' ' -f4,5,6,7 |cut -d '"' -f2)
        centos=$(cat snmp_tmp.txt |grep -i release |cut -c 16-18 |tr '-' '.')
        ubuntu=$(cat snmp_tmp.txt |grep -i "ubuntu-docs" |cut -c 13-17)
        debian=$(cat snmp_tmp.txt |grep -i "lsb-release" |cut -c 13-15)
        freebsd=$(echo "$os" |grep -i release |cut -d ' ' -f4 |cut -d '-' -f1)
        
        #OS string counts
        cntcen=$(cat snmp_tmp.txt |grep -c "centos")
        cntubu=$(cat snmp_tmp.txt |grep -ic "ubuntu")
        cntdeb=$(cat snmp_tmp.txt |grep -ic "debian")
        cntbsd=$(cat snmp_tmp.txt |grep -ic "bsd")
        
        echo "-----------------------------------------------------------------------"
        echo "Found ${cntcen} instances of CentOS strings in host resources"
        echo "Found ${cntdeb} instances of Debian strings in host resources"
        echo "Found ${cntubu} instances of Ubuntu strings in host resources"
        echo "Found ${cntbsd} instances of BSD string in host resources"
        echo "-----------------------------------------------------------------------"
        
        echo "System Description: ${os}"
        sysname=$(snmpwalk -v1 -c $c $t 1.3.6.1.2.1.1.5 |cut -d ' ' -f3,4 |cut -d '"' -f2)
        echo "System Name: ${sysname}"
                case "$os" in
                *ubuntu*)
                        echo "Extremely likely target is Ubuntu ${ubuntu}"
                        searchsploit -t ubuntu "${ubuntu}"
                ;;
                *debian*)
                        echo "Extremely likely target is Debian ${debian}"
                        searchsploit -t debian "${debian}"
                ;;
                *centos*)
                        echo "Extremely likely target is CentOS ${centos}"
                        searchsploit -t centos "${centos}" | grep -v '/windows/' | grep -v '/dos/'
                ;;
                *FreeBSD*)
                        echo "Extremely likely target is FreeBSD ${freebsd}"
                        searchsploit -t freebsd "${freebsd}" | grep -v '/windows/' | grep -v '/dos/'
                ;;
                *)
                        echo "Guessing OS based off running procs..."
                        if [ "${cntcen}" -gt "15" ]
                        then
                          echo "Highly likely CentOS ${centos}"
                          searchsploit -t centos "${centos}" | grep -v '/windows/' | grep -v '/dos/'
                        elif [ "${cntdeb}" -gt "15" ]
                        then
                          echo "Highly likely Debian ${debian}"
                          searchsploit -t debian "${debian}"
                        elif [ "${cntubu}" -gt "15" ]
                        then
                          echo "Highly likely Ubuntu ${ubuntu}"
                          searchsploit -t ubuntu "${ubuntu}"
                        elif [ "${cntbsd}" -gt "15" ]
                        then
                          echo "Highly likely FreeBSD ${freebsd}"
                          searchsploit -t freebsd "${freebsd}"
                        else
                          echo "OS Unknown."
                        fi

                ;;
                esac
        echo "-----------------------------------------------------------------------"
        ;;
    n)  echo "----------Listing Aftermarket Processes (& some stock procs)----------" 
        echo "-----------------------------------------------------------------------"
        proc=$(snmpwalk -v1 -c $c $t .1.3.6.1.2.1.25.4.2.1.2 |cut -d ':' -f2 |cut  -d '"' -f2)
        
        #Add strings here to remove from -n switch
        grep -r "${proc}" "snmp_tmp.txt" |sort -u |awk '!/lib/ &&! /gnome/ && !/colord/  && !/fonts/ && !/b$
        && !/indicator/ && !/unity/ && !/update/ && !/whoopsie/ && !/python3/ && !/cups/ && !/compiz/ \
        && !/nautilus/ && !/shotwell/ && !/bamf/ && !/lshw/ && !/session/ && !/dconf/ && !/toshset/ && !/fw$
        && !/shared-mime/ && !/lightdm/ && !/anacron/ && !/wbritish/ && !/upstart/ && !/bash-completion/ &&$
        && !/zeitgeist/ && !/xorg/ && !/pulseaudio-[a-z]/ && !/python-[a-z]/ && !/gdm-user/ && !/rpm-/ && !$
        && !/mingetty/ && !/metacity/ && !/gnote/ && !/tracker-/ && !/gstreamer/ && !/multiarch/ && !/mime/$
        echo "-----------------------------------------------------------------------"
       ;;
    h)  echo "${usage}"
        exit 1
       ;;
    b)  b="${OPTARG}"
        #brute force using nmap script. Update here if you'd like to change wordlist.
        nmap --script snmp-brute.nse -sU $b -p161 --script-args snmpbrute.communitiesdb=/usr/share/seclists$
        ;;
    :) echo "Argument needs to be added after switch" ;;
    \?) error "Unexpected option ${flag}" ;;
  esac
done
shift $((OPTIND - 1))


# Cleaning up
if [ -f snmp_tmp.txt ]; then
   rm snmp_tmp.txt
fi

echo "-------------------------It's Judgment Day-----------------------------"
echo "-----------------------------------------------------------------------"
echo "-------------------------snmprock complete----------------------------"
echo "-----------------------------------------------------------------------"
