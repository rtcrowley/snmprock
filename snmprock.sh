#!/bin/bash

# color
red='\033[0;31m'
cyn='\033[0;36m'
noco='\033[0m'

br=$(echo -e ${cyn}"-----------------------------------------------------------------------"${noco})

usage=$(
    echo -e ${cyn}"--------------------------------Usage----------------------------------"${noco}
    echo "-c = Community String. Default is set to 'public'"
    echo "     Must be set as 1st argument if NOT default"
    echo "-t = Target IP"
    echo "-a = Active processes/host resources running"
    echo "-n = Non-default procs running - cleaned-up version of -a"
    echo "-o = OS information"
    echo "-k = Kernel information"
    echo "-b = Brute Force Community String. Only takes Target IP as argument"
    echo "-h = Help (this menu)"
    echo -e ${cyn}"------------------------------Examples---------------------------------"${noco}
    echo "bash snmprock.sh -t 127.0.0.1 -n"
    echo "bash snmprock.sh -c private -t 127.0.0.1 -a -o"
    echo "bash snmprock.sh -b 127.0.0.1"
    echo "bash snmprock.sh -c raiden -t 127.0.0.1 -kano"
    echo "$br")

if [ -z "$1" ] || [[ "$1" != "-"* ]]; then
	echo "${usage}"
	exit 1
fi

c='public'

echo -e ${cyn}"------------------------------snmprock---------------------------------"${noco}



while getopts ':c:t:akonhb:' flag; do
  case "${flag}" in

    c) c="${OPTARG}"
	;;
    t) t="${OPTARG}"
	echo "Community String set to: ${c}"
	echo "$br"
	echo "Acquiring Target ${t}"
	nmap=$(nmap -sU -p161 $t)
	 case "$nmap" in
	  *open*)
	     echo "Target Acquired." 
	     echo "Nmap shows SNMP OPEN for business."
	     check=$(snmpwalk -v1 -c $c $t .1.3.6.1.2.1.1.1.0)

	     if [ -z "$check" ]
	     then
		echo -e ${red}"---------------------snmpwalk connection FAILED------------------------"${noco}
		echo -e ${red}"-------------------Double check Community String-----------------------"${noco}
		exit 1
	     else
		echo "snmpwalk connection SUCCESSFUL. Enuming now."
	     fi
	     #Getting system resources. Saving to temp file.
	     snmpwalk -v1 -c $c $t .1.3.6.1.2.1.25.6.3.1.2 |cut -d ':' -f2 |cut  -d '"' -f 2 >> snmp_tmp.txt
	     if [ -s snmp_tmp.txt ]
	     then
		echo "Host resources captured."
	     else
		echo -e ${red}"--No host resources captured. SNMP on target may be limited. Exiting.--"${noco}
		rm snmp_tmp.txt
		echo "$br"
		exit 1
	     fi
	     ;;
	   *)
	     echo -e ${red}"------------------SNMP seems to be closed or filtered------------------"${noco}
	     exit 1
	     ;;
	 esac
       ;;
    a) proc=$(snmpwalk -v1 -c $c $t .1.3.6.1.2.1.25.4.2.1.2 |cut -d ':' -f2 |cut  -d '"' -f2)
	echo "$br"
	echo -e ${cyn}"---------------------ACTIVE Host Resource intel------------------------"${noco}
	echo "$br"
	grep -r "${proc}" "snmp_tmp.txt" |sort -u
	osinfo=$(snmpwalk -v1 -On $t -c $c .1.3.6.1.2.1.1.1.0 |cut -d ':' -f2 |cut -d '#' -f1 |cut -d '"' -f2)
       ;;
    k) sysinfo=$(snmpwalk -v1 -c $c $t 1.3.6.1.2.1.1.1 |cut -d ' ' -f4,5,6 |cut -d '"' -f2)
	   kern=$(echo "${sysinfo}" |cut -d ' ' -f3 |cut -d '.' -f1,2)
	   if [ -z "$kern" ]
	   then
    	      echo -e ${red}"--------------------No Kernel info found------------------------------"
	   else   
		echo "$br"   
		echo -e ${cyn}"--------------------Kernel Research: Kernel" "${kern}""------------------------"${noco}
    	        echo "$br"
		searchsploit -t kernel "${kern}" | grep -v 'windows/' | grep -v '/dos/' 
	   fi

       ;;
    o)  echo "$br"
	echo -e ${cyn}"------------------------------OS Recon---------------------------------"${noco}
	echo "$br"
	os=$(snmpwalk -v1 -c $c $t 1.3.6.1.2.1.1.1 |cut -d ' ' -f4,5,6,7 |cut -d '"' -f2)
	centos=$(cat snmp_tmp.txt |grep -i release |cut -c 16-18 |tr '-' '.')
	ubuntu=$(cat snmp_tmp.txt |grep -i "ubuntu-docs" |cut -c 13-17)
	debian=$(cat snmp_tmp.txt |grep -i "lsb-release" |cut -c 13-15)
	#OS string counts
	cntcen=$(cat snmp_tmp.txt |grep -ic "centos")
	cntubu=$(cat snmp_tmp.txt |grep -ic "ubuntu")
	cntdeb=$(cat snmp_tmp.txt |grep -ic "debian")

	cnt=("${cntdeb}" "${cntubu}" "${cntcen}")

	echo "Found ${cntcen} instances of CentOS strings in host resources"
	echo "Found ${cntdeb} instances of Debian strings in host resources"
	echo "Found ${cntubu} instances of Ubuntu strings in host resources"
	echo "$br"
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
		*)
			echo "Guessing OS based off of running procs..."
		        max=0
		        for v in ${cnt[@]}; do
          		if (( $v > $max )); then max=$v; fi;
        		done

		        if [ $max -eq "${cnt[0]}" ]; then
				echo "Highly likely Debian ${debian}"
				searchsploit -t debian "${debian}" |grep -v '/windows/' | grep -v '/dos/'
        		elif [ $max -eq "${cnt[1]}" ]; then 
				echo "Highly likely Ubuntu ${ubuntu}"
				searchsploit -t ubuntu "${ubuntu}" |grep -v '/windows/' | grep -v '/dos/'
	       		elif [ $max -eq "${cnt[2]}" ]; then
				echo "Highly likely CentOS ${centos} "
				searchsploit -t centos "${centos}" |grep -v '/windows/' | grep -v '/dos/'
       			else
               			echo "Uknown"
       			fi

                ;;
		esac
	;;
    n)  echo "$br"
	echo -e ${cyn}"----------Listing Aftermarket Processes (& some stock procs)-----------"${noco}
	echo "$br"
	proc=$(snmpwalk -v1 -c $c $t .1.3.6.1.2.1.25.4.2.1.2 |cut -d ':' -f2 |cut  -d '"' -f2)
	#Strings that eliminante some stock procs
	grep -r "${proc}" "snmp_tmp.txt" |sort -u |awk '!/lib/ &&! /gnome/ && !/colord/  && !/fonts/ && !/bluetooth/ \
	&& !/indicator/ && !/unity/ && !/update/ && !/whoopsie/ && !/python3/ && !/cups/ && !/compiz/ \
	&& !/nautilus/ && !/shotwell/ && !/bamf/ && !/lshw/ && !/session/ && !/dconf/ && !/toshset/ && !/fwupd/ \
	&& !/shared-mime/ && !/lightdm/ && !/anacron/ && !/wbritish/ && !/upstart/ && !/bash-completion/ && !/snapd/ \
	&& !/zeitgeist/ && !/xorg/ && !/pulseaudio-[a-z]/ && !/python-[a-z]/ && !/gdm-user/ && !/rpm-/ && !/sysvinit/ \
	&& !/mingetty/ && !/metacity/ && !/gnote/ && !/tracker-/ && !/gstreamer/ && !/multiarch/ && !/mime/ \
	&& !/psutils/ && !/pm-utils/ && !/sudo-/ && !/dhclient/ && !/nss-sysin/ && !/wpa_suppli/ && !/initscripts/ \
	&& !/dnsmasq/ && !/dbus-/ && !/systemd-/ && !/dash-/ && !/bash-/ && !/squashfs-/ && !/acpid-/'
        ;;
    h)  echo "${usage}"
	exit 1
       ;;
    b)  b="${OPTARG}"
	#brute force using nmap script
	nmap --script snmp-brute.nse -sU $b -p161 --script-args snmpbrute.communitiesdb=/usr/share/seclists/Miscellaneous/snmp.txt 
	;;
    :) echo "Argument needs to be added after switch" ;;
    \?) error "Unexpected option ${flag}" ;;
  esac
done
shift $((OPTIND - 1))

#Removing temp file  if it exits
if [ -f snmp_tmp.txt ]; then
   rm snmp_tmp.txt
fi

echo -e ${cyn}"-------------------------snmprock complete-----------------------------"${noco}
