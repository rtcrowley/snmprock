# snmprock

A bash script to enumerate Linux targets via SNMP. This should only be ran on **Kali Linux** hosts as it's a sort of wrapper for native Kali apps & directories.

The script uses **snmpwalk**, **searchsploit** and **Nmap** to enumerate running processes. OS and Kernel enumeration is also available, along with a Community String brute force option.

Searchsploit, OS and Kernel results may vary as this has only been tested on a few versions of **Debian, Ubuntu and CentOS**. Use your best Judgment. Manual checks are always best if time permits.

___

### Usage:

```bash
root@kali:/home# bash snmprock.sh -h
--------------------------------Usage----------------------------------
-c = Community String. Default is set to 'public'
     Must be set as 1st argument if NOT default
-t = Target IP
-a = Active processes/host resources running
-n = Non-default procs running - cleaned-up version of -a
-o = OS information
-k = Kernel information
-b = Brute Force Community String. Only takes Target IP as argument
-h = Help (this menu)
------------------------------Examples---------------------------------
bash snmprock.sh -c private -t 127.0.0.1 -n
bash snmprock.sh -t 127.0.0.1 -a -o
bash snmprock.sh -b 127.0.0.1
bash snmprock.sh -c raiden -t 127.0.0.1 -kano
-----------------------------------------------------------------------
```

Tested on host **Kali Linux 2017.2**
