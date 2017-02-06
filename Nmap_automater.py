#!/usr/bin/python 
# Nmap automated scanner for easy understanding and easy use
# Reference: https://nmap.org/book/man.html
# Initiating Libraries
import os
import sys
import nmap
import socket
import time


print" " +"\n" + " "

print"###### Nmap Automater ######"

print"Nmap Automated Scanner >>>>>>>>>>> Automates nmap scans"

print"Author : Srinan"

print"{Note: Under development}"

print"###### Nmap automated scanner for easy understanding and easy use ######"

print" " +"\n" + " "



def main():
    print "Scanning Options"
    print "(1) Active hosts/Host discovery"
    print "(2) Host Sevices discovery"
    print "(3) Intense Scan"
    print "(4) Intense Scan + UDP"
    print "(5) Intense Scan - all TCP ports"
    print "(6) Normal Scan"
    print "(7) Vulnerability scan"
    print "(8) Fragment Packets"
    print "(9) Traceroute scan"
    print "(10) DNS Resolution scan"
    print "(11) Banner grabbing"
    print "(12) Exit"
    print" " +"\n" + " "

    option = raw_input("Choose your Scanning Option: ")

    if option == '1':
        host = raw_input("Provide the IP range to scan")
    	hosts_list = str(host)  
    	nm= nmap.PortScanner() 
    	nm.scan(hosts= host, arguments='-PE -sn')
    	hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
  
    
    
    	for host, status in hosts_list: 
        	    if 'up' in status: 
                        print "----------------------------------------------------------------------------"
            	    	print'{0}'.format(host)  + " is " + "up"
                 	
                 
                    
    if option == '2':
	host = raw_input("Provide the IP range to scan")
        os.system("nmap -T5 -sV -v "+host)
        print "\n[**] Done \n"
        main() 
    
    elif option == '3':
        host = raw_input("Provide the IP range to scan")
        os.system("nmap -T4 -A -v "+host)
        print "\n[**] Done \n"
        main()

    elif option == '4':
        host = raw_input("Provide the IP range to scan")
        os.system("nmap -sS -sU -T4 -A -v "+host)
        print "\n[**] Done \n"
        main()

    elif option == '5':
        host = raw_input("Provide the IP range to scan")
        os.system("nmap -p- -T4 -A -v "+host)
        print "\n[**] Done \n"
        main()

    elif option == '6':
        host = raw_input("Provide the IP range to scan")
        os.system("nmap "+host)
        print "\n[**] Done \n"
        main()        
    
    elif option == '7':
        host = raw_input("Provide the IP range to scan")
        os.system("nmap -p- --script=*vuln* --script-args=unsafe=1  "+host)
        print "\n[**] Done \n"
        main()      
    
    elif option == '8':
        host = raw_input("Provide the IP range to scan")
        os.system("nmap -f"+host)
        print "\n[**] Done \n"
        main()      
    
    elif option == '9':
        host = raw_input("Provide the IP range to scan")
        os.system("nmap -sn --traceroute "+host)
        print "\n[**] Done \n"
        main()

    elif option == '10':
        host = raw_input("Provide the IP range to scan")
        os.system("nmap -R "+host)
        print "\n[**] Done \n"
        main()
    
   elif option == '11':
        host = raw_input("Provide the IP range to scan")
        os.system("nmap -sV --script=banner "+host)
        print "\n[**] Done \n"
        main()

    elif option == '12':
        print "[**] Exiting Nmap_Automater"
        time.sleep(2)
        sys.exit()

    else:
	print "\nInvalid Option\n"
        main()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("interrupt received, stopping the scan")
        time.sleep(2)
        main()                  
