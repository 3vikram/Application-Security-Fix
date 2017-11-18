import os
import subprocess


#Live IP SCAN USING SUBNET
def Live_Scan():
    IP_Subnet = input("Enter the subnet: " )
    IP_Last_Oct = input("Enter the last octet in Subnet address: ")
    Port_Scan = input("Do you want to perform port scan?: ").lower().strip()
    Final_IP_Address = IP_Subnet + IP_Last_Oct
    a = 'nmap  -oN Livescan.txt '+ Final_IP_Address
    response = os.system(a)
    with open('Livescan.txt','r') as ff:
        No_Ports_Open = 0
        with open('live_ip.csv','a+') as aa:
            for line in ff:
                if "Nmap scan report for " in line:
                    No_Ports_Open = No_Ports_Open + 1
                    aa.write(line[line.index('for ')+ 4:])
                    continue
            print(No_Ports_Open)
            aa.close()
    if Port_Scan == "yes" or "y":
        port_scan_results = Service_Scan()
        print(port_scan_results)
    elif Port_Scan == "No" or "N":
        print("Thank You for using me! See you later for a port scan :)")
    else:
        print("incorrect input")

def Service_Scan():
    with open('live_ip.csv', 'r') as aa:
        for ips in aa:
            b = 'nmap -Pn -sT -oN port_scan.txt ' + ips
            response1 = os.system(b)
            No_Ports_Open = 0
            with open('port_scan.txt','r') as r1:
                for line1 in r1:
                    if "open" in r1:
                        No_Ports_Open += 1
                        print(r1)
                        continue
                print(No_Ports_Open)


c = Live_Scan()
print(c)
