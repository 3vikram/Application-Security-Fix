import os

def Live_Scan():
    IP_Subnet = input("Enter the subnet: " )
    IP_Last_Oct = input("Enter the last octet in Subnet address: ")
    Port_Scan = input("Do you want to perform port scan?: ").lower().strip()
    Final_IP_Address = IP_Subnet + IP_Last_Oct
    File_Exists_Check()
    a = 'nmap  -sP -oN Livescan.txt ' + Final_IP_Address
    response = os.system(a)
    with open('Livescan.txt','r+') as ff:
        with open('live_ip.csv','a+') as aa:
            for line in ff:
                if "Nmap scan report for " in line:
                    aa.write(line[line.index('for ')+ 4:])
                    continue
            aa.close()
    if Port_Scan == "yes" or "y":
        port_scan_results = Service_Scan()
        print(port_scan_results)
    elif Port_Scan == "no" or "n":
        print("Thank You for using me! See you later for a port scan :)")
    else:
        print("incorrect input")

def Service_Scan():
    No_Ports_Open = 0
    with open('live_ip.csv', 'r+') as aa:
        for ips in aa:
            b = 'nmap -P0 -sT -oN port_scan.txt ' + ips
            response1 = os.system(b)
            with open('Final_service.txt','a+') as fs:
                with open('port_scan.txt','r+') as r1:
                    for line1 in r1:
                        if "open" in line1:
                            No_Ports_Open = No_Ports_Open + 1
                            fs.write(line1)
                            continue
                    print(No_Ports_Open)
                    fs.close()
    Service_Vuln_Scan()


def Service_Vuln_Scan():
    with open('Final_service.txt', 'r+') as fs:
        for service_list in fs:
            service = service_list[service_list.index('open  ')+6:]
            vuln_commans = 'nmap  --script=' + service + '*' +
            response = os.system(vuln_commans)
            print(vuln_commans)

def File_Exists_Check():
    if os.path.isfile('./live_ip.csv'):
        os.remove("live_ip.csv")
    if os.path.isfile('.Livescan.txt'):
        os.remove("Livescan.txt")
    if os.path.isfile('./port_scan.txt'):
        os.remove("port_scan.txt")
    if os.path.isfile('./Final_service.txt'):
        os.remove("Final_service.txt")

result = Live_Scan()
print(result)
