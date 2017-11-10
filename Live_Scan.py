import os

def ping(userin):
    hostname=open(userin,'r+')
    number_of_servers_up = 0
    number_of_servers_down = 0
    number_of_servers_failed_to_reach = 0
    list_live_servers = []
    for hn in hostname:
        response= os.system('ping ' + hn)
        if response==0:
            print("{} is up".format(hn))
            number_of_servers_up+=1
            report=open('live_ip.xls','a+')
            report.write(str(hn)+'\n')
            list_live_servers.append(hn)
        elif response==2:
            print("{} is down".format(hn))
            number_of_servers_down+=1
        else:
            print("ping to {} failed".format(hn))
            number_of_servers_failed_to_reach+=1
    hostname.close()
    print("Number of servers up {}".format(number_of_servers_up))
    print("Number of servers down {}".format(number_of_servers_down))
    print("Number of servers failed to reach {}".format(number_of_servers_failed_to_reach))
    print("list of live servers are {}".format(list_live_servers))


output=ping("C:\\Users\\trra\\Documents\\ip.txt")
