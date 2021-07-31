import scapy.all as scapy
import optparse

def get_arguements():
    parser = optparse.OptionParser()
    parser.add_option("-r","--target", dest="range", help="Range of IP address")
    (options, arguements) = parser.parse_args()
    if not options.range:
        #code to handle error
        parser.error("[-] Please specify an Range of IP address, Use --help for more information")
    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered, unanswered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)
    #print(answered.summary())  
    client_list=[]
    for element in answered:
        client_dict = {"ip":element[1].psrc, "mac":element[1].hwsrc}
        client_list.append(client_dict)
    return client_list
    
def print_result(scan_result):
    print("IP\t\t\tMAC Address\n-------------------------------------------------")
    for client in scan_result:
        print(client["ip"] + "\t\t" + client["mac"])

options = get_arguements()	
scan_result = scan(options.range)
print_result(scan_result)