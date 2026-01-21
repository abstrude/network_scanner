# Network Scanner
# Escáner de red
# Use: sudo python3 network_scanner.py --target <Enter target ip address (192.168.1.1), or range (192.168.1.1/24)>
# Uso: sudo python3 network_scanner.py -t <Ingrese la dirección IP de objetivo (192.168.2.1), o el rango (192.168.2.1/24)>
# Weapons of Mass Education℠ https://abstru.de
# Armas de Educación Masiva℠ https://abstru.de/es/index-es.html

import scapy.all as scapy
import argparse


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP address, or range.")
    (options) = parser.parse_args()
    
    if not options.target:
        parser.error("Specify target IP address, or range!")

    return options


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    response_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False) [0]
    
    clients_list = []

    for element in response_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)

    return clients_list


def print_result(results_list):
    print("\nIP\t\t\tMAC")
    print("--------------------------------------------")
    
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])

    print("--------------------------------------------")
    print("Weapons of Mass Education℠ https://abstru.de\n")

options = get_args()

scan_result = scan(options.target)

print_result(scan_result)