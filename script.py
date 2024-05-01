from scapy.all import *
import threading
import time

tip = "10.0.2.15"
tp = 23

def print_pkt(pkt):
    pkt.show()

def spoof_icmp(target_ip):
    cnt = 5
    while cnt:
        # Craft ICMP echo request packet
        ip = IP(dst=target_ip)
        icmp_pkt = ip/ICMP()

        # Send the packet
        print("Sending spoofed ICMP echo request packets to", target_ip)
        send(icmp_pkt, verbose=False)
        time.sleep(2)
        # ls(ip)
        cnt-=1

def send_ping(target_ip):
    cnt = 5
    while cnt:
        print("Sending ICMP echo request to ", target_ip)
        icmp_req = IP(dst=target_ip)/ICMP()
        response = sr1(icmp_req, timeout=2, verbose=False)
        if response:
          print("Ping reply received from", response[IP].src)
        else:
          print("No reply received")
        cnt-=1
        print("\n")

def send_tcp_packet(target_ip, target_port):
    try:
        cnt = 5
        while cnt:
          print("Sending TCP packet to ", target_ip, ":", target_port)
          # Craft TCP packet
          tcp_pkt = IP(dst=target_ip)/TCP(dport=target_port)
          # Send the packet
          send(tcp_pkt, verbose=False)
          print("TCP packet sent successfully")
          cnt-=1 
          print("\n")
    except Exception as e:
        print("An error occurred while sending TCP packet:", e)

def sniff_icmp():
    print("Sniffing ICMP packets. Press Ctrl+C to stop.")
    print("---------------------------")
    # sniff(filter='icmp', prn=print_pkt)
    sniff(filter='icmp', prn=process_packet)

def sniff_tcp(target_ip, target_port):
    print("\nSniffing TCP packets. Press Ctrl+C to stop.")
    print("---------------------------")
    sniff(filter='tcp', prn=process_packet)

def icmp():
    target_ip = input("Enter the desired IP address: ")
    # target_ip = tip
    # Create a thread to send the ping
    ping_thread = threading.Thread(target=send_ping, args=(target_ip,))
    ping_thread.start()

    sniff_icmp()
    
    # Wait for the ping thread to finish before exiting
    ping_thread.join()

def tcp():
    target_ip = input("Enter the desired IP address: ")
    # target_ip = tip

    target_port = int(input("Enter the desired PORT address: "))
    # target_port = tp

    # Create a thread to send the ping
    ping_thread = threading.Thread(target=send_tcp_packet, args=(target_ip,target_port,))
    ping_thread.start()

    sniff_tcp()

    # Wait for the ping thread to finish before exiting
    ping_thread.join()

def process_packet(packet):
    if TCP in packet:
        print(" TCP Packet:")
        print("  Source IP:", packet[IP].src)
        print("  Destination IP:", packet[IP].dst)
        print("  Source Port:", packet[TCP].sport)
        print("  Destination Port:", packet[TCP].dport)
        print("  Flags:", packet[TCP].flags)
        print("  Payload:", packet[TCP].payload)
    elif ICMP in packet:
        print(" ICMP Packet:")
        print("  Source IP:", packet[IP].src)
        print("  Destination IP:", packet[IP].dst)
        print("  Type:", packet[ICMP].type)
        print("  Code:", packet[ICMP].code)
        print("  Payload:", packet[ICMP].payload)


def sniffer_protocol(type_filter, target_ip, target_port):
    print("\nSniffing " + type_filter  + " packets. Press Ctrl+C to stop.")
    print("---------------------------")
    fil = ""
    if type_filter == 'tcp': 
      fil = type_filter +" && dst host " + target_ip + " && dst port " + target_port + ""
    elif type_filter == 'icmp':
      fil = type_filter +" && dst host " + target_ip
    sniff(filter= fil, prn=process_packet)

def sniffer_net(target_net, target_mask):
    print("\nSniffing net "+ target_net + " and mask " + target_mask + " packets. Press Ctrl+C to stop.")
    print("---------------------------")
    fil = "net " + target_net + " mask " + target_mask + ""
    sniff(filter= fil, prn=process_packet)

def hacking(packet):
    print("Without change: ")
    process_packet(packet)
    packet[IP].dst = "208.80.154.224"
    send(packet)
    print("HACKING: ")
    process_packet(packet)

def sniffer_man_in_the_middle():
    print("Sniffing ICMP packets. Press Ctrl+C to stop.")
    print("---------------------------")
    sniff(filter='icmp', prn=hacking)


def menu_protocol():
    target_ip = input("Enter the target IP address: ")
    target_port = input("Enter the target PORT: ")
    option = input("Enter the filter icmp OR tcp: ")

    sniffer_protocol(option, target_ip, target_port)

    # if option == "icmp":
       # icmp()
    # elif option == "tcp":
       # tcp()
    # else:
       # print("Invalid option")
       # exit(1)

def menu_net():
    target_net = input("Enter the target NET address: ")
    target_mask = input("Enter the target MASK address: ")
    
    sniffer_net(target_net, target_mask)

def menu_hack():
    print("Man in the middle !!!")
    sniffer_man_in_the_middle()

def main():
    menu_protocol()

if __name__ == "__main__":
    main()