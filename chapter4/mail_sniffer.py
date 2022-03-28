from scapy.all import sniff, TCP, IP

def packet_sniff(packet):
    print(packet.show())

def main():
    sniff(prn=packet_sniff, count=1)

if __name__=='__main__':
    main()
    