import ipaddress
import struct
import socket
import os
import sys


class IP:
    def __init__(self, buff=None) -> None:
        header = struct.unpack('<BBHHHBBH4s4s', buff)
        # Retrieve High order nibble of the byte by right shifting 4 places
        self.ver = header[0] >> 4
        # Retrieve Low Order (Last 4) nibble of the byte using binary AND evaluation
        self.ihl = header[0] & 0xf

        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.offset = header[4]
        self.ttl = header[5]
        self.protocol_num = header[6]
        self.sum = header[7]
        self.src = header[8]
        self.dst = header[9]

        # Human Readable IP Addresses
        self.src_address = ipaddress.ip_address(self.src)
        self.dst_address = ipaddress.ip_address(self.dst)

        # map protocol constants to their names
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}

        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except Exception as e:
            print('%s No protocol for %s' % (e, self.protocol_num))
            self.protocol = str(self.protocol_num)

class ICMP:
    #Duplicate of ICMP.py file and class created previously. 
    def __init__(self, buff):
        header = struct.unpack('<BBHHH', buff)
        self.type = header[0]
        self.code = header[1]
        self.sum = header[2]
        self.id = header[3]
        self.seq = header[4]

def sniff(host):
    # Mostly Duplicate code from simple_sniffer.py
    if os.name == 'nt':
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP

    sniffer = socket.socket(
        socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((host, 0))

    # Include IP Header in the capture
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    try:
        while True:
            # Read the packet in
            raw_buffer = sniffer.recvfrom(65535)[0]
            # Create the ip header from the first 20 Bytes
            ip_header = IP(raw_buffer[0:20])

            # Print the detected protocol and hosts
            print('Protocol: %s %s -> %s' % (ip_header.protocol,
                                            ip_header.src_address, ip_header.dst_address))

            if ip_header.protocol == 'ICMP':
                #Retrieve additional Information if its and ICMP packet. 
                print(f'Version: {ip_header.ver}')
                print(f'Header Length: {ip_header.ihl} TTL: {ip_header.ttl}')

                #Calulate where the ICMP Packet starts
                offset = ip_header.ihl * 4
                buf = raw_buffer[offset:offset +8]
                #Create ICMP Structure
                icmp_header = ICMP(buf)
                print('ICMP -> Type: %s Code: %s \n'% (icmp_header.type, icmp_header.code))
            
    except KeyboardInterrupt:
        # Turn off promiscuous Mode
        if os.name == 'nt':
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        sys.exit()


if __name__ == '__main__':
    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        host = '192.168.1.69'
    sniff(host=host)
