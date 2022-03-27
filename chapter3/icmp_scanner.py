import ipaddress
import struct
import socket
import os
import sys
import time
import threading

'''
Possible Future Projects - 
    1. Modify the below code to encrypt and decrypt the message portion of the ICMP packet, for data exfiltration. 
    2. Expand beyond ICMP for individual protocol headers of value
        - Look into interesting protocols, RTMP, SSH, etc

'''

# Target Subnet
SUBNET = '192.168.1.0/24'
# String to Include in our ICMP Packets
# If we encrypt this data in the future, this can be used as a data exfiltration library/method.
MESSAGE = 'This is my string.'


def udp_sender():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        for ip in ipaddress.ip_network(SUBNET).hosts():
            sender.sendto(bytes(MESSAGE, 'utf8'), (str(ip), 65212))


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
    # Duplicate of ICMP.py file and class created previously.
    def __init__(self, buff):
        header = struct.unpack('<BBHHH', buff)
        self.type = header[0]
        self.code = header[1]
        self.sum = header[2]
        self.id = header[3]
        self.seq = header[4]


class Scanner:
    def __init__(self, host):
        self.host = host
        if os.name == 'nt':
            socket_protcol = socket.IPPROTO_IP
        else:
            socket_protocol = socket.IPPROTO_ICMP

        self.socket = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket_protocol)

        self.socket.bind((host, 0))

        # Include IP Header in the capture
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        if os.name == 'nt':
            self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    def sniff(self):
        # Moved Duplicate code from simple_sniffer.py to the init method

        hosts_up = set([f'{str(self.host)} *'])

        try:
            while True:
                # Read the packet in
                raw_buffer = self.socket.recvfrom(65535)[0]
                # Create the ip header from the first 20 Bytes
                ip_header = IP(raw_buffer[0:20])

                # Print the detected protocol and hosts
                print('Protocol: %s %s -> %s' % (ip_header.protocol,
                                                 ip_header.src_address, ip_header.dst_address))

                if ip_header.protocol == 'ICMP':
                    # Calulate where the ICMP Packet starts
                    offset = ip_header.ihl * 4
                    buf = raw_buffer[offset:offset + 8]
                    # Create ICMP Structure
                    icmp_header = ICMP(buf)

                    # Check for Type and CODE 3 and check ICMP src address is in our subnet above
                    if icmp_header.code == 3 and icmp_header.type == 3 and ipaddress.ip_address(ip_header.src_address) in ipaddress.IPv4Network(SUBNET):
                        # Check for the Message Writted Above
                        if raw_buffer[len(raw_buffer) - len(MESSAGE):] == bytes(MESSAGE, 'utf-8'):
                            tgt = str(ip_header.src_address)
                            #
                            if tgt != self.host and tgt not in hosts_up:
                                hosts_up.add(str(ip_header.src_address))
                                print(f'Hosts Up: {tgt}')

                    # Retrieve additional Information if its an ICMP packet.
                    # Still print the packet, even if it does not contain the above mesage.
                    print(f'Version: {ip_header.ver}')
                    print(
                        f'Header Length: {ip_header.ihl} TTL: {ip_header.ttl}')

                    print('ICMP -> Type: %s Code: %s \n' %
                          (icmp_header.type, icmp_header.code))

        except KeyboardInterrupt:
            # Turn off promiscuous Mode
            if os.name == 'nt':
                self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

            print('\n User interrupted.')
            if hosts_up:
                print(f'\n\nSummary: Hosts on {SUBNET}')
            for host in sorted(hosts_up):
                print(f'{host}')
            print('')
            sys.exit()


if __name__ == '__main__':
    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        host = '192.168.1.69'

    s = Scanner(host)
    time.sleep(5)
    t = threading.Thread(target=udp_sender)
    t.start()
    s.sniff()
