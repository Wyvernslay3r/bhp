import socket
import os

#Establish Listening Host
HOST = '192.168.1.69'

def main():
    if os.name == 'nt':
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP

    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((HOST, 0))

    #Include IP Header in the capture
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    #Read one Packet
    print(sniffer.recvfrom(65565))

    #Turn off promiscuous mode in Windows
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RXCVALL_OFF )

if __name__ == '__main__':
    main()
