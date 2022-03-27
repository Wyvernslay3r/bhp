import ipaddress
import struct


class IP:
    def __init__(self, buff=None) -> None:
        header = struct.unpack('<BBHHHBBH4S4S', buff)
        self.ver - header[0] >> 4   # Retrieve High order nibble of the byte by right shifting 4 places
        self.ihl = header[0] & 0xf  # Retrieve Low Order (Last 4) nibble of the byte using binary AND evaluation 

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
        self.src_address = ipaddress.ip_address(self.dst)

        # map protocol constants to their names
        self.protocol_map = {1: "ICP", 6: "TCP", 17: "UDP"}
