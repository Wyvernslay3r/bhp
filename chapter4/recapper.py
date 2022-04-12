from scapy.all import TCP, rdpcap
import collections
import os
import re
import sys
import zlib

OUTDIR = '~/Desktop/Pictures'
PCAPS = '~/Downloads'

response = collections.namedtuple('Response',['header', 'payload'] )

def get_header(payload):
    try:
        raw_header = payload[:payload.index(b'\r\n\r\n')+2]
    except ValueError:
        sys.stdout.write('-')
        sys.stdout.flush()
        return None

    header = dict(re.findall(r'(?P<name>.*?): (?P<value>.*?)\r\n', raw_header.decode()))

    if 'Content-Type' not in header:
        return None
    
    return header