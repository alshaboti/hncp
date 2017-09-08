import socket
import struct
import json

from scapy.all import *

############# MODIFY THIS PART IF NECESSARY ###############
interface = 'enp2s0'

def cap_ARP(pkt):
    src = pkt[0][ARP].hwsrc
    dst = pkt[0][ARP].hwdst
    
    if src not in mac_dic.keys():
        mac_dic[src] = {'dst': dst}
        print(src, ': ', dst)
        with open('sniffed_macs.json', 'w') as fp:
           json.dump(mac_dic,fp)


#qdcount - query dns count,
#ancount - dns answer count
#dns.an[0] is the 1st DNSRR,
#dns.an[1] is the 2nd DNSRR,
def cap_DNS(pkt):  
  print('capture DNS!')
  # print(pkt.show())
  # if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
  #   print( pkt[IP].src, ' ', pkt.getlayer(DNS).qd.qname)


  if pkt.haslayer(DNSQR): #DNSQR: DNS question record
    for x in range(pkt[DNS].ancount):
      print (pkt[DNSRR][x].rdata)
  if pkt.haslayer(DNSRR): #DNSRR DNS Resource Record
    dn = pkt[DNS][DNSRR].rrname.decode("utf-8")[:-1]
    ip = pkt[DNS][DNSRR].rdata
    print(ip, ': ', dn)
    if ip not in dns_dic.keys():
        dns_dic[ip] = {'dn': dn}
        with open('sniffed_dns.json', 'w') as fp:
           json.dump(dns_dic,fp)


def cap(pkt):
  if pkt.haslayer(DNS):
    cap_DNS(pkt)
  elif pkt.haslayer(ARP):
    cap_ARP(pkt)


def main():    
    with open('sniffed_macs.json', 'w') as fp:
       json.dump(mac_dic,fp)   

    with open('sniffed_dns.json', 'w') as fp:
       json.dump(dns_dic,fp)           
    #sniff(iface=interface,lfilter=lambda x: x.haslayer(DNS), prn=cap_DNS)
    sniff(iface=interface, prn=cap)

mac_dic = {}
dns_dic = {}
if __name__ == '__main__':
  main()

# sudo tcpdump -i enp2s0 -vvv -s 0 -l -n port 53