# RUN me: $ sudo python3 unauth_hosts.py 
import socket
import struct
import json

def main():
    mac_dic = {}
    con = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, add = con.recvfrom(65536)
        dst, src, proto, data = eth_frame(raw_data)

        #ignor other packets that are not from mirror interface
        ignored_mac=["00:50:b6:18:ec:b6","98:90:96:a2:11:cc","00:1b:21:d3:1f:62"]
        if src in ignored_mac:
            continue

        if src not in mac_dic.keys():
            mac_dic[src] = {'dst': dst, 'proto': proto}
            print(mac_dic)
            #try catch
            with open('sniffed_macs.json', 'w') as fp:
               json.dump(mac_dic,fp)


def eth_frame(data):
    eth_dst, eth_src, eth_type = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_add(eth_dst), get_mac_add(eth_src), socket.htons(eth_type), data[:14]


def get_mac_add(byte_add):
    eth_add = map('{:02x}'.format, byte_add)
    return ":".join(eth_add).lower()

main()
