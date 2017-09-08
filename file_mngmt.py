import os
import re
import paramiko

from yaml import load, dump, YAMLError
from  protocol_translation import proto_trans
import requests
import json
#not used anymore, I used ssh key between the devices, such that 
# I don't need to provide username password

class file_management:
  dhcp_leases = {}
  faucet_yaml = {}
  blocked_macs = []
  faucet_joined_dev = []
  faucet_learned_macs = []
  servers ={}
  def __init__(self, servers):
    self.servers = servers

  def update_all(self):
    self.update_dhcp_leases()
    print('len dhcp_leases: ', len(self.dhcp_leases))

    self.update_faucet_yaml()
    print('len faucet_yaml: ', len(self.faucet_yaml))

    self.update_faucet_joined_dev()
    print('len faucet_joined_dev: ', len(self.faucet_joined_dev))

    self.update_blocked_macs()
    print('len blocked_macs: ', len(self.blocked_macs))


  def reset_faucet_config(self):
      os.system("ssh moh@192.168.5.8 cp etc/ryu/faucet/faucet-def.yaml etc/ryu/faucet/faucet.yaml")

  def ssh_command(self, host_name, port, user_name, password, command):
     ssh_client = paramiko.SSHClient(self)

     out = ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
     out = ssh_client.load_system_host_keys()
     out = ssh_client.connect(host_name,port, user_name, password)
     stdin, stdout, stderr = ssh_client.exec_command(command)
     return [stdout, stdin, stderr]


  def update_dhcp_leases(self):
     os.system("scp pi@192.168.10.254:/var/lib/misc/dnsmasq.leases dnsmasq.leases")
     with open('dnsmasq.leases', 'r') as file_stream:
       leases = file_stream.read()

     lines = leases.split('\n')

     self.dhcp_leases = {}
     for line in lines:
       cols = line.split()
       if(len(cols)>3):
          self.dhcp_leases[cols[1].upper()] = {'ip':cols[2],'hostname': cols[3]}
     # add dhcp server ip, mac
     self.dhcp_leases['B8:27:EB:E6:70:F1'] =  {'ip': '192.168.10.254','hostname': 'piDHCPServer'}


  # get faucet yaml file using ssh client 
  def update_faucet_yaml(self):
     os.system("scp moh@192.168.5.8:/home/moh/etc/ryu/faucet/faucet.yaml faucet.yaml")

     with open('faucet.yaml', 'r') as file_stream:
       try:
         faucet_conf =  load(file_stream)
       except YAMLError as exc:
          print(exc)

     self.faucet_yaml = faucet_conf


  # write faucet yaml file and restart fuacet using ssh
  def set_faucet_yaml(self):      
     #delete the added rule_id attribute before you write it to the file
      wifi_acl_list = self.faucet_yaml['acls']['wifi_acl']
      for i in range(0, len(wifi_acl_list) ) :
          if 'rule_id' in self.faucet_yaml['acls']['wifi_acl'][i]['rule']:
             del self.faucet_yaml['acls']['wifi_acl'][i]['rule']['rule_id']

      with open("faucet.yaml", "w") as fd:
          dump(self.faucet_yaml, fd, default_flow_style=False)
      # it works as long as you set ssh key between the two hosts
      os.system("scp faucet.yaml moh@192.168.5.8:/home/moh/etc/ryu/faucet/faucet.yaml")
      os.system("ssh root@192.168.5.8 docker exec reannz_faucet pkill -HUP -f faucet.faucet") #pkill -HUP -f faucet.faucet")


  #request faucet status through promethous 
  def update_faucet_joined_dev(self):
      resp= requests.get('http://192.168.5.8:9244').content
      faucet_resp = str(resp)
      learned_macs = re.findall(r'learned_macs{[\w+,\=,\",},\s]+\d{1,}',faucet_resp)
      mac_pad = '00:00:00:00:00:00'
      self.faucet_learned_macs = []
      for line in learned_macs:
         mac = line.split()[-1]
         if mac != '0':
            mac = hex(int(mac))
            mac =  mac[2:] # remove 0x
            mac =  ':'.join(format(s, '02x') for s in bytes.fromhex(mac))
            mac = mac_pad[:17-len(mac)] + mac
            self.faucet_learned_macs.append(mac)
      
      

      self.faucet_joined_dev = self.get_dev_info(self.faucet_learned_macs)
  

  def update_blocked_macs(self):
      #Src dst proto from mirror port, sniffed by sniffed_macs.py
      with open('sniffed_macs.json','r') as fp:
        sniffed_macs = json.load(fp)

      #ignor other packets that are not from mirror interface
      ignored_mac=["00:50:b6:18:ec:b6","98:90:96:a2:11:cc",
            "00:1b:21:d3:1f:62", "00:00:00:00:00:00","b8:27:eb:e6:70:f1"]    
      # sniffed_macs - joined_dev = blocked_dev (i.e.new devices)
      self.blocked_macs = []
      for mac in sniffed_macs.keys():
         notfound=True
         for dev in self.faucet_learned_macs:
            if mac == dev:
               notfound=False
               break
         if notfound and mac not in ignored_mac:
             self.blocked_macs.append(mac)
    

  def get_dev_info(self, dev_mac):

      dev_macs = dev_mac
      if not isinstance(dev_mac, list):
         dev_macs = [dev_mac]

      dev_macs_info = []
      for mac in dev_macs:
         mac = mac.upper()
         if mac in self.dhcp_leases.keys():
            name = self.dhcp_leases[mac]['hostname']
            ip = self.dhcp_leases[mac]['ip']
            dev_macs_info.append({'name':name,'ip':ip,'mac':mac,'desc': None})
         else:
            dev_macs_info.append({'name': None,'ip': None,'mac':mac,'desc': None })

      if not isinstance(dev_mac, list):
         return dev_macs_info[0]

      return dev_macs_info    


  def net_topology(self, net_policy):

    ignored_mac = ['ff:ff:ff:ff:ff:ff']

    home_net_topo = {
      "type": "NetworkGraph",
      "label": "Home Network Topology",
      "protocol": "OpenFlow",
      "version": "1.3",
       "nodes": [],
       "links": []
    }

    nodes = []
    for dev in self.faucet_joined_dev:
      node = {
              "id": dev['mac'].lower(),
              "label": dev['name'],
              "properties": {
                "ip": dev['ip'],
                "gateway": True if self.servers['gW_Server'].lower() == dev['mac'].lower() else False
              }
          }
      nodes.append(node)

    links = []
    for policy in net_policy:
      if not(policy['from_mac'].lower() in self.faucet_learned_macs and \
         policy['to_mac'].lower() in self.faucet_learned_macs): 
        continue
      link_type = "wireless" if policy['from_mac'].lower() not in self.servers.values() \
                                or policy['to_mac'].lower() not in self.servers.values() else "ethernet"
      link = {
              "source": policy['from_mac'].lower(),
              "target": policy['to_mac'].lower(),
              "cost": 1,
              "properties": {
                  "tx": 0.900,
                  "rx": 0.497,
                  "bitrate": "100 mbit/s",
                  "type": link_type,
                  "protocols": policy['service']['service_name']
              }
          }
      links.append(link)
    
    home_net_topo['nodes'] = nodes
    home_net_topo['links'] = links
    with open('static/home_net.json','w') as fd:
      json.dump(home_net_topo, fd)    