from flask import Flask, render_template, request
import requests
import json
import paramiko

app = Flask(__name__)

@app.route('/')
def index():

    # get IP, hostname from DHCP server 
    dhcp_leases = get_dhcp_leases()

    # request learned mac from faucet promethous 192.168.5.8:9244
    joined_dev_macs = req_faucet_macs()

    # TODO: add dev IP and hostname
    joined_dev_info = update_dev_info(dhcp_leases, joined_dev_macs)

    #Src dst proto from mirror port, sniffed by unauth_hosts.py
    with open('sniffed_macs.json','r') as fp:
      sniffed_macs = json.load(fp)

    # sniffed_macs - joined_dev = blocked_dev (i.e.new devices)
    blocked_macs = []
    for mac in sniffed_macs.keys():
       notfound=True
       for dev in joined_dev_macs:
          if mac == dev:
             notfound=False
             break
       if notfound:
           blocked_macs.append(mac) 

    blocked_dev_info = update_dev_info( dhcp_leases, blocked_macs )
#    for i in range(0, len(blocked_dev_info)):
 #      blocked_dev_info[i]["allow"] = "unchecked"
  #     blocked_dev_info[i]["deny"] = "checked"
 
    net_policy = [{'from':'android121', 'to': 'Internet', 'services': 
       [{'service_name': 'all', 'decision':'checked'},
       {'service_name': 'HTTPS', 'decision':'unchecked'},
       {'service_name': 'SSH', 'decision':'unchecked'},
       {'service_name': 'MQTT','decision':'unchecked'},
       {'service_name': 'CoAP', 'decision':'unchecked'} ] 
    }]

    return render_template('index.html', joined_dev=joined_dev_info, 
    	blocked_dev=blocked_dev_info, net_policy= net_policy )


@app.route('/join', methods=['post'])
def join():
    if request.method == 'POST':
    	return  request.form['decision'] + ' mac is '+ request.form['mac']
    else:
    	return 'not post function!!'

@app.route('/network_policy', methods=['post'])
def network_policy():
    if request.method == 'POST':
    	return  'from' + request.form['from'] + ' to '+ request.form['to'] 
    else:
    	return 'not post function!!' 


def update_dev_info(dev_info, dev_macs):
    dev_macs_info = []
    for mac in dev_macs:
       if mac in dev_info.keys():
          name = dev_info[mac]['hostname']
          ip = dev_info[mac]['ip']
          dev_macs_info.append({'name':name,'ip':ip,'mac':mac,'desc':'None'})
       else:
          dev_macs_info.append({'name':'None','ip':'none','mac':mac,'desc':'None'})

    return dev_macs_info


def req_faucet_macs():
    resp= requests.get('http://192.168.5.8:9244').content
    faucet_resp = str(resp)
    mac_indx = faucet_resp.find("mac=")
    faucet_auth_macs = []
    while mac_indx>0:
       start = mac_indx+5
       end = start+17
       faucet_auth_macs.append(faucet_resp[start:end])
       faucet_resp = faucet_resp[end:]
       mac_indx = faucet_resp.find("mac=")
    return  faucet_auth_macs


def get_dhcp_leases():
   leases =  ssh_command('192.168.10.254', 22, 'pi', '1leea.2mra', 'cat /var/lib/misc/dnsmasq.leases')
   #convert from unicode string to regular string
   leases =str(leases,'utf-8')
   lines = leases.split('\n')

   dhcp_leases = {}
   for line in lines:
     cols = line.split()
     if(len(cols)>3):
        dhcp_leases[cols[1]] = {'ip':cols[2],'hostname': cols[3]}

   return dhcp_leases


def ssh_command(host_name, port, user_name, password, command):
   ssh_client = paramiko.SSHClient()

   out = ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
   out = ssh_client.load_system_host_keys()
   out = ssh_client.connect(host_name,port, user_name, password)
   stdin, stdout, stderr = ssh_client.exec_command(command)
   return stdout.read()




