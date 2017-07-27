# HTTP server for HNCP

from flask import Flask, render_template, request, redirect
import requests
import json
import paramiko
from yaml import load, dump, YAMLError
from  protocol_translation import proto_trans
import os, sys
import re


#for login after: pip3 install flask-login flask-sqlalchemy
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from flask_login import current_user


import rule_managment as rule_mngmt 
from rule_managment import default_rule



app = Flask(__name__)

servers = {'http_server':'00:1b:21:d3:1f:62','gW_Server': 'b8:27:eb:e6:70:f1'}

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////home/moh/flaskenv/login.db'
app.config['SECRET_KEY'] = 'sdn.wifi'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)



class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True)
    password = db.Column(db.String(30)) 


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def login_page():
    if current_user.is_authenticated:
       return redirect('/home')
    else:
       return render_template('login.html')


@app.route('/login', methods=['POST'])
def index():
    user = User.query.filter_by(username=request.form['uname'], password = request.form['pwd']).first()
    if user is not None:
      login_user(user)
      return redirect('/home')
    return 'Fail to login, try agian!'

@app.route('/logout')
@login_required
def logout():
   logout_user()
   return 'You are now logged out! '

@app.route('/home')
@login_required
def home():
    # get IP, hostname from DHCP server
    global dev_info
    dev_info = get_dhcp_leases()
    print('dev_info OK')
    sys.stdout.flush()

    # request learned mac from faucet promethous 192.168.5.8:9244
    joined_dev_macs = get_faucet_macs()
    print('joined_dev_macs OK')
    sys.stdout.flush()

    #  add dev IP and hostname
    global joined_dev_info    
    joined_dev_info = get_dev_info(joined_dev_macs)
    print('joined_dev_info OK')
    sys.stdout.flush()

    # get faucet.yaml file
    global faucet_yaml
    faucet_yaml = get_faucet_yaml()
    print('faucet_yaml OK')
    sys.stdout.flush()

    blocked_dev_info = get_blocked_devs(joined_dev_macs)

    # get faucet policy
    # let's make it static at first 
    net_policy = get_faucet_policy(faucet_yaml['acls']['wifi_acl'])

    return render_template('index.html', joined_dev=joined_dev_info, 
    	blocked_dev=blocked_dev_info, net_policy= net_policy )

#Allow DHCP service for this device
@app.route('/join', methods=['post'])
@login_required
def join():
    rule_mngmt.add_join_rules(request.form['mac'], faucet_yaml['acls']['wifi_acl'])

    set_faucet_yaml()

    return redirect('/home')


@app.route('/delete_policy', methods=['POST'])
@login_required
def network_policy():
    delete_faucet_rule( int(request.form['rule_id']) )
    set_faucet_yaml()
#   return 'Rule is deleted successfully!'
    args={"parag":"Rule is deleted successfully!","link":"http://192.168.5.3:5000/home", "btn_value":"Home"} 
    return render_template('done.html', args=args )


@app.route('/new_policy', methods=['GET'])
@login_required
def new_policy():
    args = {}
    args['local_devs_list'] = joined_dev_info
    args['services_dict'] = proto_trans['tp_proto']

    return render_template('new_policy.html', args = args)

@app.route('/add_policy', methods=['POST'])
@login_required
def add_policy():
  acl_to = acl_from = faucet_yaml['acls']['wifi_acl']  
  
  if request.form['to_entity'].lower() == servers['http_server']:
     acl_to = faucet_yaml['acls']['port3_acl']

  rule_mngmt.add_rule(request.form['from_entity'], 
         request.form['to_entity'], int(request.form['service']), 
         acl_from, acl_to)
  set_faucet_yaml()

  args={"parag":"Rule is added successfully!","link":"http://192.168.5.3:5000/home", "btn_value":"Home"} 
  return render_template('done.html', args=args )

@app.route('/reset', methods=['GET'])
@login_required
def reset_faucet_config():
    os.system("ssh moh@192.168.5.8 cp etc/ryu/faucet/faucet-def.yaml etc/ryu/faucet/faucet.yaml")
    return redirect('/home')


@app.errorhandler(404)
def not_found(error):
    return 'Try again, error!'


def delete_faucet_rule(rule_id):

    wifi_acl_list = faucet_yaml['acls']['wifi_acl']
    copy_acl_list = []
    for i in range(0, len(wifi_acl_list) ) :
        rule = wifi_acl_list[i]['rule']
        if rule['rule_id'] == rule_id:        
           continue        
        copy_acl_list.append(wifi_acl_list[i])

    faucet_yaml['acls']['wifi_acl'] = copy_acl_list


def get_dev_info(dev_mac):
    dev_macs = dev_mac
    if not isinstance(dev_mac, list):
       dev_macs = [dev_mac]

    dev_macs_info = []
    for mac in dev_macs:
       mac = mac.upper()
       if mac in dev_info.keys():
          name = dev_info[mac]['hostname']
          ip = dev_info[mac]['ip']
          dev_macs_info.append({'name':name,'ip':ip,'mac':mac,'desc': None})
       else:
          dev_macs_info.append({'name': None,'ip': None,'mac':mac,'desc': None })

    if not isinstance(dev_mac, list):
       return dev_macs_info[0]

    return dev_macs_info

#request faucet status through promethous 
def get_faucet_macs():
    resp= requests.get('http://192.168.5.8:9244').content
    faucet_resp = str(resp)
    learned_macs = re.findall(r'learned_macs{[\w+,\=,\",},\s]+\d{1,}',faucet_resp)
    mac_pad = '00:00:00:00:00:00'
    faucet_learned_macs = []
    for line in learned_macs:
       mac = line.split()[-1]
       if mac != '0':
          mac = hex(int(mac))
          mac =  mac[2:] # remove 0x
          mac =  ':'.join(format(s, '02x') for s in bytes.fromhex(mac))
          mac = mac_pad[:17-len(mac)] + mac
          faucet_learned_macs.append(mac)

    return  faucet_learned_macs

# get faucet yaml file using ssh client 
def get_faucet_yaml():
   os.system("scp moh@192.168.5.8:/home/moh/etc/ryu/faucet/faucet.yaml faucet.yaml")

   with open('faucet.yaml', 'r') as file_stream:
     try:
       faucet_conf =  load(file_stream)
     except YAMLError as exc:
        print(exc)

   return faucet_conf


# write faucet yaml file and restart fuacet using ssh
def set_faucet_yaml():
    
    wifi_acl_list = faucet_yaml['acls']['wifi_acl']
    for i in range(0, len(wifi_acl_list) ) :
        if 'rule_id' in faucet_yaml['acls']['wifi_acl'][i]['rule']:
           del faucet_yaml['acls']['wifi_acl'][i]['rule']['rule_id']

    with open("faucet.yaml", "w") as fd:
        dump(faucet_yaml, fd, default_flow_style=False)
    # it works as long as you set ssh key between the two hosts
    os.system("scp faucet.yaml moh@192.168.5.8:/home/moh/etc/ryu/faucet/faucet.yaml")
    os.system("ssh root@192.168.5.8 docker exec reannz_faucet pkill -HUP -f faucet.faucet") #pkill -HUP -f faucet.faucet")


def get_blocked_devs(joined_dev_macs):
    #Src dst proto from mirror port, sniffed by sniffed_macs.py
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

    return get_dev_info( blocked_macs )


def check_rev_rule(srcs, dsts, protos, rule):
    # check if rule is rev of an existing one
    is_dhcp, is_rev = rule_mngmt.is_dhcp_rule(rule)
    for idx in range(0, len(srcs['dl_src'])):
      if srcs['dl_src'][idx] == rule['dl_dst'] and \
         ( is_dhcp or dsts['dl_dst'][idx] == rule['dl_src']) and \
         protos['dl_type'][idx] == rule['dl_type'] and \
         protos['nw_proto'][idx] == rule['nw_proto'] and \
         srcs['tp_src'][idx] == rule['tp_dst'] and \
         dsts['tp_dst'][idx] == rule['tp_src']:
         return True, idx
    return False, -1


def get_faucet_policy(acl_list):

   policy = []
   srcs = {'dl_src':[], 'nw_src':[], 'tp_src':[]}
   dsts = {'dl_dst':[],'nw_dst':[], 'tp_dst':[]}
   protos = {'dl_type':[], 'nw_proto':[]}
   
   for idx in range(0, len(acl_list)):      
       
       rule = rule_mngmt.update_rule(acl_list[idx]['rule'])            
 
       is_reverse, r_id = check_rev_rule(srcs,dsts,protos, rule)      
       rule_id = idx if r_id == -1 else r_id          
       
       acl_list[idx]['rule']['rule_id'] = rule_id

       srcs['dl_src'].append(rule['dl_src'])
       dsts['dl_dst'].append(rule['dl_dst'])
       srcs['tp_src'].append(rule['tp_src']) 
       dsts['tp_dst'].append(rule['tp_dst'])
       protos['dl_type'].append(rule['dl_type'])
       protos['nw_proto'].append(rule['nw_proto'])
       
       if is_reverse:
          continue

       from_host = get_dev_info(rule['dl_src'])['name']
       to_host = get_dev_info(rule['dl_dst'])['name']

       service = {'service_name': rule_mngmt.get_rule_service_name(rule), 
                  'actions': rule['actions']['allow']}
       new_policy = {'from_mac': rule['dl_src'],
                     'from_host': from_host,
                     'to_mac': rule['dl_dst'],
                     'to_host': to_host,
                     'from_ip': rule ['nw_src'],
                     'to_ip': rule['nw_dst'],
                     'service': service, 
                     'idx': rule_id,
                     'is_rev': is_reverse 
                    }
       policy.append(new_policy)
   return policy


def get_dhcp_leases():

   os.system("scp pi@192.168.10.254:/var/lib/misc/dnsmasq.leases dnsmasq.leases")
   with open('dnsmasq.leases', 'r') as file_stream:
     leases = file_stream.read()

   lines = leases.split('\n')

   dhcp_leases = {}
   for line in lines:
     cols = line.split()
     if(len(cols)>3):
        dhcp_leases[cols[1].upper()] = {'ip':cols[2],'hostname': cols[3]}
   # add dhcp server ip, mac
   dhcp_leases['B8:27:EB:E6:70:F1'] =  {'ip': '192.168.10.254','hostname': 'piDHCPServer'}
   return dhcp_leases


#not used anymore, I used ssh key between the devices, such that 
# I don't need to provide username password
def ssh_command(host_name, port, user_name, password, command):
   ssh_client = paramiko.SSHClient()

   out = ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
   out = ssh_client.load_system_host_keys()
   out = ssh_client.connect(host_name,port, user_name, password)
   stdin, stdout, stderr = ssh_client.exec_command(command)
   return [stdout, stdin, stderr]


