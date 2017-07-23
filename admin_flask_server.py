from flask import Flask, render_template, request, redirect
import requests
import json
import paramiko
from yaml import load, dump, YAMLError
from  protocol_translation import proto_trans
import collections
import os
import re


#for login after: pip3 install flask-login flask-sqlalchemy
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from flask_login import current_user


app = Flask(__name__)

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

    # request learned mac from faucet promethous 192.168.5.8:9244
    joined_dev_macs = get_faucet_macs()
    print('joined_dev_macs OK')

    #  add dev IP and hostname
    joined_dev_info = get_dev_info(joined_dev_macs)
    print('joined_dev_info OK')

    # get faucet.yaml file
    global faucet_yaml
    faucet_yaml = get_faucet_yaml()
    print('faucet_yaml OK')

    # get faucet policy
    # let's make it static at first 
    global acls
    max_group_id, net_policy = get_faucet_policy(faucet_yaml['acls']['wifi_acl'])
    acls = {'wifi_acl': {'next_group_id': max_group_id +1 } }

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

    blocked_dev_info = get_dev_info( blocked_macs )

    return render_template('index.html', joined_dev=joined_dev_info, 
    	blocked_dev=blocked_dev_info, net_policy= net_policy )

#Allow DHCP service for this device
@app.route('/join', methods=['post'])
@login_required
def join():
    add_join_rules(request)

    set_faucet_yaml()

    return redirect('/home')


@app.route('/delete_policy', methods=['POST'])
@login_required
def network_policy():
    delete_faucet_rule( int(request.form['group_id']) )
    set_faucet_yaml()
#   return 'Rule is deleted successfully!'
    args={"parag":"Rule is deleted successfully!","link":"http://192.168.5.3:5000/home", "btn_value":"Home"} 
    return render_template('done.html', args=args )


@app.route('/new_policy', methods=['GET'])
@login_required
def new_policy():
    pass


@app.route('/reset', methods=['GET'])
@login_required
def reset_faucet_config():
    os.system("ssh moh@192.168.5.8 cp etc/ryu/faucet/faucet-def.yaml etc/ryu/faucet/faucet.yaml")
    return redirect('/home')


@app.errorhandler(404)
def not_found(error):
    return 'Try again, error!'


def delete_faucet_rule(group_id):

    wifi_acl_list = faucet_yaml['acls']['wifi_acl']
    copy_acl_list = []
    for i in range(0, len(wifi_acl_list) ) :
        rule = wifi_acl_list[i]['rule']
        if rule['group_id'] == group_id:
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
    with open("faucet.yaml", "w") as fd:
        dump(faucet_yaml, fd, default_flow_style=False)
    # it works as long as you set ssh key between the two hosts
    os.system("scp faucet.yaml moh@192.168.5.8:/home/moh/etc/ryu/faucet/faucet.yaml")
    os.system("ssh root@192.168.5.8 pkill -HUP -f faucet.faucet")

def get_faucet_policy(acl_list):

   policy = []
   max_group_id = -1
   for rule_dict in acl_list:
       rule = update_acl_rule(rule_dict['rule'])

   # if rule semantic attribute is not set, then it is reverse rule (IGNORE)
       if not rule['semantic']:
         continue

       from_host = get_dev_info(rule['dl_src'])['name']
       to_host = get_dev_info(rule['dl_dst'])['name']

       max_group_id = rule['group_id'] if rule['group_id'] > max_group_id else max_group_id

       new_policy = {'from_mac': rule['dl_src'],
                     'from_host': from_host,
                     'to_mac': rule['dl_dst'],
                     'to_host': to_host,
                     'from_ip': rule ['nw_src'],
                     'to_ip': rule['nw_dst'],
                     'service': get_service(rule),
                     'semantic': rule['semantic'],
                     'group_id': rule['group_id']
                    }
       policy.append(new_policy)
   return max_group_id, policy

def get_service(rule):
  service ={}
  if rule['tp_src'] != 'Any':
     service['service_name'] = proto_trans['tp_proto'][rule['tp_src']] 
  elif rule['tp_dst'] != 'Any':
     service['service_name'] = proto_trans['tp_proto'][rule['tp_dst']] 
  elif rule['nw_proto'] != 'Any':
     service['service_name'] = proto_trans['nw_proto'][rule['nw_proto']] 
  elif rule['tp_dst'] != 'Any':
    service['service_name'] = proto_trans['tp_proto'][rule['tp_dst']] 
  elif rule['dl_type'] != 'Any':
    dl_type = int(rule['dl_type'],16)
    service['service_name'] = proto_trans['dl_type'][dl_type] 
  else:
     service['service_name']='Any'

  service['decision']= 'checked' if rule['actions']['allow'] else 'unchecked'

  return service


def update_acl_rule(rule):
    def update(d, u):
       for k, v in u.items():
           if isinstance(v, collections.Mapping):
               r = update(d.get(k, {}), v)
               d[k] = r
           else:
               d[k] = u[k]
       return d

    default_rule = {'semantic': '',
                    'group_id': -1,
                    'actions':  {'allow': 0, 'output':{'port': None}, 'mirror':None},
                    'dl_src': 'Any',
                    'dl_dst': 'Any',
                    'dl_type': 'Any',
                    'nw_src': 'Any',
                    'nw_dst': 'Any',
                    'nw_proto': 'Any',
                    'tp_src': 'Any',
                    'tp_dst': 'Any'}
    update(default_rule,rule)
    return default_rule


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


def add_join_rules(request):
    arp_rule ={'rule': {
                  'group_id':acls['wifi_acl']['next_group_id'] ,
                  'semantic': 'Allow to use ARP',
                  'actions':{ 'allow': 1},
                  'dl_src': request.form['mac'],
                   'dl_type': '0x0806'
                }
              }
    #insert the rule before the last rule (which is drop all)
    acl_size = len (faucet_yaml['acls']['wifi_acl'])
    faucet_yaml['acls']['wifi_acl'].insert( acl_size -2 , arp_rule)

    rev_arp_rule ={'rule': {
                  'group_id':acls['wifi_acl']['next_group_id'] ,
                  'actions':{ 'allow': 1},
                  'dl_dst': request.form['mac'],
                   'dl_type': '0x0806'
                } 
              }
    acl_size = len (faucet_yaml['acls']['wifi_acl'])
    faucet_yaml['acls']['wifi_acl'].insert( acl_size -2 ,rev_arp_rule)
    acls['wifi_acl']['next_group_id'] += 1


    dhcp_rule = {'rule':{'group_id': acls['wifi_acl']['next_group_id'], 
               'semantic': 'Allow DHCP service',
               'dl_dst': 'ff:ff:ff:ff:ff:ff',
               'dl_src': request.form['mac'],
               'dl_type': '0x800',
               'nw_proto': 17,
               'nw_src': '0.0.0.0',
               'nw_dst': '255.255.255.255',
               'tp_src': 68,
               'tp_dst': 67,
               'actions':{'output':{'port': 2 }}
                       }
               }
    acl_size = len (faucet_yaml['acls']['wifi_acl'])
    faucet_yaml['acls']['wifi_acl'].insert( acl_size -2 , dhcp_rule)

    rev_dhcp_rule = {'rule':{'group_id': acls['wifi_acl']['next_group_id'], 
               'dl_dst': request.form['mac'],
               'dl_type': '0x800',
               'nw_proto': 17,
               'nw_src': '192.168.10.254',
               'tp_src': 67,
               'tp_dst': 68,
               'actions':{'allow': 1}
                       }
               }
    acl_size = len (faucet_yaml['acls']['wifi_acl'])
    faucet_yaml['acls']['wifi_acl'].insert( acl_size -2 , rev_dhcp_rule)
    acls['wifi_acl']['next_group_id'] += 1

    icmp_rule ={'rule': {
                  'group_id':acls['wifi_acl']['next_group_id'] ,
                  'semantic': 'Allow to use ICMP',
                  'actions':{ 'allow': 1},
                  'nw_proto': 1 ,
                  'dl_src': request.form['mac'],
                   'dl_type': '0x0800'
                }
              }
    #insert the rule before the last rule (which is drop all)
    acl_size = len (faucet_yaml['acls']['wifi_acl'])
    faucet_yaml['acls']['wifi_acl'].insert( acl_size -2 , icmp_rule)

    rev_icmp_rule ={'rule': {
                  'group_id': acls['wifi_acl']['next_group_id'],
                  'actions': { 'allow': 1},
                  'nw_proto': 1,
                  'dl_dst': request.form['mac'],
                  'dl_type': '0x0800'
                }
              }
    #insert the rule before the last rule (which is drop all)
    acl_size = len (faucet_yaml['acls']['wifi_acl'])
    faucet_yaml['acls']['wifi_acl'].insert( acl_size -2 , rev_icmp_rule)
    acls['wifi_acl']['next_group_id'] += 1



