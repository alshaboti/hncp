from protocol_translation import proto_trans
import collections

default_rule = {'actions':  {'allow': 0, 'output':{'port': None}, 'mirror':None},
              'dl_src': 'Any',
              'dl_dst': 'Any',
              'dl_type': 'Any',
              'nw_src': 'Any',
              'nw_dst': 'Any',
              'nw_proto': 'Any',
              'tp_src': 'Any',
              'tp_dst': 'Any'}

def update_rule(rule):
    def update(d, u):
       for k, v in u.items():
           if isinstance(v, collections.Mapping):
               r = update(d.get(k, {}), v)
               d[k] = r
           else:
               d[k] = u[k]
       return d
    def_rule = default_rule.copy()              
    update(def_rule,rule)
    return def_rule

def get_rule_service_name(rule):

  service_name = "UnKnown"
  if rule['tp_src'] != 'Any':
     service_name = proto_trans['tp_proto'][rule['tp_src']] 
  elif rule['tp_dst'] != 'Any':
     service_name = proto_trans['tp_proto'][rule['tp_dst']] 
  elif rule['nw_proto'] != 'Any':
     service_name = proto_trans['nw_proto'][rule['nw_proto']] 
  elif rule['tp_dst'] != 'Any':
    service_name = proto_trans['tp_proto'][rule['tp_dst']] 
  elif rule['dl_type'] != 'Any':
    dl_type = int(rule['dl_type'],16)
    service_name = proto_trans['dl_type'][dl_type] 
  else:
     service_name='All Services'

  return service_name

def get_arp_rule(mac, allow=1):
    arp_rule = []
    arp_rule.append({'rule': {
                  'actions':{ 'allow': allow },
                  'dl_src': mac,
                   'dl_type': '0x0806'
                }
              })
    arp_rule.append({'rule': {
                  'actions':{ 'allow': allow },      
                  'dl_dst': mac,
                  'dl_type': '0x0806'
                } 
              })
    return arp_rule

# using dl_type
def is_arp_rule(rule):
    if rule['dl_type'] !=  default_rule['dl_type'] and \
       int(rule['dl_type'], 16) == int('0x0806',16):
         return True
    return False

def get_dhcp_rule(mac, allow=1):
    dhcp_rule = []
    dhcp_rule.append({'rule':{
               'dl_dst': 'ff:ff:ff:ff:ff:ff',
               'dl_src': mac,
               'dl_type': '0x800',
               'nw_proto': 17,
               'nw_src': '0.0.0.0',
               'nw_dst': '255.255.255.255',
               'tp_src': 68,
               'tp_dst': 67,
               'actions':{'allow': allow}
                       }
               })
    dhcp_rule.append({'rule':{
               'dl_dst': mac,
               'dl_type': '0x800',
               'nw_proto': 17,
               'nw_src': '192.168.10.254',
               'tp_src': 67,
               'tp_dst': 68,
               'actions':{'allow': allow}
                       }
               })
    return dhcp_rule

# using dl_type,nw_proto, tp_src, tp_dst
def is_dhcp_rule(rule):
 
    if rule['dl_type'] !=  default_rule['dl_type'] and \
       int(rule['dl_type'], 16) == int('0x0800',16) \
       and rule['nw_proto'] !=  default_rule['nw_proto'] \
       and int(rule['nw_proto']) == 17:

       if rule['tp_src'] !=  default_rule['tp_src'] and \
          rule['tp_dst'] !=  default_rule['tp_dst'] :

         if rule['tp_src'] == 67 and rule['tp_dst'] == 68 :
           return True, False
         elif rule['tp_src'] == 68 and rule['tp_dst'] == 67 :
           return True, True
           
    return False, False


def get_icmp_rule(mac, allow=1):
    icmp_rule = []
    icmp_rule.append({'rule': {
                  'actions':{ 'allow': allow},
                  'nw_proto': 1 ,
                  'dl_src': mac,
                   'dl_type': '0x0800'
                }
              })
    icmp_rule.append({'rule': {
                  'actions':{ 'allow': allow},
                  'nw_proto': 1,
                  'dl_dst': mac,
                  'dl_type': '0x0800'
                }
              })
    return icmp_rule

# using dl_type,nw_proto, tp_src, tp_dst
def is_icmp_rule(rule):
    
    if rule['dl_type'] !=  default_rule['dl_type'] and \
       int(rule['dl_type'], 16) == int('0x0800',16) and \
       rule['nw_proto'] !=  default_rule['nw_proto'] and \
       rule['nw_proto'] == 1:
         return True
    return False

#by default add the rules before the last 2 rules
def add_rules(rules, acl, offset = 2):
    acl_size = len (acl)
    for rule in rules:
        acl.insert( acl_size - offset , rule)
        acl_size += 1
    return acl_size, acl

def add_join_rules(mac, acl):
    arp_rule = get_arp_rule(mac, 1)
    add_rules(arp_rule, acl)

    dhcp_rule = get_dhcp_rule(mac, 1)
    add_rules(dhcp_rule, acl)

    icmp_rule = get_icmp_rule(mac, 1)
    add_rules(icmp_rule, acl)



