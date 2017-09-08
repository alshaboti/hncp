from protocol_translation import proto_trans
import collections


default_entity  = {
  'ip': 'Any', 
  'mac': 'Any',
  'port': 'Any'
}


default_rule = {'actions':  {'allow': 0},
              'dl_src': 'Any',
              'dl_dst': 'Any',
              'dl_type': 'Any',
              'nw_src': 'Any',
              'nw_dst': 'Any',
              'nw_proto': 'Any',
              'tp_src': 'Any',
              'tp_dst': 'Any'}

flatten = lambda l: [item for sublist in l for item in sublist]

def trim_rule(rule):
  r = {}
  for k, v in rule.items():
    if v != 'Any':
       r[k]  = v
  return r
       
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

def get_dl_rule(from_mac, dl_type, to_mac=default_rule['dl_dst'] , allow=1):  
    rule = []
    from_rule = default_rule.copy()
    from_rule['actions']['allow'] = allow
    from_rule['dl_src'] = from_mac

    from_rule['dl_dst'] = to_mac

    from_rule['dl_type'] = dl_type 
    rule.append(from_rule)

    to_rule = default_rule.copy()
    to_rule['actions']['allow'] = allow    
    to_rule['dl_src'] = to_mac

    to_rule['dl_dst'] = to_mac

    to_rule['dl_type'] = dl_type 
    rule.append(to_rule)
    return rule

def get_ip_rule(from_entity, to_entity, nw_proto, allow=1):
    rule = get_dl_rule(from_entity, to_entity,
                      '0x0800' , allow=1)    
    rule[0]['nw_proto'] = nw_proto
    rule[1]['nw_proto'] = nw_proto

    return rule

def get_tcp_rule(from_entity, to_entity, allow=1):
    rule = get_ip_rule(from_entity, to_entity, 6, allow)
    return rule  

def get_udp_rule(from_entity, to_entity, allow=1):
    rule = get_ip_rule(from_entity, to_entity, 17, allow)
    return rule  

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


def get_http_rule(mac, allow=1):
    rule = []
    rule.append({'rule':{
               'dl_dst': 'b8:27:eb:e6:70:f1',
               'dl_src': mac,
               'dl_type': '0x800',
               'nw_proto': 6,
               'tp_dst': 80,
               'actions':{'allow': allow}
                       }
               })
    rule.append({'rule':{
               'dl_dst': mac,
               'dl_src': 'b8:27:eb:e6:70:f1',
               'dl_type': '0x800',
               'nw_proto': 6,
               'nw_src': '192.168.10.254',
               'tp_src': 80,
               'actions':{'allow': allow}
                       }
               })
    return rule

def get_ssh_rule(from_mac, to_mac, allow=1):
    rule = []
    rule.append({'rule':{
               'dl_dst': to_mac,
               'dl_src': from_mac,
               'dl_type': '0x800',
               'nw_proto': 6,
               'tp_dst': 22,
               'actions':{'allow': allow}
                       }
               })
    rule.append({'rule':{
               'dl_dst': from_mac,
               'dl_src': to_mac,
               'dl_type': '0x800',
               'nw_proto': 6,
               'tp_src': 22,
               'actions':{'allow': allow}
                       }
               })
    return rule

# using dl_type
def is_arp_rule(rule):
    if rule['dl_type'] !=  default_rule['dl_type'] and \
       int(rule['dl_type'], 16) == int('0x0806',16):
         return True
    return False


def get_dns_rule(mac, allow=1):
    rule = []
    rule.append({'rule':{
               'dl_src': mac,
               'dl_type': '0x800',
               'nw_proto': 17,
               'tp_dst': 53,
               'actions':{'allow': allow}
                       }
               })
    # rule.append({'rule':{
    #            'dl_dst': mac,
    #            'dl_type': '0x800',
    #            'nw_proto': 17,
    #            'tp_src': 53,
    #            'actions':{'allow': allow}
    #                    }
    #            })
    return rule

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
    # dhcp_rule.append({'rule':{
    #            'dl_dst': mac,
    #            'dl_type': '0x800',
    #            'nw_proto': 17,
    #            'nw_src': '192.168.10.254',
    #            'tp_src': 67,
    #            'tp_dst': 68,
    #            'actions':{'allow': allow}
    #                    }
    #            })
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
#by default add the rules before the last 2 rules
def insert_rules(rules, acl, offset = 2):
    acl_size = len (acl)
    for rule in rules:
        acl.insert( acl_size - offset , rule)
        acl_size += 1
    return acl_size, acl

def add_join_rules(mac, acl):
    rules = []
    arp_rule = get_arp_rule(mac)
    rules.append(arp_rule)

    dhcp_rule = get_dhcp_rule(mac)
    rules.append(dhcp_rule)

    dns_rule = get_dns_rule(mac)
    rules.append(dns_rule)

    icmp_rule = get_icmp_rule(mac)
    rules.append(icmp_rule)
    rules = flatten(rules)
    insert_rules(rules, acl)


def add_rule(from_mac, to_mac, port_no, acl_from, acl_to, allow=1):

     
    rule = []
    rule.append({'rule':{
               'dl_dst': to_mac,
               'dl_src': from_mac,
               'dl_type': '0x800',
               'nw_proto':6,
               'tp_dst': port_no,
               'actions':{'allow': allow}
                       }
               })

    rule.append({'rule':{
               'dl_dst': from_mac,
               'dl_src': to_mac,
               'dl_type': '0x800',
               'nw_proto': 6,
               'tp_src': port_no,
               'actions':{'allow': allow}
                       }
               })

    insert_rules([rule[0]], acl_to)
    insert_rules([rule[1]], acl_from )

