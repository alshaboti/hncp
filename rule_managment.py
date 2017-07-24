from protocol_translation import proto_trans

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
    if 'dl_type' in list(rule['rule'].keys()) and \
       int(rule['rule']['dl_type'], 16) == int('0x0806',16):
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
    keys = list(rule['rule'].keys())
    if 'dl_type' in keys and int(rule['rule']['dl_type'], 16) == \
       int('0x0800',16) and 'nw_proto' in keys and int(rule['rule']['nw_proto']) == 17:
       if 'tp_src' in keys and 'tp_dst' in keys:
         if int(rule['rule']['tp_src']) == 67 and int(rule['rule']['tp_dst']) in 68 :
           return 1
         elif int(rule['rule']['tp_src']) == 67 and int(rule['rule']['tp_dst']) in 68 :
           return 2
    return 0


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
    keys = list(rule['rule'].keys())
    if 'dl_type' in keys and int(rule['rule']['dl_type'], 16) == \
       int('0x0800',16) and 'nw_proto' in keys and int(rule['rule']['nw_proto']) == 1:
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



