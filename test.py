import json
from hashlib import sha256
import rule_managment as rule_mgmnt
from yaml import load, dump, YAMLError

def is_conditional(rule):
    # valid rule with one key should be actions
    return len(rule.keys()) == 1

def update_acl_rule(rule):
    def update(d, u):
       for k, v in u.items():
           if isinstance(v, collections.Mapping):
               r = update(d.get(k, {}), v)
               d[k] = r
           else:
               d[k] = u[k]
       return d

    default_rule = {'actions':  {'allow': 0, 'output':{'port': None}, 'mirror':None, 'dl_dst': None},
                    'dl_src': None ,
                    'dl_dst': None,
                    'dl_type': None,
                    'nw_src': None,
                    'nw_dst': None,
                    'nw_proto': None,
                    'tp_src': None,
                    'tp_dst': None}
    update(default_rule,rule)
    return default_rule

if __name__ == '__main__':
   with open('faucet.yaml', 'r') as file_stream:
     try:
       faucet_conf =  load(file_stream)
     except YAMLError as exc:
       print(exc)

   top_level = faucet_conf.keys()
   print (top_level)   
   acls = faucet_conf['acls'].keys()
   print(acls)

   #select one for testing
   wifi_acl_list = faucet_conf['acls']['wifi_acl']
   print(wifi_acl_list)

   for rule_dict in wifi_acl_list:
      rule = rule_dict['rule']
      rule_keys = rule.keys()
      print(rule_keys)
      print('is_conditional: ', is_conditional(rule))
      if is_conditional(rule):
        print(" From All to All: All services")
      else: #check condition
        l2 = l2_condition(rule)
        l3 = l3_condition(rule)
        l4 = l4_condition(rule)
        from_ = from_condition(rule)
        to_ = to_condition(rule)



       print()

   # rules1 = rule_mgmnt.get_dhcp_rule("aa:aa:aa:aa:aa:aa")   
   # rule11 = json.dumps(rules1[0], sort_keys=True).encode('utf-8')
   # hash1 = sha256( rule11 ).hexdigest()
   # rules2 = rule_mgmnt.get_dhcp_rule("aa:aa:aa:aa:aa:aa")   
   # rule22 = json.dumps(rules2[0], sort_keys=True).encode('utf-8')
   # hash2 = sha256( rule22).hexdigest()
   # if hash1 == hash2:
   #    print (hash1)
   #    print (hash2)

   ##################################
   # rules = []
   # r = rule_mgmnt.get_dhcp_rule("aa:aa:aa:aa:aa:aa")
   # rule_mgmnt.add_rules(r, rules, 0)

   # r = rule_mgmnt.get_arp_rule("aa:aa:aa:aa:aa:aa")
   # rule_mgmnt.add_rules(r, rules, 0)

   # r = rule_mgmnt.get_icmp_rule("aa:aa:aa:aa:aa:aa")
   # rule_mgmnt.add_rules(r, rules, 0)
   # print (rules)

