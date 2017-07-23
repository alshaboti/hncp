from yaml import load, dump, YAMLError


def read_faucet_conf(config_file):
    with open(config_file, 'r') as stream:
        try:
           return load(stream)
        except YAMLError as exc:
            print(exc)

if __name__ == '__main__':

  faucet_conf = read_faucet_conf("testFaucet.yaml")
  print(faucet_conf)
  print("faucet_conf all")

  acls = faucet_conf['acls']

  # let's make it static at first 
  wifi_acl_list = acls['wifi_acl']
  for rule_dict in wifi_acl_list:
     print(rule_dict['rule']['semantic']) 
     
