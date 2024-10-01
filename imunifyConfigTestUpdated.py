import json
import subprocess
import logging
import sys
import re
from datetime import datetime, timedelta



global usernames_str
global json_conf_data
logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')

apm_data = subprocess.run('apm users', shell=True, capture_output=True, text=True, check=False)
json_data = json.loads(apm_data.stdout)

# Extract usernames
usernames = [item["username"] for item in json_data["data"]]
print("List of existing apps on server:", usernames)
usernames_str = " ".join(usernames)
logging.info("List of existing apps on server:", usernames_str)

def imunify_cli_cmds(im_cmd):
#  print(im_cmd)
  output = subprocess.run(im_cmd, shell=True, capture_output=True, text=True, check=False)
  return output

getConfigdata = imunify_cli_cmds('imunify360-agent config show --json')
json_conf_data = json.loads(getConfigdata.stdout)

def get_config(cnf_data, key):

  for item_key, item_value in json_conf_data["items"].items():
      if key in item_value:
          return item_value[key]

print("Malware Scan time settings:", json_conf_data['items']['MALWARE_SCAN_SCHEDULE'])
print("Default action: ", get_config(json_conf_data, 'default_action'))
print("User override proactive defense:", get_config(json_conf_data, 'user_override_proactive_defense'))
print("Modsec ruleset", get_config(json_conf_data, 'ruleset'))
print("Modsec app_specific_ruleset", get_config(json_conf_data, 'app_specific_ruleset'))
print("Modsec cms_account_compromise_prevention", get_config(json_conf_data, 'cms_account_compromise_prevention'))
print("Webshield:", get_config(json_conf_data, 'WEBSHIELD'))
print("Webshield Enabled:", json_conf_data['items']['WEBSHIELD']['enable'])
print("ENHANCED_DOS Enabled:", json_conf_data['items']['ENHANCED_DOS']['enable'])

pd_keys = ['blamer', 'jit_compatible_mode', 'log_whitelisted', 'mode', 'php_immunity']
for items in pd_keys:
   print(f"configuration for PD, {items}", get_config(json_conf_data, items))

feat_mngmt_data = imunify_cli_cmds('imunify360-agent feature-management show --json')
feat_data = json.loads(feat_mngmt_data.stdout)
for item in feat_data['items']:
    print(f"User: {item['name']}")
    print(f"AV: {item['features']['av']}")
    print(f"Proactive: {item['features']['proactive']}")
    print(f"Proactive: {item['features']['proactive']}")
    print(f"Proactive: {item['features']['proactive']}")
