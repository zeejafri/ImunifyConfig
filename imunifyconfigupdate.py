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

def getCronHour():
    try:
        cronLine = ""
        crontab = open("/etc/crontab", "r")
        lines = crontab.readlines()
        for i in lines:
            if "Backup_Entry" in i:
                cronLine = i
                break
        crontab.close()

        if not cronLine:
            raise Exception("Cron entry is empty")

        matchGroups = re.match(r"^(?P<min>\w+)\s+(?P<hour>[\w*\/]+).+", cronLine)
        if matchGroups:
            hour = matchGroups.group('hour')
            if '*' in hour:
                hour="6"
            format = '%H'
            time = datetime.strptime(hour, format) - timedelta(hours=3)
            return time.hour
        else:
            raise Exception("Regex not matched")
    except Exception as e:
        raise Exception("Unknown error occured")

def imunify_cli_cmds(im_cmd):
#  print(im_cmd)
  output = subprocess.run(im_cmd, shell=True, capture_output=True, text=True, check=False)
  return output

def get_config(cnf_data, key):

  for item_key, item_value in json_conf_data["items"].items():
      if key in item_value:
          return item_value[key]
  #return False

try:
  cmd = "imunify360-agent feature-management disable --feature av"
  newUser_av_disable = imunify_cli_cmds(cmd)
  #AV feature disable:
  if newUser_av_disable.returncode != 0:
    raise Exception(f"Failed to disable AV feature for new users, error: {newUser_av_disable.stderr}")
  else: print("AV configurations status for new users ",newUser_av_disable.stdout)
  existUser_av_disable = imunify_cli_cmds(cmd + " --users " + usernames_str)
  if existUser_av_disable.returncode != 0:
     raise Exception(f"Failed to disable AV feature for new users, error: {existUser_av_disable.stderr}")
  else: print("AV Configurations status for existing users ", existUser_av_disable.stdout.strip().replace('\n', ' '))


  #Proactive feature disable:
  cmd = "imunify360-agent feature-management disable --feature proactive"
  newUser_pr_disable = imunify_cli_cmds(cmd)
  if newUser_pr_disable.returncode != 0:
     raise Exception(f"Failed to disable Proactive feature for new users, error: {newUser_pr_disable.stderr}")
  else: print("Proactive configurations status for new users",newUser_pr_disable.stdout)
  existUser_pr_disable = imunify_cli_cmds(cmd + " --users " + usernames_str)
  if existUser_pr_disable.returncode != 0:
     raise Exception(f"Failed to disable Proactive feature for existing users, error: {existUser_pr_disable.stderr}")
  else: print("Proactive configurations status for existing users ",existUser_pr_disable.stdout.strip().replace('\n', ' '))


  #minimize ruleSet
  min_rule_set = imunify_cli_cmds('imunify360-agent config update \'{"MOD_SEC": {"ruleset": "MINIMAL"}}\' --json')
  if min_rule_set.returncode !=0:
     raise Exception(f"Failed to disable Proactive feature for existing users, error: {min_rule_set.stderr}")
  else:
    rule_set_output = json.loads(min_rule_set.stdout)
    print("Proactive configurations status for users:", rule_set_output["items"]["MOD_SEC"]["ruleset"])
  
  #Proactive defense setup
  pd_setup = imunify_cli_cmds("imunify360-agent config update '{\"PROACTIVE_DEFENCE\": {\"blamer\": true, \"jit_compatible_mode\": false, \"log_whitelisted\": true, \"mode\": \"KILL\", \"php_immunity\": false}}' --json")
  if pd_setup.returncode !=0:
     raise Exception(f"Failed to disable Proactive feature for existing users, error: {pd_setup.stderr}")
  else:
    pd_setup = json.loads(pd_setup.stdout)
    print("Proactive defense setup status:", pd_setup["items"]["PROACTIVE_DEFENCE"])


  #SETUP USER OVERRIDE
  override = imunify_cli_cmds('imunify360-agent config update \'{"PERMISSIONS": {"user_override_proactive_defense": true}}\' --json')
  if override.returncode != 0:
     raise Exception(f"Failed to setup user over ride, error: {override.stderr}")
  else: 
    override = json.loads(override.stdout)
    print("Proactive defense setup status:", override["items"]["PERMISSIONS"])
  default_action = imunify_cli_cmds('imunify360-agent config update \'{"PERMISSIONS": {"user_override_malware_actions": true}, "MALWARE_SCANNING": {"default_action": "notify"}}\' --json')
  if default_action.returncode != 0:
     raise Exception(f"Failed to update malware actions, error: {default_action.stderr}")
  else: 
    default_action = json.loads(default_action.stdout)
    permissions = default_action["items"].get("PERMISSIONS")
    m_scan = default_action["items"].get("MALWARE_SCANNING")
    print("Current status of permissions", permissions.get("user_override_malware_actions"))
    print("Default action value:", m_scan.get("default_action"))

  #ScanSchedule Setup
  scan_hour = getCronHour()
  conf_update_cmd = f"imunify360-agent config update '{{\"MALWARE_SCAN_SCHEDULE\":{{\"day_of_month\": 1, \"day_of_week\": 1, \"hour\": {scan_hour}, \"interval\": \"day\"}}}}' --json"
  conf_update = imunify_cli_cmds(conf_update_cmd)
  if conf_update.returncode != 0:
     raise Exception(f"Failed to update scan schedule: {conf_update.stderr}")
  else:
    scan_data = json.loads(conf_update.stdout)
    malware_scan_sch = scan_data["items"]["MALWARE_SCAN_SCHEDULE"]
    print("Malware Scan Schedule updated: ", malware_scan_sch, '\n')

  ##Cross check configurations
  #print("################ Cross Checking updated data ################", "\n")
  #getConfigdata = imunify_cli_cmds('imunify360-agent config show --json')
  #json_conf_data = json.loads(getConfigdata.stdout)
#
  ## Checking Scan time settings
  #sc_time = get_config(json_conf_data, 'hour')
  #if sc_time != getCronHour():
  #    raise Exception(f"Scan time hour not set, require value: {getCronHour()} current value: {sc_time}")
  #else: print("Scan time is set to required value:", getCronHour())
  #
  ##Check '{"MOD_SEC": {"ruleset": "MINIMAL"}}'
  #modsec = get_config(json_conf_data, 'ruleset')
  #if modsec != "MINIMAL":
  #  raise Exception(f"Modsec rules not set, current status: {modsec} required  value: 'MINIMAL'")
  #else: print("Mod sec rules verified", modsec)
  #
  ##check PD configuration  '{"PROACTIVE_DEFENCE": {"blamer": true, "jit_compatible_mode": false, "log_whitelisted": true, "mode": "KILL", "php_immunity": false}}'
  #pd_config = {"blamer": True, "jit_compatible_mode": False, "log_whitelisted": True, "mode": "KILL", "php_immunity": False}
  #pd_keys = ['blamer', 'jit_compatible_mode', 'log_whitelisted', 'mode', 'php_immunity']
  #for item in pd_keys:
  #  # print("current item", item)
  #  # print("current value returned from function", get_config(json_conf_data, item))
  #  # print('PD config item', pd_config[item])
  #  if item == 'mode' and get_config(json_conf_data, item) != 'KILL':
  #     raise Exception(f"Err: PD not mode value not setup correctly: {item}, required value: 'KILL'")
  #  elif (item == 'log_whitelisted' or item == 'blamer') and get_config(json_conf_data, item) != pd_config[item]:
  #     raise Exception(f"Err: PD not setup correctly for {item}, required value: true")
  #  elif get_config(json_conf_data, item) != pd_config[item]:   
  #    raise Exception(f"Err: PD not setup correctly {item}, current value: {get_config(json_conf_data, item)}")
  #print("PD configurations verified")
#
# #Feature management
  #feat_mngmt_data = imunify_cli_cmds('imunify360-agent feature-management show --json')
  #feat_data = json.loads(feat_mngmt_data.stdout)
  #app_error_list= []
  #for i in feat_data['items']:
  #  if i['features']['av'] or i['features']['proactive']:
  #    print(i['features'])
  #    app_error_list.append(i['name'])
  #default_action = get_config(json_conf_data, 'default_action')
  #user_override_proactive_defense = get_config(json_conf_data, 'user_override_proactive_defense')
  #if user_override_proactive_defense == False or len(app_error_list) > 0 or default_action != "notify":
  #  error_obj = {
  #      2: {
  #          "apps": app_error_list,
  #          "default_action": default_action,
  #          "user_override_proactive_defense": user_override_proactive_defense
  #      }
  #  }
  #  raise Exception(f"feature management config not set for users: {error_obj}")
  #else: print("Feature management user configurations are set")
      
except Exception as e:
  logging.error(f"Error: {e}")
  sys.exit(1)
