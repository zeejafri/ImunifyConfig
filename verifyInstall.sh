#!/bin/bash

filename='/var/log/i360deploy.log'
check_service_status() {
    local service_name="$1"
    local status=$(systemctl status "$service_name" | grep "Active:")

    if [[ -n "$status" ]]; then
        echo "$service_name: $status"
    else
        echo "$service_name: Service is down"
        echo "###### $(date): $(service_name): NOT OK"
    fi
}

echo "###### checking region of server"
echo " "
curl ipinfo.io
echo " "
echo " "
if tail -n 1 $filename | grep -q 'OK'; then
    echo "###### $(date): Imunify Installation: OK"
else
    echo "###### $(date): Imunify Installation: NOT OK"
    grep -E 'Installing cloudways configuration|unable|failed|error|not found|No such file or directory|Failed to fetch|Err:55 https://repo.imunify360.cloudlinux.com/imunify360|imunify360-agent: command not found |was not installed| free space' $filename
fi
echo " "
echo " "
echo " "
if token_expire_utc=$(cat /var/imunify360/license.json | grep -a token_expire_utc | cut -d ":" -f1 --complement |  sed 's/[[:space:],]//g'); then
    echo "###### $(date): License Installation: OK"
    date -d @"$token_expire_utc" +"%Y-%m-%d %H:%M:%S"
else 
echo "###### $(date): License Installation: NOT OK"
fi
echo " "
echo " "
echo " "
if cat /etc/shorewall/rules | grep -q 8084; then
    echo "###### $(date): Shorewall Rules: OK"
    cat /etc/shorewall/rules
else
   echo "###### $(date): Shorewall Rules: NOT OK!!"
fi
echo " "
echo " "
echo " "
if netstat -tpln | grep -q 8084; then
    echo "###### $(date): Apache Port set to 8084: OK"
   netstat -tpln | grep 8084
   echo " "
   echo "Modsec configuration"
   cat /etc/modsecurity/modsecurity.conf
else
    echo "###### $(date): Apache Port set to 8084: NOT OK"
fi
   echo " "
      echo " "
cat /etc/ansible/facts.d/packages.fact
echo " "
echo " "
cat /etc/ansible/facts.d/playbook_version.fact 
echo " "
echo " "
check_service_status "apache2"
echo " "
echo " "
check_service_status "shorewall"
echo " "
echo " "
check_service_status "imunify360"

echo " "
echo " "
echo "########## Disk space stats"
df -hT
echo " "
echo "  "  
if cat /etc/sysconfig/imunify360/imunify360.config.d/50-initial-default-action.config  | grep -q notify; then
   echo "###### $(date): Malware Default Action: OK"
    cat /etc/sysconfig/imunify360/imunify360.config.d/50-initial-default-action.config
else 
echo " "
echo "  " 
    echo "###### $(date): Malware Default Action: NOT OK"
fi
echo " "
echo "  " 
echo "********** Imunify API admin user  " 
cat /etc/sysconfig/imunify360/auth.admin
echo " "
echo " "
#tail  /home/master/applications/*/logs/apache*error*log
