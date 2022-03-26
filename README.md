# Zabbix-Barracuda-WAF-Monitoring
Following contains the bash script to add all the VIPs and nodes present in the Barracuda device using HTTP method to zabbix.

### Install Dependencies ###
This script requires jq json processor. Kindly install it using
```bash
yum install epel-release -y
yum update -y
yum install jq -y
```
### Run the script ###
To run the script kindly change its permission for the file to execute and then enter the device IP on prompt.
```bash
chmod 755 api_wafscript.sh
./api_wafscript.sh
```

