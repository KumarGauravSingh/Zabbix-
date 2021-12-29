#!/bin/bash
#WAF Device IP Ask

echo "Please enter Barracuda Device IP"
read -r Barr_Dev_IP
echo $Barr_Dev_IP

#Generate Waf Token

waftoken=$(curl -X POST "http://${Barr_Dev_IP}:8000/restapi/v3.1/login" -H "accept: application/json" -H "Content-Type: application/json" -d '{ "password": "abc@123", "username": "abc"}' | jq '.token'| sed -e 's/^"//' -e 's/"$//'  )

token_input=$waftoken:

echo "WAF Token is : $token_input"
echo ""


#Genearate Zabbix Token
zabbix_url=http://<youip_or_domain>/zabbix/api_jsonrpc.php

user=testlinux
password=testlinux

# 2.1 get authorization token of zabbix

zabbix_auth=$(curl -s -X POST \
-H 'Content-Type: application/json-rpc' \
-d " \
{
 \"jsonrpc\": \"2.0\",
 \"method\": \"user.login\",
 \"params\": {
  \"user\": \"$user\",
  \"password\": \"$password\"
 },
 \"id\": 1,
 \"auth\": null
}
" $zabbix_url | \
jq -r '.result'
)

echo "Zabbix Token : " $zabbix_auth
echo ""

#Fetch all service list and save in vsitelist.txt

curl -X GET "http://${Barr_Dev_IP}:8000/restapi/v3.1/services/" -H  "accept: application/json" -u "$token_input" | jq '.data' | jq -r '.[] | .name' > vsites_list.txt

#TEMPLATE Creation

tempid=$(curl -s -X POST -H 'Content-Type: application/json-rpc' -d '{"jsonrpc": "2.0", "method": "template.create", "params": {"host": "Barracuda_'"$Barr_Dev_IP"'", "groups":{"groupid":"43"}, "macros": {"macro":"{$TOKEN}","value":"'"$token_input"'"}, "tags":[{"tag": "Barracuda Device", "value": "10.248.0.164"}], "macros": [ { "macro": "{$TOKEN}", "value":"'"$token_input"'" } ]}, "auth": "'"$zabbix_auth"'", "id": 1}' $zabbix_url| jq '.result' | jq -r '.templateids'| jq -r '.[]')

#tempid=$(curl -s -X POST -H 'Content-Type: application/json-rpc' -d '{"jsonrpc": "2.0", "method": "template.create", "params": {"host": "Barracuda_'"$Barr_Dev_IP"'", "macros": {"macro":"{$TOKEN}","value":"'"$token_input"'"}, "tags":[{"tag": "Barracuda Device", "value": "'"$Barr_Dev_IP"'"}], "macros": [ { "macro": "{$TOKEN}", "value": "'"$token_input"'" } ]}, "auth": "'"$zabbix_auth"'", "id": 1}'  $zabbix_url | jq '.result' | jq -r '.templateids'| jq -r '.[]')

echo "Template ID: $tempid"

#HOST Creation

hostid=$(curl -s -X POST -H 'Content-Type: application/json-rpc' -d '{"jsonrpc": "2.0", "method": "host.create", "params": { "host": "Barracuda_WAF_'"$Barr_Dev_IP"'", "interfaces": [ { "type": 2, "main": 1, "useip": 1, "ip": "'"$Barr_Dev_IP"'", "dns": "", "port": "161", "details": { "version": 2, "community": "{$SNMP_COMMUNITY}" } } ], "groups": [ { "groupid": "43" } ], "templates": [{"templateid": "'"$tempid"'"}], "macros": [ { "macro": "{$SNMP_COMMUNITY}", "value": "cudaSNMP" } ]}, "auth": "'"$zabbix_auth"'", "id": 1 }' $zabbix_url | jq '.result' | jq -r '.hostids'| jq -r '.[]')

echo "Host ID: $hostid"
echo ""

#Create Application & Items

for site in $(cut -f 1 vsites_list.txt); do

#Create Application name by fatchinf IP address & Port of service

app_ip=$(curl -X GET "http://${Barr_Dev_IP}:8000/restapi/v3.1/services/${site}?parameters=ip-address" -H  "accept: application/json" -u "$token_input" | jq -r --arg v "$site" '.data[$v]."ip-address"')

app_port=$(curl -X GET "http://${Barr_Dev_IP}:8000/restapi/v3.1/services/${site}?parameters=port" -H  "accept: application/json" -u "$token_input" | jq -r --arg v "$site" '.data[$v].port')

app_hostname="vip_"$app_ip"_"$app_port
echo "Application name : $app_hostname"

#Create Application

appid=$(curl -s -X POST -H 'Content-Type: application/json-rpc' -d '{"jsonrpc": "2.0","method": "application.create","params": {"name": "'"$app_hostname"'","hostid": "'"$tempid"'"},"auth": "'"$zabbix_auth"'","id": 1}' $zabbix_url | jq '.result' | jq -r '.applicationids'| jq -r '.[]')

echo "Application created & ID of $app_hostname is $appid"

#Create Item


#Item-1 -------- Name of Service ------

curl -s -X POST -H 'Content-Type: application/json-rpc' -d '{ "jsonrpc": "2.0", "method": "item.create", "params": { "url":"http://'"$Barr_Dev_IP"':8000/restapi/v3.1/services/'"$site"'", "query_fields": [ { "parameters":"name" } ], "type":"19", "hostid":"'"$tempid"'", "delay":"180s", "key_":"service.'"$site"'.name", "name":"Name of Service", "value_type":"4", "output_format":"0", "authtype":"1", "timeout":"60s", "username":"{$TOKEN}", "applications": ["'"$appid"'"], "preprocessing": [ { "type": "21", "params": "var obj = JSON.parse(value);\n var servedata = JSON.stringify(obj[\"data\"]);\n var dataobj = JSON.parse(servedata);\n var name = JSON.stringify(dataobj[\"'"$site"'\"][\"name\"]);\n var stat = name.replace(\/\\\"\/g, \"\");\n return [stat];", "error_handler":"0", "error_handler_params":"" } ] }, "auth": "'"$zabbix_auth"'", "id": 2 }'  $zabbix_url

#Item-2 ------- Basic Security Mod ------

curl -s -X POST -H 'Content-Type: application/json-rpc' -d '{ "jsonrpc": "2.0", "method": "item.create", "params": { "url":"http://'"$Barr_Dev_IP"':8000/restapi/v3.1/services/'"$site"'", "query_fields": [ {"groups":"Basic Security"}, { "parameters":"mode" } ], "type":"19", "hostid":"'"$tempid"'", "delay":"180s", "key_":"service.'"$site"'.mode", "name":"Basic Security Mode", "value_type":"4", "output_format":"0", "authtype":"1", "timeout":"60s", "username":"{$TOKEN}", "applications": ["'"$appid"'"], "preprocessing": [ { "type": "21", "params": "return [JSON.stringify(JSON.parse(value)[\"data\"][\"'"$site"'\"][\"Basic Security\"][\"mode\"]).replace(\/\\\"\/g, \"\")];", "error_handler":"0", "error_handler_params":"" } ] }, "auth": "'"$zabbix_auth"'", "id": 2 }'  $zabbix_url

#Item-3 ------- CURRENT CONNECTIONS -----

if [[ $app_port -eq 443 || $app_port -eq 8443 ]]
then

curl -s -X POST -H 'Content-Type: application/json-rpc' -d '{ "jsonrpc": "2.0", "method": "item.create", "params": { "url":"http://'"$Barr_Dev_IP"':8000/restapi/v3.1/stats/ssl-stats", "type":"19", "hostid":"'"$tempid"'", "delay":"180s", "key_":"CurrentConn.'"$site"'", "name":"Current Connection", "value_type":"0", "output_format":"0", "authtype":"1", "timeout":"60s", "username":"{$TOKEN}", "applications": ["'"$appid"'"], "preprocessing": [ { "type": "21", "params": "return [parseFloat(JSON.parse(value)[\"Ssl Stats\"][\"'"$app_ip"':'"$app_port"'\"][\"Service Details\"][\"Current Connections\"])]", "error_handler":"0", "error_handler_params":"" } ] }, "auth": "'"$zabbix_auth"'", "id": 2 }'  $zabbix_url

else

curl -s -X POST -H 'Content-Type: application/json-rpc' -d '{ "jsonrpc": "2.0", "method": "item.create", "params": { "url":"http://'"$Barr_Dev_IP"':8000/restapi/v3.1/stats/http-stats", "type":"19", "hostid":"'"$tempid"'", "delay":"180s", "key_":"CurrentConn.'"$site"'", "name":"Current Connection", "value_type":"0", "output_format":"0", "authtype":"1", "timeout":"60s", "username":"{$TOKEN}", "applications": ["'"$appid"'"], "preprocessing": [ { "type": "21", "params": "return [parseFloat(JSON.parse(value)[\"Http Stats\"][\"'"$app_ip"':'"$app_port"'\"][\"Service Details\"][\"Current Connections\"])]", "error_handler":"0", "error_handler_params":"" } ] }, "auth": "'"$zabbix_auth"'", "id": 2 }'  $zabbix_url

fi

#Item-4 ------- Service Status ---------

curl -s -X POST -H 'Content-Type: application/json-rpc' -d '{ "jsonrpc": "2.0", "method": "item.create", "params": { "url":"http://'"$Barr_Dev_IP"':8000/restapi/v3.1/services/'"$site"'", "query_fields": [ {"groups":"Service"}, {"category":"operational"}, { "parameters":"status" } ], "type":"19", "hostid":"'"$tempid"'", "delay":"180s", "key_":"service.'"$site"'.status", "name":"Service '"$site"'", "value_type":"4", "output_format":"0", "authtype":"1", "timeout":"60s", "username":"{$TOKEN}", "applications": ["'"$appid"'"], "preprocessing": [ { "type": "21", "params": "return [JSON.stringify(JSON.parse(value)[\"data\"][\"'"$site"'\"][\"operational-status\"]).replace(\/\\\"\/g, \"\")];", "error_handler":"0", "error_handler_params":"" } ] }, "auth": "'"$zabbix_auth"'", "id": 2 }'  $zabbix_url

#Trigger-1 For service Status  ------- Service Trigger ---------

curl -s -X POST -H 'Content-Type: application/json-rpc' -d '{"jsonrpc": "2.0", "method": "trigger.create", "params": {"description": "'"$app_hostname"'('"$site"') - Status : Down", "expression": "{Barracuda_'"$Barr_Dev_IP"':service.'"$site"'.status.str(Down)}=1", "priority":"4", "manual_close":"1"}, "auth": "'"$zabbix_auth"'", "id": 1 }' $zabbix_url

curl -s -X POST -H 'Content-Type: application/json-rpc' -d '{"jsonrpc": "2.0", "method": "trigger.create", "params": {"description": "'"$app_hostname"'('"$site"') -  Status : Disabled", "expression": "{Barracuda_'"$Barr_Dev_IP"':service.'"$site"'.status.str(Disabled)}=1", "priority":"2", "manual_close":"1"}, "auth": "'"$zabbix_auth"'", "id": 1 }' $zabbix_url

curl -s -X POST -H 'Content-Type: application/json-rpc' -d '{"jsonrpc": "2.0", "method": "trigger.create", "params": {"description": "'"$app_hostname"'('"$site"') -  Status : Standby", "expression": "{Barracuda_'"$Barr_Dev_IP"':service.'"$site"'.status.str(Standby)}=1", "priority":"1", "manual_close":"1"}, "auth": "'"$zabbix_auth"'", "id": 1 }' $zabbix_url


#Fetch Server list of a perticular service

curl -X GET "http://${Barr_Dev_IP}:8000/restapi/v3.1/services/${site}/servers?groups=Server&category=operational" -H  "accept: application/json" -u "$token_input" | jq -r '.data' | jq -r 'keys' | jq -r '.[]' >  vsites_vservers_list.txt

#Loop to create server items

for server in $(cut -f 1 vsites_vservers_list.txt); do

#Item-5 -------- SERVER ITEMS ---------

curl -s -X POST -H 'Content-Type: application/json-rpc' -d '{ "jsonrpc": "2.0", "method": "item.create", "params": { "url":"http://'"$Barr_Dev_IP"':8000/restapi/v3.1/services/'"$site"'", "query_fields": [ {"groups":"Service"}, {"category":"operational"}, { "parameters":"status" } ], "type":"19", "hostid":"'"$tempid"'", "delay":"180s", "key_":"server.'"$server"'.status", "name":"'"$server"'", "value_type":"4", "output_format":"0", "authtype":"1", "timeout":"60s", "username":"{$TOKEN}", "applications": ["'"$appid"'"], "preprocessing": [ { "type": "21", "params": "return [JSON.stringify(JSON.parse(value)[\"data\"][\"'"$site"'\"][\"Server\"][\"data\"][\"'"$server"'\"][\"operational-status\"]).replace(\/\\\"\/g, \"\")];", "error_handler":"0", "error_handler_params":"" } ] }, "auth": "'"$zabbix_auth"'", "id": 2 }'  $zabbix_url

#Trigger-2 for status of server ----- Server Trigger ------

curl -s -X POST -H 'Content-Type: application/json-rpc' -d '{"jsonrpc": "2.0", "method": "trigger.create", "params": {"description": "'"$app_hostname"' - Server('"$server"') - Status : Down", "expression": "{Barracuda_'"$Barr_Dev_IP"':server.'"$server"'.status.str(Down)}=1", "priority":"4", "manual_close":"1"}, "auth": "'"$zabbix_auth"'", "id": 1 }' $zabbix_url

curl -s -X POST -H 'Content-Type: application/json-rpc' -d '{"jsonrpc": "2.0", "method": "trigger.create", "params": {"description": "'"$app_hostname"' - Server('"$server"') - Status : Disabled", "expression": "{Barracuda_'"$Barr_Dev_IP"':server.'"$server"'.status.str(Disabled)}=1", "priority":"2", "manual_close":"1"}, "auth": "'"$zabbix_auth"'", "id": 1 }' $zabbix_url


done

done

#Remove created files 

rm -rf vsites_vservers_list.txt
rm -rf vsites_list.txt

echo ""
echo "Script Completed !!"
