#!/bin/sh

echo "enter the domain name"

read domain_name

echo "finding subdomains for $domain_name" 

echo "---------------------------------------------------------------------------------\n"
curl -s https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$domain_name | grep -o -E "[a-zA-Z0-9._-]+\.$domain_name"|anew|sort -u >> threat-crowd.txt

echo "finding subdomains from threatcrowd.org " 

curl --silent https://sonar.omnisint.io/subdomains/$domain_name | grep -o -E "[a-zA-Z0-9._-]+\.$domain_name" | anew |sort -u >>sonar.txt

echo "finding subdomains from  sonar.omnisint.io "

curl --silent -X POST https://synapsint.com/report.php -d "name=https://$domain_name" | grep -oE "[a-zA-Z0-9._-]+\.$domain_name" | anew |sort -u  >>synap.txt

echo "finding subdomains from  synapsint.com"

curl -s "https://securitytrails.com/list/apex_domain/$domain_name/history/txt" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | grep ".$domain_name" | anew |sort -u >>sec-trails.txt

echo "finding subdomains from  securitytrails.com "

curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$domain_name/passive_dns"  | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | anew |sort -u >> alienvault.txt

echo "finding subdomains from  otx.alienvault.com "

cat threat-crowd.txt sonar.txt synap.txt sec-trails.txt alienvault.txt | anew >>  $domain_name.txt
rm threat-crowd.txt sonar.txt synap.txt sec-trails.txt alienvault.txt
