nmap -sV --max-hostgroup 10 10.1.1.1/24 -oG scan_results.txt

grep Up scan_results.txt | cut -d " " -f 2 > up_ips.txt

while read ip; do
    nmap $ip -oN report_$ip.txt
done < up_ips.txt
