# nmap
```
sudo nmap 10.11.1.0/24 -oG nmap_results
sudo nmap -sV -sT -O -A -oX nmap_results.xml 10.11.1.0/24
```
# nmap2md
```
# xml input
python nmap2md.py nmap_results.xml 
```
# nmap2neo4j
```
# xml input
python nmap-to-neo4j.py -p password -t xml -f nmap_results.xml --attacking-host kali --attacking-ip 192.168.119.206 -n 1 -c 10.11.1.0/24
# txt input
python nmap-to-neo4j.py -p password -t txt -f nmap_results --attacking-host kali --attacking-ip 192.168.119.206 -n 1 -c 10.11.1.0/24
# Add subnet through a pivot endpoint
python nmap-to-neo4j.py -p password -t xml -f nmap_results_2.xml -n 2 -c 10.0.5.0/24 -pi 10.11.1.5
```
#  md2neo4j
```
python md2neo4j.py -p password 
```