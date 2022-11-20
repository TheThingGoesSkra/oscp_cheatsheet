# Nmap
Using masscan to scan top20ports of nmap in a /24 range (less than 5min)
```
masscan -p20,21-23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080 199.66.11.0/24
```