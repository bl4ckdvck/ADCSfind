# ADCS find script
A small script to search for ADCS servers and cert publisher servers with web enroll.
# Usage
```
ADCSfind.py [-h] -d DOMAIN -u USERNAME -p PASSWORD [--dc-ip DC_IP] [--check-web] [--use-ssl]

  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
  -u USERNAME, --username USERNAME
  -p PASSWORD, --password PASSWORD
  --dc-ip DC_IP         DC ip
  --check-web           check web enroll endpoints
  --use-ssl             use ssl for ldap

```
