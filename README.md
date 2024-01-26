SETUP:
sudo setcap cap_net_raw+ep $(readlink -f $(which python))

#### Todo

- When you use the -Pn option, you instruct Nmap to skip the host discovery phase, assuming that all specified hosts are online. This can be useful in situations where the target hosts are configured to block certain types of ICMP packets or when you want to perform port scanning without waiting for the host discovery process to complete.

```
WHATCMS_API_KEY=Sdsdsd
```

- Verbosity
- banner grabbing for http (80)
- banner grabbing for 3306 mysql
- show filtered for unknowns
- at least do, http, ftp, ssh, mysql and filtered for all others.
  81.169.145.86 21 - wireshark - help command is used
- collect ftps from hunter
- Service scan
- Print host scans multiple warning
- HTML report output, screenshots and saving stdouts to a fodler

all usages:

- with ip
- with domain name
- with subnets
- with subnet ranges 192.168.1.5-20
- with full scan
- with fast scan
- with port
- with port range
