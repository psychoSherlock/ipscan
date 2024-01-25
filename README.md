SETUP:
sudo setcap cap_net_raw+ep $(readlink -f $(which python))

#### Todo

- When you use the -Pn option, you instruct Nmap to skip the host discovery phase, assuming that all specified hosts are online. This can be useful in situations where the target hosts are configured to block certain types of ICMP packets or when you want to perform port scanning without waiting for the host discovery process to complete.

- fast scan and complete scan
- Verbosity
- display port is open messages
- banner grabbing for http (80)
- banner grabbing for 3306 mysql
- show filtered for unknowns
- at least do, http, ftp, ssh, mysql and filtered for all others.
  81.169.145.86 21 - wireshark - help command is used
- collect ftps from hunter
