SETUP:
sudo setcap cap_net_raw+ep $(readlink -f $(which python))

#### Todo

- When you use the -Pn option, you instruct Nmap to skip the host discovery phase, assuming that all specified hosts are online. This can be useful in situations where the target hosts are configured to block certain types of ICMP packets or when you want to perform port scanning without waiting for the host discovery process to complete.

- fast scan and complete scan
- Verbosity
