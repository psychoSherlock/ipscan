# IPScan

# Setup

- if errors permission errors are shown in linux

```
sudo setcap cap_net_raw+ep $(readlink -f $(which python))
```

- For windows, install `Npcap`

all usages:

- with ip
- with domain name
- with subnets
- with subnet ranges 192.168.1.5-20
- with full scan
- with fast scan
- with port
- with port range
