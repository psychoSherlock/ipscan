This is a small project I developed for my seniors as their final year project
# IPScan - Network Mapper and Vulnerability Scanner
IPScan is a Python-based tool designed to perform network mapping and vulnerability scanning. It allows users to target specific IP addresses, subnets, or domains and scan for open ports and potential vulnerabilities and display them in a table like output along with colors.

![image](https://github.com/psychoSherlock/ipscan/assets/81918189/f58fb85d-fe52-4a83-8bfc-99b199707fce)
![image](https://github.com/psychoSherlock/ipscan/assets/81918189/75047024-0f78-4c3d-9613-e48115aa4369)
![image](https://github.com/psychoSherlock/ipscan/assets/81918189/5fcc0f9e-eebc-48b3-aaa6-6591f22479ca)
![image](https://github.com/psychoSherlock/ipscan/assets/81918189/74017d0b-0a21-4bea-a9ac-3e44120e045a)


# Installation / Setup

```sh
pip install -r requirements.txt
```

- If permission related errors are shown in linux:

```
sudo setcap cap_net_raw+ep $(readlink -f $(which python))
```

- For windows, install [Npcap](https://npcap.com/)

### Features:
- Scan IP Address
- Scan domain Name
- Scan Subnets
- Scan IP Ranges: eg: `192.168.1.5-20`
- Scan entire port range 1-65535 ports
- Fast scan to scan 1024 important ports
- Scan custom ports -p22 or port ranges -p2-10
- Displays details in a cool table like terminal view
- Scan from input file
- Service scan to banner grab most used Services and print them 
- Vuln scan to scan for vulnerabilities using exploit-db


# Usage

To use IPScan, you need to run the  `ipscan.py`  script from the command line with the appropriate arguments. Here's a breakdown of the available arguments:

-   `-t`  or  `--target`: This argument is used to specify the target of the scan. The target can be an IP address, a subnet, or a domain. For example,  `-t 192.168.1.1`  or  `--target www.example.com`.
    
-   `-p`  or  `--port`: This argument is used to specify a single port or a range of ports to scan on the target. For example,  `-p 80`  would scan port 80, and  `-p 20-25`  would scan ports 20 through 25.
    
-   `-f`  or  `--full-scan`: This argument is used to perform a full scan. When this argument is used, IPScan will scan all 65535 ports on the target. This argument doesn't require a value.
    
-   `-i`  or  `--input-file`: This argument is used to specify an input file containing a list of targets to scan. Each line in the file should contain one target. For example,  `-i targets.txt`  would read the targets from the file  `targets.txt`.
Here's an example of how to use these arguments:
I apologize for the confusion earlier. Without the full context of your code, it's difficult to provide a complete explanation of all the command-line arguments. However, if your script includes vulnerability scanning and service scanning, you might have additional arguments like `-v` or `--vuln-scan` and `-s` or `--service-scan`. Here's a possible explanation:

- `-v` or `--vuln-scan`: This argument is used to perform a vulnerability scan on the target. When this argument is used, IPScan will attempt to identify potential vulnerabilities in the target system. This argument doesn't require a value.

- `-sV` or `--service-scan`: This argument is used to perform a service scan on the target. When this argument is used, IPScan will attempt to identify the services running on the open ports of the target system. This argument doesn't require a value.

Please note that these are hypothetical explanations based on common practices in network scanning tools. For accurate descriptions of these arguments, you should refer to the actual implementation in your `ipscan.py` script.
```
python  ipscan.py  -t  192.168.1.1  -p  20-25
```
This command will scan ports 20 through 25 on the target IP address 192.168.1.1.
```
python  ipscan.py  -t  www.example.com  -f
```
This command will perform a full scan on the target domain  www.example.com.

Please note that the  `-t`  (or  `--target`) argument is required for the script to run. The  `-p`  (or  `--port`) and  `-f`  (or  `--full-scan`) arguments are optional, but at least one of them must be provided.

