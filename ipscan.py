from ping3 import ping, verbose_ping
from scapy.all import IP, sr1, ICMP, TCP
import os
from time import sleep, gmtime, strftime, time
from datetime import datetime
from terminaltables import AsciiTable
from colorama import Fore, init, Style
from platform import system
import re
import socket
import ipaddress
import threading

#### configurations ###
init(autoreset=True)  # To autoreset colors

magneta = Fore.MAGENTA + Style.BRIGHT
green = Fore.GREEN + Style.BRIGHT
yellow = Fore.YELLOW + Style.BRIGHT
red = Fore.RED + Style.BRIGHT


if system() == 'Windows':
    os.system("color 0a")

else:
    pass

###########################
print(magneta + """
 _____  _____    _____                     
|_   _||  __ \  / ____|                    
  | |  | |__) || (___    ___   __ _  _ __  
  | |  |  ___/  \___ \  / __| / _` || '_ \ 
 _| |_ | |      ____) || (__ | (_| || | | |
|_____||_|     |_____/  \___| \__,_||_| |_|

""" + '\n' + f'Initialized at {yellow}{strftime("%Y-%m-%d %H:%M:%S", gmtime())}')

# ip = input("\n[?] Ip or Domain of Target: ")

dataTable = []
table = AsciiTable(dataTable)


targets_list = []


def scan(givenTarget):
    # Check if the input contains any protocol specifications
    protocol_pattern = re.compile(r'^\s*(https?|ftp)://')
    if protocol_pattern.match(givenTarget):
        print("Given address must not contain protocols")
        exit(0)  # Exits if protocol is given.

    if givenTarget.replace('.', '').replace('/', '').replace('-', '').isdigit():
        enumerateTargets(givenTarget)
    else:
        resolvedIp = socket.gethostbyname(givenTarget)  # resovlve host
        print('\n' + str(givenTarget) + " is at " + green + str(resolvedIp))
        enumerateTargets(resolvedIp)


def generate_ip_list(subnet):
    ip_list = []

    # Check if the subnet is in CIDR notation
    try:
        network = ipaddress.IPv4Network(subnet, strict=False)
        ip_list = [str(ip) for ip in network.hosts()]
    except ValueError:
        # If not in CIDR notation, try parsing as a range
        if '-' in subnet:
            try:
                prefix, last_octet_range = subnet.rsplit('.', 1)
                start, end = last_octet_range.split('-')
                start_ip = int(start.strip())
                end_ip = int(end.strip())

                # Generate the list of IP addresses in the range
                ip_list = [f"{prefix}.{ip}" for ip in range(
                    start_ip, end_ip + 1)]
            except ValueError:
                print("Invalid range format")
        else:
            # If both CIDR notation and range notation fail, treat it as an individual IP
            try:
                ip = ipaddress.IPv4Address(subnet.strip())
                ip_list = [str(ip)]
            except ValueError:
                print("Invalid subnet or IP format")

    return ip_list


def is_host_up(host):
    try:
        # Send an ICMP echo request and wait for the response
        response = sr1(IP(dst=host) /
                       ICMP(), timeout=1, verbose=False)

        if response:
            return True
        else:
            return False
    except Exception as e:
        print(f"Error: {e}")
        return False


def enumerateTargets(givenTarget):
    global targets_list
    targets_list = generate_ip_list(givenTarget)
    for target in targets_list:  # Move the host_up such that only up hosts are scanned and portscan is after that
        if is_host_up(target):
            print(f"{target} is {green} up")
            portScan(target)

        else:
            print(f"{target} is {red} down")


fast_scan = True
if fast_scan:
    target_ports = range(0, 1024 + 1)
else:
    target_ports = range(0, 65535)
# If disabled, all ports will be scanned. Else 1024 ports will be scanned


# -------- Port Scan--------------------------#

def scan_port(target_host, port):
    try:
        # Create a socket object
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Set a timeout for the connection attempt
        sock.settimeout(1)

        # Attempt to connect to the target host and port
        sock.connect((target_host, port))

        # If successful, print the open port
        print(f"[+] Port {port} is open")

        # Close the socket connection
        sock.close()
    except socket.error:
        pass  # Port is closed


def portScan(target_ip):
    # Print a banner with the target information
    print("-" * 60)
    print(f"Scanning target: {target_ip}")
    print("-" * 60)

    # Record the start time
    start_time = time()

    # Create and start a thread for each port to be scanned
    threads = []
    for port in target_ports:
        thread = threading.Thread(
            target=scan_port, args=(target_ip, int(port)))
        threads.append(thread)
        thread.start()

    # Wait for all threads to finish
    for thread in threads:
        thread.join()

    # Record the end time
    end_time = time()

    # Calculate and print the time difference
    elapsed_time = end_time - start_time
    print(f"\nScan completed in {elapsed_time:.2f} seconds.")


# -------- Port Scan--------------------------#


# scan('8.8.8.8')
# scan("176.20.1.1/24")
# scan('goole.com')
# scan('192.168.221.1-30')

scan("192.168.43.1-53")
