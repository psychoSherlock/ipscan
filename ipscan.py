from ping3 import ping, verbose_ping
from scapy.all import IP, sr1, ICMP, TCP
import os
from time import sleep, gmtime, strftime, time
from datetime import datetime
from terminaltables import DoubleTable
from colorama import Fore, init, Style
from platform import system
import re
import socket
import ipaddress
import threading
import queue
import logging
import csv
import argparse
from banners import *
#### configurations ###

init(autoreset=True)  # To autoreset colors

magneta = Fore.MAGENTA + Style.BRIGHT
green = Fore.GREEN + Style.BRIGHT
yellow = Fore.YELLOW + Style.BRIGHT
red = Fore.RED + Style.BRIGHT


# Disable scapy mac address error warning
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def whatservice(port_number):
    with open('service-ports.csv', 'r') as file:
        csv_reader = csv.DictReader(file)

        for row in csv_reader:
            if row['Port Number'] == port_number:
                return row['Service Name']
    return "Unknown"  # Return None if the port number is not found


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


probable_targets = []


def scan(givenTarget):
    global actualGivenTarget  # Required for later access
    actualGivenTarget = givenTarget  # Actual target is later required for domain access
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


def worker(host_queue):
    while not host_queue.empty():
        target = host_queue.get()
        if is_host_up(target):
            print(f"{target} is {green} up")
            live_targets.append(target)
        else:
            # print(f"{target} is {red} down")
            pass
        host_queue.task_done()


def enumerateTargets(givenTarget):
    global probable_targets
    probable_targets = generate_ip_list(givenTarget)
    global live_targets
    live_targets = []

    # Use a queue to share targets among threads
    target_queue = queue.Queue()
    for target in probable_targets:
        target_queue.put(target)

    # Create and start threads
    # Adjust the number of threads as needed
    num_threads = min(30, target_queue.qsize())
    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=worker, args=(target_queue,))
        threads.append(thread)
        thread.start()

    # Wait for all threads to finish
    for thread in threads:
        thread.join()
    print('\n\n')
    hostTable = [["HOST", "STATUS"]]
    for x in live_targets:
        # Print the hosts table
        hostTable.append([str(x), f"{green}up{Fore.RESET}"])
    print(DoubleTable(hostTable, "Alive Hosts").table)
    for l in live_targets:
        portScan(l)


# If disabled, all ports will be scanned. Else 1024 ports will be scanned


# -------- Port Scan--------------------------#

def scan_port(target_host, port):
    global open_ports  # open ports wont be modified because every scan resets it to 0. if modifed while doing the portscan then no ports would be present
    try:
        # Create a socket object
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Set a timeout for the connection attempt
        sock.settimeout(1)

        # Attempt to connect to the target host and port
        sock.connect((target_host, port))

        # If successful, print the open port
        open_ports.append(port)
        if args.service:
            print(f"Port {green}{port}{Fore.RESET} is Open")

        # Close the socket connection
        sock.close()
    except socket.error:
        pass  # Port is closed
    return open_ports


def portScan(target_ip):
    global open_ports
    open_ports = []  # Reset open ports list at the start of every new portScan such that ports of previous target is not present here
    # Print a banner with the target information
    print('\n')
    print("-" * 60)
    print(f"Scanning target: {target_ip}")
    if args.service:
        print(
            f'\n{red}[+] Service scan is enabled. Open ports will be displayed to save time: ')
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

    if not args.service:
        # ----- Scan without service --------
        portTable = [["PORT", "STATE", "SERVICE"]]
        for o in open_ports:  # o is port
            # Print the hosts table
            portTable.append(
                [str(o), f"{green}open{Fore.RESET}", f"{whatservice(str(o))}"])
        print(DoubleTable(portTable, f"{target_ip}").table)

        # ------- Scan without Service ------------

    # -------- Scan with Service ------------
    else:
        print(f"\n{green}[!] Starting service scan...\n")
        portTable = [["PORT", "STATE", "VERSION"]]

        # Actual state and Actual Version
        for o in open_ports:
            # Here args is passed for domain access and resolved in the banner function
            actState, actVersion = banner_grab(actualGivenTarget, o)
            portTable.append(
                [str(o), f'{green if actState == "open" else red}{actState}{Fore.RESET}', f"{actVersion}"])
        print(DoubleTable(portTable, f"{target_ip}").table)

    # -------- Scan with service ------------

    # Calculate and print the time difference
    elapsed_time = end_time - start_time
    print(f"\nScan completed in {elapsed_time:.2f} seconds.\n")


# -------- Port Scan--------------------------#


# --------- Version Detecter ------------------#


# Added in banners.py for easy of reading

# ---------- Version Detecter -----------------#


# --------- Command Line Setup------------------#

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="IPScan - Network Mapper and Vulnerability Scanner")

    parser.add_argument('-t', '--target', dest='target', required=False,
                        help='Target IP / Subnet / Domain')

    parser.add_argument('-p', '--port', dest='port', required=False,
                        help='A single port / port range to scan. Eg: -p 20-25')

    parser.add_argument('-f', '--full-scan', dest='full_scan', action='store_true',
                        help='Scan all ports (1-65535). Default is 1-1024')

    parser.add_argument('-sV', '--service-scan', dest="service", action='store_true',
                        help="Identify the running services by fingerprinting and banner-grabbing. This may take more time")

    parser.add_argument('-i', '--input', dest='input_file',
                        help='Read input from a file. Each line will be treated as a target. You can also use CIDR notation')

    args = parser.parse_args()

    if not args.target and not args.input_file:
        parser.error(
            "The -t/--target option is required unless -i/--input is provided.")

    # Port specifications
    global target_ports
    if args.full_scan:
        target_ports = range(0, 65535)  # if full scan enabled, scan all ports
    elif args.port:
        if "-" in args.port:
            x1, x2 = args.port.split('-')  # if range is given, scan the range
            target_ports = list(range(int(x1), int(x2)))
        else:
            target_ports = [int(args.port)]  # just single port
    else:
        target_ports = range(0, 1024 + 1)  # fast scan with 1024 ports

    return args
# --------- Command Line Setup------------------#


def main():
    global args
    args = parse_arguments()
    if args.input_file:
        # Read lines from the input file and call the scan function for each line
        with open(args.input_file, 'r') as file:
            for line in file:
                scan(line.strip())

    else:
        scan(args.target)


if __name__ == "__main__":
    main()

# scan('8.8.8.8')
# scan("176.20.1.1/24")
# scan('goole.com')
# scan('192.168.221.1-30')
# scan('scanme.nmap.org')
# scan("scanme.nmap.org")
# scan("google.com")
# scan("attacker.com")
