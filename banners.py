# This file helps to grab banners of most of the common ports, useful for service scan
import urllib3
import requests
import re
import socket


def extract_ssh_version(banner):
    openssh_keyword = "OpenSSH"

    if openssh_keyword in banner:
        # Find the index of the first occurrence of "OpenSSH"
        index = banner.index(openssh_keyword)

        # Extract the substring starting from the index of "OpenSSH" to the end
        openssh_version = banner[index:]

        return openssh_version
    else:
        # If "OpenSSH" is not present, return the original banner
        return banner


def banner_grab(target_host, port):
    target_ip = socket.gethostbyname(target_host)

    if port == 80 or port == 443:  # Assume they are web server for current case, more works on future
        return get_server_info(f"{target_host}:{port}")
    else:  # Else do socket scans
        try:
            # Create a socket object
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Set a longer timeout for the connection attempt
            sock.settimeout(10)

            # Attempt to connect to the target host and port
            sock.connect((target_host, port))

            sock.send(b'\r\n')
            try:
                banner = sock.recv(1024).decode('utf-8').strip()
            except:
                banner = sock.recv(1024)
            # Receive data from the connected socket
            # banner = sock.recv(1024).decode('utf-8').strip()

            # If a banner is received, print it
            if banner:
                if 'ssh' in banner.lower():
                    return "open", (extract_ssh_version(banner))
                else:
                    pass
                    print('No Banner Found')
            else:
                return "filtered", "N/A"

            # Close the socket connection
            sock.close()
        except socket.error as e:
            print(e)
            print(f"{port} connection timed out")
            return "closed", "N/A"
            pass  # Port is closed


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_server_info(url):
    try:
        try:
            url = f"http://{url}"
        except:
            url = f"https://{url}"

        response = requests.head(url, verify=False, allow_redirects=True)
        headers = response.headers
        server_info = []
        # List of headers to check
        headers_to_check = [
            'X-Powered-By',
            'Server',
            'X-Server',
            'X-AspNet-Version',
            'X-Runtime',
            'X-AspNetMvc-Version',
            'X-Pingback',
            'X-Generator',
            'X-Drupal-Cache'
        ]

        for header in headers_to_check:
            if header in headers:
                server_info.append(f" {headers[header]}")

        if server_info:
            return "open", ' '.join(server_info)
        else:
            return "filtered", "N/A"
    except requests.exceptions.RequestException as e:
        print(f"\nError: {e}\n")
        return "filtered", "N/A"
