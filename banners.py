# This file helps to grab banners of most of the common ports, useful for service scan
import urllib3
import requests
import re
import socket


def mysql_parser(host, port):
    try:
        # Create a socket object
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Connect to the remote server
        client_socket.connect((host, port))

        # Send data (you can customize this if needed)
        data_to_send = b'\x0b\x00\x00\x00\x0a'
        client_socket.send(data_to_send)

        # Receive the response
        response = client_socket.recv(1024)

        if b"mariadb" in response.lower():
            mariadb_version_match = re.search(
                b'MariaDB-1:([0-9]+\\.[0-9]+\\.[0-9]+)', response)
            if mariadb_version_match:
                mariadb_version = mariadb_version_match.group(
                    1).decode('utf-8')
                return "open", f"MariaDB {mariadb_version}"
            else:
                return "filtered", str(response)

        # print(response)

    except Exception as e:
        print(f"Error: {e}")
    finally:
        # Close the socket
        client_socket.close()


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


def ftp_banner_parser(banner):
    if "Pure-FTPd" in banner:
        return "open", "Pure-FTPd"
    elif "vsFTPd" in banner:
        # Use regular expression to extract version number (5 characters including dots)
        version_match = re.search(r'vsFTPd\s+([\d.]+)', banner)
        if version_match:
            return "open", f"vsFTPd {version_match.group(1)}"
    elif "ProFTPD" in banner:
        # Use regular expression to extract version number (5 characters including dots)
        version_match = re.search(r'ProFTPD\s+([\d.]+)', banner)
        if version_match:
            return "open", f"ProFTPD {version_match.group(1)}"
    return "open", banner


def banner_grab(target_host, port):
    target_ip = socket.gethostbyname(target_host)

    common_web_ports = [80, 443, 8080, 8000, 8443, 3128]

    if port in common_web_ports:  # Assume they are web server for current case, more works on future
        return get_server_info(f"{target_host}:{port}")
    else:  # Else do socket scans
        try:
            # Create a socket object
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Set a longer timeout for the connection attempt
            sock.settimeout(10)

            # Attempt to connect to the target host and port
            sock.connect((target_ip, port))

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
                elif "220" in banner:
                    return ftp_banner_parser(banner)
                else:
                    return mysql_parser(target_ip, port)
            else:
                return "filtered", "N/A"

            # Close the socket connection
            sock.close()
        except socket.error as e:
            try:
                return mysql_parser(target_ip, port)
            except:
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
