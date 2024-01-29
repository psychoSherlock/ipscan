# This module is in development. It searches the given service for existing vulns in EDB
import pyxploitdb
from colorama import Fore, Style

magneta = Fore.MAGENTA + Style.BRIGHT
yellow = Fore.YELLOW + Style.BRIGHT


def searchvuln(services, target):
    for service in services:
        for x in service.split(" "):
            if x != "":
                print(
                    f"Searching for {yellow}{x}{Fore.RESET} on {magneta}{target}{Fore.RESET}")
                pyxploitdb.searchEDB(x, _print=True)
