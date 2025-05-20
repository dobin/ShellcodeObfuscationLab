#!/usr/bin/env python3

import argparse
import sys
from ipaddress import ip_address
"""
Convert shellcode into IPv4 addresses
Based on: https://github.com/wsummerhill/IPv4Fuscation-Encrypted/blob/main/IPv4encrypt-shellcode.py
https://infosecwriteups.com/the-art-of-obfuscation-evading-static-malware-detection-f4663ae4716f
"""


def get_ips(ip_input, version):
    ip_string = ("const char* IPv{}s[] = ".format(version) + "{\n")

    if version == "4":
        ipsPerLine = 5
    else:
        ipsPerLine = 2
        
    for i in range(0, len(ip_input), ipsPerLine):
        ips_batch = ip_input[i:i + ipsPerLine]
        ip_string += '  ' + ', '.join(['"{}"'.format(ip) for ip in ips_batch]) + ',\n'

    ip_string = ip_string.rstrip(', \n') # Remove trailing comma and space
    ip_string += (" };")

    return ip_string


def bin2ip(input_file) -> str:
    chunk_size = 4 # ipv4

    # Read input shellcode file to get it in IPv4 format
    raw_ips = []
    with open(input_file, "rb") as f:
        chunk = f.read(chunk_size)
        while chunk:
            if len(chunk) < chunk_size: 
                padding = chunk_size - len(chunk)
                chunk = chunk + (b"\x90" * padding)
                raw_ips.append(str(ip_address(chunk)))
                break
            
            raw_ips.append(str(ip_address(chunk)))
            chunk = f.read(chunk_size)

    ips_string = get_ips(raw_ips, "4")
    return ips_string



