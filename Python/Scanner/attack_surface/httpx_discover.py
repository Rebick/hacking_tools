#!/usr/bin/env python3

import argparse
import httpx
import re
from rich import print
from rich.table import Table

def parse_masscan_output(file_path):
    targets = {}
    with open(file_path, 'r') as f:
        for line in f:
            if line.startswith("open tcp"):
                parts = line.split()
                port = parts[2]
                ip = parts[3]
                if ip not in targets:
                    targets[ip] = set()
                targets[ip].add(port)
    return targets


def test_httpx(ip, ports):
    print(f"[+] Testing IP: {ip}")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("URL")
    table.add_column("Status", justify="right")
    table.add_column("Length", justify="right")
    table.add_column("Title")

    for port in ports:
        print(f"[*] Probando puerto: {port}")  # DEBUG
        urls = [
            f"http://{ip}:{port}",
            f"https://{ip}:{port}"
        ]
        for url in urls:
            try:
                response = httpx.get(url, timeout=5, follow_redirects=True, verify=False)
                title = re.search(r'<title>(.*?)</title>', response.text, re.IGNORECASE)
                title_text = title.group(1) if title else "No Title"
                table.add_row(url, str(response.status_code), str(len(response.text)), title_text)
            except Exception as e:
                # Puedes descomentar esto si quieres debug completo
                # print(f"[-] Error {url}: {e}")
                pass
    print(table)
    print("-" * 80)


def main():
    parser = argparse.ArgumentParser(description="Detect HTTP/HTTPS services on Masscan output")
    parser.add_argument("-f", "--file", required=True, help="Masscan output file")
    args = parser.parse_args()

    targets = parse_masscan_output(args.file)

    for ip, ports in targets.items():
        test_httpx(ip, ports)


if __name__ == "__main__":
    main()
