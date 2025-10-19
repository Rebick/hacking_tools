#!/usr/bin/env python3

import argparse
import requests
import json
from bs4 import BeautifulSoup
from tabulate import tabulate
import subprocess
import re

# Variables Globales
HEADERS = {'User-Agent': 'Mozilla/5.0'}


def search_asn(query):
    url = f'https://api.bgpview.io/search?query_term={query}'
    response = requests.get(url, headers=HEADERS)
    return response.json() if response.status_code == 200 else None


def extract_asn_info(data):
    results = []
    detailed_ips = {}
    asns = data.get('data', {}).get('asns', [])
    ipv4s = data.get('data', {}).get('ipv4_prefixes', [])
    ipv6s = data.get('data', {}).get('ipv6_prefixes', [])

    for asn in asns:
        ipv4_list = [ip['prefix'] for ip in ipv4s if ip['description'] == asn['description']]
        ipv6_list = [ip['prefix'] for ip in ipv6s if ip['description'] == asn['description']]
        parent_ips = list(set([ip['parent_ip'] for ip in ipv4s if ip['description'] == asn['description']]))
        ipv4_count = len(ipv4_list)
        ipv6_count = len(ipv6_list)
        parent_ip_count = len(parent_ips)
        results.append([
            asn['asn'], asn['name'], asn['country_code'], ', '.join(asn['abuse_contacts']),
            ', '.join(asn['email_contacts']), ipv4_count, ipv6_count, parent_ip_count
        ])
        detailed_ips[asn['asn']] = ipv4_list + ipv6_list

    return results, detailed_ips


def run_nmap(asn):
    cmd = ["nmap", "--script", "targets-asn", f"--script-args=targets-asn.asn={asn}"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout


def parse_nmap_output(output):
    return re.findall(r'\d+\.\d+\.\d+\.\d+', output)


def main():
    parser = argparse.ArgumentParser(description="Attack Surface Recon Tool")
    parser.add_argument("-q", "--query", help="Search keyword (ex: paypal)", required=True)
    args = parser.parse_args()

    print(f"[+] Buscando resultados para: {args.query}")
    data = search_asn(args.query)

    if not data:
        print("[!] Error obteniendo datos de BGPView")
        return

    asn_results, detailed_ips = extract_asn_info(data)

    print(tabulate(asn_results, headers=['ASN', 'Nombre', 'Pais', 'Abuse Contact', 'Email Contact', 'IPv4', 'IPv6', 'Parent IP']))

    if len(asn_results) == 1:
        selected_asn = asn_results[0][0]
    else:
        selected_asn = input("[?] Selecciona el ASN para Nmap y RapidDNS: ")

    print(f"\n[+] Ejecutando Nmap en ASN: {selected_asn}")
    output = run_nmap(selected_asn)
    ips = parse_nmap_output(output)

    if not ips:
        print(f"[-] ASN {selected_asn} sin IPs activas")
    else:
        print(f"[+] IPs detectadas por Nmap:\n{chr(10).join(ips)}")

    print(f"\n[+] Detalle de IPs encontradas para ASN {selected_asn}:")
    for idx, ip in enumerate(detailed_ips.get(int(selected_asn), []), 1):
        print(f"{idx}. {ip}")


if __name__ == "__main__":
    main()
