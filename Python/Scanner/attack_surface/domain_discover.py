#!/usr/bin/env python3

import argparse
import requests
from bs4 import BeautifulSoup
from tabulate import tabulate


HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
    'Accept-Encoding': 'gzip, deflate',
    'Referer': 'https://rapiddns.io/',
    'Accept-Language': 'en-US,en;q=0.9',
}

COOKIES = {
    'cookieconsent_status': 'dismiss',
}


def consultar_rapiddns(ip):
    urls = [
        f'https://rapiddns.io/s/{ip}#result',
        f'https://rapiddns.io/sameip/{ip}#result'
    ]

    for url in urls:
        try:
            print(f"[+] Consultando RapidDNS para IP: {ip} -> URL: {url}")
            response = requests.get(url, headers=HEADERS, cookies=COOKIES, timeout=7)
            if response.status_code == 200 and '<table' in response.text:
                return response.text
        except Exception as e:
            print(f"[-] Timeout en: {url}")

    print("[-] No se obtuvo respuesta válida de RapidDNS")
    return None


def parsear_tabla(html):
    soup = BeautifulSoup(html, 'html.parser')
    table = soup.find('table')

    if not table:
        return []

    datos = []
    for fila in table.find_all('tr')[1:]:
        columnas = [columna.get_text(strip=True) for columna in fila.find_all('td')]
        if columnas:
            datos.append(columnas)

    return datos


def main():
    parser = argparse.ArgumentParser(description="Consulta dominios por IP en RapidDNS")
    parser.add_argument("-i", "--ip", required=True, help="IP a consultar. Si no trae CIDR, se agrega /24 automáticamente.")
    args = parser.parse_args()

    ip = args.ip
    if '/' not in ip:
        ip += '/24'

    html = consultar_rapiddns(ip)
    if html:
        datos = parsear_tabla(html)
        if datos:
            print(tabulate(datos, headers=["Domain", "Address", "Type", "Date"]))
        else:
            print("[-] No se encontraron registros.")

if __name__ == "__main__":
    main()
