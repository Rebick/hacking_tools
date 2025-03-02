import requests
from bs4 import BeautifulSoup
import re

class Scanner:
    def __init__(self, url, ignore_links):
        self.target_url = url
        self.links_to_ignore = ignore_links
        self.session = requests.Session()
        self.target_links = []

    def crawl(self):
        # Lógica para rastrear enlaces en la URL objetivo
        response = self.session.get(self.target_url)
        soup = BeautifulSoup(response.content, "html.parser")
        for link in soup.find_all("a"):
            href = link.get("href")
            if href and href not in self.target_links:
                self.target_links.append(href)

    def run_scanner(self):
        # Lógica para ejecutar el escáner en cada enlace encontrado
        for link in self.target_links:
            print(f"Escaneando {link}")