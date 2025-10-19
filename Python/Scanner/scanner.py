import requests                    # Peticiones HTTP sin complicaciones
from bs4 import BeautifulSoup      # Parseo de HTML
import re                          # Expresiones regulares (no usadas aún)

class Scanner:
    def __init__(self, url: str, ignore_links: list[str]):
        # URL raíz que servirá de punto de partida
        self.target_url = url
        # Lista de rutas que NO deben explorarse (logout, admin-kill-session, etc.)
        self.links_to_ignore = ignore_links
        # Session() reutiliza cookies y encabezados; perfecto para autenticación persistente
        self.session = requests.Session()
        # Almacenará los enlaces únicos descubiertos
        self.target_links: list[str] = []

    # -- CRAWLER ------------------------------------------------------------
    def crawl(self) -> None:
        """
        Rastrea la página inicial buscando etiquetas <a>.
        Solo añade enlaces si no se han visto antes.
        Limitaciones:
          · No sigue recursivamente enlaces hijos
          · No resuelve rutas relativas ni filtra dominios externos
          · No controla profundidad ni bucles infinitos
        """
        response = self.session.get(self.target_url)
        soup = BeautifulSoup(response.content, "html.parser")

        for tag in soup.find_all("a"):           # Recorre todas las <a>
            href = tag.get("href")               # Obtiene valor de href
            if not href:
                continue                         # ignora <a> vacías
            if href in self.links_to_ignore:     # respeta la blacklist
                continue
            if href not in self.target_links:    # evita duplicados
                self.target_links.append(href)   # guarda el nuevo enlace

    # -- SCANNER ------------------------------------------------------------
    def run_scanner(self) -> None:
        """
        Itera por cada link encontrado.
        Hoy imprime en consola, pero no ejecuta pruebas de seguridad aún.
        """
        for link in self.target_links:
            print(f"[+] Escaneando {link}")

    # Las siguientes funciones son llamadas desde xss_vulnerability_scanner.py
    # pero *no existen* todavía. Deben implementarse:
    #   · extract_forms(url)           → devuelve lista de formularios
    #   · test_xss_in_form(form,url)   → prueba payload en form
    #   · test_xss_in_link(url)        → inyecta payload en parámetro GET
