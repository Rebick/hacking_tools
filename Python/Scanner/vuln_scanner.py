#!/usr/bin/env python3
"""
Script de ejemplo que usa la clase Scanner para:
  1. Autenticarse en DVWA
  2. Rastrear enlaces
  3. Probar XSS (las funciones de prueba aún no están implementadas)
"""
import scanner

target_url = "http://192.168.1.8/dvwa/"
links_to_ignore = [target_url + "logout.php"]

# Credenciales para DVWA (modo low security)
data_dict = {"username": "admin", "password": "password", "Login": "submit"}

vuln_scanner = scanner.Scanner(target_url, links_to_ignore)

# 1. Login – las cookies quedan almacenadas en vuln_scanner.session
vuln_scanner.session.post(target_url + "login.php", data=data_dict)

# 2. Descubrimiento de enlaces
vuln_scanner.crawl()

# 3. Ejecución (por ahora solo imprime cada URL)
vuln_scanner.run_scanner()

# 4. Ejemplo de uso futuro (no funcionará hasta codificar los métodos)
forms = vuln_scanner.extract_forms(target_url + "vulnerabilities/xss_r/")
print(forms)
resp = vuln_scanner.test_xss_in_form(forms[0], target_url + "vulnerabilities/xss_r/")
print(resp)
resp = vuln_scanner.test_xss_in_link(target_url + "vulnerabilities/xss_r/?name=")
print(resp)
