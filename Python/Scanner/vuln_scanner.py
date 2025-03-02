#!/usr/bin/env python3

import scanner

# URL objetivo y enlaces a ignorar
target_url = "http://192.168.1.8/dvwa/"
links_to_ignore = [target_url + "logout.php"]

# Diccionario de datos para el inicio de sesión
data_dict = {"username": "admin", "password": "password", "Login": "submit"}

# Inicializa el escáner
vuln_scanner = scanner.Scanner(target_url, links_to_ignore)

# Inicia sesión en el objetivo
vuln_scanner.session.post(target_url + "login.php", data=data_dict)

# Realiza el rastreo del sitio y ejecuta el escáner
vuln_scanner.crawl()
vuln_scanner.run_scanner()

# Ejemplo de pruebas adicionales (descomenta si es necesario)
forms = vuln_scanner.extract_forms(target_url + "vulnerabilities/xss_r/")
print(forms)
response = vuln_scanner.test_xss_in_form(forms[0], target_url + "vulnerabilities/xss_r/")
print(response)
response = vuln_scanner.test_xss_in_link(target_url + "vulnerabilities/xss_r/?name=")
print(response)
