import argparse
import subprocess

def authenticate(ip_target, user, password, domain):
    """Ejecuta CrackMapExec para verificar autenticación con dominio."""
    print(f"\033[34m[INFO] Probando autenticación con {domain}\\{user}@{ip_target}...\033[0m")
    
    cmd = ["cme", "smb", ip_target, "-u", user, "-p", password, "-d", domain]
    result = subprocess.run(cmd, capture_output=True, text=True)

    if "[+]" in result.stdout:
        print(f"\033[32m[✔] Autenticación exitosa: {domain}\\{user}:{password}\033[0m")
    else:
        print(f"\033[31m[✘] Credenciales incorrectas: {domain}\\{user}:{password}\033[0m")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-ip-target", required=True)
    parser.add_argument("-user", required=True)
    parser.add_argument("-password", required=True)
    parser.add_argument("-domain", required=True)

    args = parser.parse_args()
    authenticate(args.ip_target, args.user, args.password, args.domain)
