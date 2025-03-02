import subprocess
import platform

class SMBEvaluation:
    def __init__(self, ip_target):
        self.ip_target = ip_target

    def check_connectivity(self):
        """Verifica si el servidor SMB responde al ping antes de continuar."""
        print(f"\033[34m[INFO] Verificando conectividad con {self.ip_target}...\033[0m")

        ping_cmd = ["ping", "-c", "1", self.ip_target] if platform.system().lower() != "windows" else ["ping", "-n", "1", self.ip_target]

        try:
            result = subprocess.run(ping_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if result.returncode == 0:
                print(f"\033[32m[✔] El servidor {self.ip_target} está en línea.\033[0m")
                return True
            else:
                print(f"\033[31m[✘] El servidor {self.ip_target} NO responde al ping. Abortando.\033[0m")
                return False
        except Exception as e:
            print(f"\033[31m[!] Error al ejecutar el ping: {e}\033[0m")
            return False

    def check_anonymous_shares(self):
        """Verifica si hay carpetas accesibles sin autenticación."""
        print(f"\033[34m[INFO] Buscando carpetas accesibles anónimamente en {self.ip_target}...\033[0m")

        try:
            cmd = ["smbmap", "-H", self.ip_target, "-u", "", "-p", ""]
            result = subprocess.run(cmd, capture_output=True, text=True)

            if "ADMIN$" in result.stdout or "IPC$" in result.stdout:
                print(f"\033[33m[!] Solo recursos administrativos detectados. No hay carpetas compartidas accesibles anónimamente.\033[0m")
            elif "Disk" in result.stdout:
                print(f"\033[32m[✔] Carpetas accesibles sin usuario:\033[0m")
                print(result.stdout)
            else:
                print(f"\033[31m[✘] No se encontraron carpetas accesibles anónimamente.\033[0m")

        except Exception as e:
            print(f"\033[31m[!] Error al ejecutar smbmap: {e}\033[0m")
