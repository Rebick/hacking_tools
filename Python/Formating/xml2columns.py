import xml.etree.ElementTree as ET
import sys

def procesar_xml(archivo_xml):
    """Lee y procesa el XML para extraer nombres de usuario y contraseñas."""
    try:
        tree = ET.parse(archivo_xml)
        root = tree.getroot()

        # Espacio de nombres en XML de Excel
        ns = {'ns': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}

        # Extraer todos los valores de <t> dentro de <si>
        valores = [t.text for t in root.findall(".//ns:t", ns) if t.text]

        # Verifica si hay suficientes valores
        if len(valores) < 5:
            print("[✘] No se encontraron suficientes datos en el XML.")
            return

        # Extraer encabezados para verificar estructura
        encabezados = valores[:5]
        if encabezados != ["First Name", "Last Name", "Email", "Username", "Password"]:
            print("[✘] El formato del XML no es válido o esperado.")
            return

        # Procesar datos en bloques de 5 columnas
        resultado = []
        i = 5  # Saltamos los encabezados
        while i < len(valores):
            # Verificar si quedan suficientes valores para una fila completa
            if i + 3 < len(valores):  # Debe haber al menos First Name, Username y Password
                nombre = valores[i]  # First Name
                apellido = valores[i + 1] if i + 1 < len(valores) else " "  # Last Name (si no hay, espacio)
                usuario = valores[i + 3]  # Username
                contraseña = valores[i + 4] if i + 4 < len(valores) else " "  # Password

                # Agregar al resultado
                resultado.append(f"{usuario}:{contraseña}")
                i += 5  # Avanzar al siguiente bloque
            else:
                break

        # Imprimir credenciales extraídas
        if resultado:
            print("\n".join(resultado))
        else:
            print("[✘] No se encontraron usuarios y contraseñas válidos en el XML.")

    except ET.ParseError:
        print("[✘] Error al analizar el XML. Verifica que el archivo sea válido.")
    except FileNotFoundError:
        print(f"[✘] Archivo no encontrado: {archivo_xml}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"[✘] Uso: python3 {sys.argv[0]} archivo.xml")
        sys.exit(1)

    archivo_xml = sys.argv[1]
    procesar_xml(archivo_xml)
