#!/usr/bin/env python3
"""
attack_surface_report.py
Genera un resumen ejecutivo y técnico de la superficie de ataque
a partir de los archivos producidos por subfinder, httpx, katana y gau.

Estructura de salida:
├── attack_surface_report.md   (resumen en Markdown)
└── report_data/
    ├── domains.csv
    ├── subdomains.csv
    ├── alive.csv
    ├── urls_katana.csv
    ├── urls_gau.csv
    └── urls_combined.csv
"""

from pathlib import Path
from datetime import datetime
import csv
import re
import textwrap

# ------------ Configuración básica ------------
FILES = {
    "targets":        Path("target.txt"),
    "subdomains":     Path("subdomain.txt"),
    "alive":          Path("subdomains_alive.txt"),
    "katana_urls":    Path("katana_urls.txt"),
    "gau_urls":       Path("gau_urls.txt"),
}
REPORT_MD   = Path("attack_surface_report.md")
DATA_FOLDER = Path("report_data")      # CSV detallados
DATA_FOLDER.mkdir(exist_ok=True)

# Extensiones sensibles (regex pre-compilado)
SENS_EXT_RE = re.compile(
    r"\.(?:xls[xm]?|json|pdf|sql|docx?|pptx?|txt|zip|tar\.gz|tgz|bak|7z|rar|"
    r"log|cache|secret|db|backup|ya?ml|gz|config|csv|md\d?)$", re.I
)

# ------------ Funciones auxiliares ------------
def read_lines(path: Path) -> list[str]:
    if not path.exists():
        print(f"[WARN] {path} no encontrado; se ignora.")
        return []
    return [l.strip() for l in path.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip()]

def write_csv(path: Path, rows):
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["value"])
        writer.writerows([[r] for r in sorted(rows)])

def count_sensitive(urls: set[str]) -> tuple[int, dict[str, int]]:
    hits = [u for u in urls if SENS_EXT_RE.search(u)]
    ext_stats: dict[str, int] = {}
    for url in hits:
        ext = re.search(r"\.([a-z0-9.]+)$", url, re.I).group(1).lower()
        ext_stats[ext] = ext_stats.get(ext, 0) + 1
    return len(hits), dict(sorted(ext_stats.items(), key=lambda x: (-x[1], x[0])))

# ------------ Lectura de datos ------------
targets        = set(read_lines(FILES["targets"]))
subdomains     = set(read_lines(FILES["subdomains"]))
alive          = set(read_lines(FILES["alive"]))
katana_urls    = set(read_lines(FILES["katana_urls"]))
gau_urls       = set(read_lines(FILES["gau_urls"]))
all_urls       = katana_urls | gau_urls

# ------------ Estadísticas básicas ------------
param_urls     = {u for u in all_urls if "?" in u and "=" in u}
sensitive_cnt, sensitive_breakdown = count_sensitive(all_urls)

stats = {
    "Fecha de generación":       datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    "Dominios objetivo":         len(targets),
    "Subdominios descubiertos":  len(subdomains),
    "Subdominios vivos":         len(alive),
    "URLs (Katana)":             len(katana_urls),
    "URLs (gau)":                len(gau_urls),
    "URLs únicas totales":       len(all_urls),
    "URLs con parámetros":       len(param_urls),
    "URLs con archivos sensibles": sensitive_cnt,
}

# ------------ Exportar CSV detallados ------------
write_csv(DATA_FOLDER / "domains.csv",      targets)
write_csv(DATA_FOLDER / "subdomains.csv",   subdomains)
write_csv(DATA_FOLDER / "alive.csv",        alive)
write_csv(DATA_FOLDER / "urls_katana.csv",  katana_urls)
write_csv(DATA_FOLDER / "urls_gau.csv",     gau_urls)
write_csv(DATA_FOLDER / "urls_combined.csv", all_urls)

# ------------ Construcción del reporte MD ------------
with REPORT_MD.open("w", encoding="utf-8") as md:
    md.write(f"# Attack Surface Report\n\n")
    md.write(f"**Fecha de generación:** {stats['Fecha de generación']}\n\n")
    md.write("## Resumen Ejecutivo\n\n")
    md.write("| Métrica | Valor |\n|---|---|\n")
    for k, v in stats.items():
        if k.startswith("Fecha"):
            continue
        md.write(f"| {k} | {v} |\n")
    md.write("\n")

    md.write("### Archivos sensibles detectados\n\n")
    if sensitive_cnt:
        md.write(f"Se encontraron **{sensitive_cnt}** URLs con extensiones potencialmente "
                 "sensibles. Desglose por extensión:\n\n| Extensión | Cantidad |\n|---|---|\n")
        for ext, cnt in sensitive_breakdown.items():
            md.write(f"| .{ext} | {cnt} |\n")
    else:
        md.write("_No se detectaron archivos que coincidan con el patrón de extensiones "
                 "sensibles._\n")
    md.write("\n")

    md.write("### Distribución de URLs con parámetros\n\n")
    md.write(f"Hay **{len(param_urls)}** URLs que contienen parámetros (`?key=value`). "
             "Revisa `report_data/urls_combined.csv` para la lista completa.\n\n")

    md.write("## Detalle Técnico\n\n")
    md.write(textwrap.dedent("""
    1. **Inventario de dominios y subdominios**  
       - `report_data/domains.csv`  
       - `report_data/subdomains.csv`

    2. **Respuesta de liveness (httpx)**  
       - `report_data/alive.csv`

    3. **Recolección de URLs**  
       - Katana (`report_data/urls_katana.csv`)  
       - gau (`report_data/urls_gau.csv`)  
       - Combinadas (`report_data/urls_combined.csv`)

    4. **Siguiente pasos sugeridos**
       - Escaneo de vulnerabilidades sobre los hosts vivos.  
       - Análisis de endpoints con parámetros (`sqlmap`, `xssmap`, etc.).  
       - Descarga y análisis manual de los archivos sensibles detectados.  
       - Re-evaluación tras aplicar remediaciones.
    """))

print(f"[+] Reporte generado: {REPORT_MD}")
print(f"[+] CSV detallados en:  {DATA_FOLDER}/")
