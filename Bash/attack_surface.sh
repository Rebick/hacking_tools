#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

# 0. Verificar dependencias
tools=(httpx subfinder katana urldedupe gau arjun curl anew)
for t in "${tools[@]}"; do
  command -v "$t" &>/dev/null || {
    echo "[ERROR] Falta la herramienta '$t'. Instálala y reintenta." >&2
    exit 1
  }
done
echo "[+] Dependencias OK"

# 1. Recolectar subdominios
TARGET_LIST="target.txt"
[[ -s $TARGET_LIST ]] || { echo "[ERROR] $TARGET_LIST vacío o inexistente" >&2; exit 1; }

echo "[*] Buscando subdominios…"
subfinder -silent -dL "$TARGET_LIST" -all -recursive -o subdomain.txt
subdomain_count=$(wc -l < subdomain.txt)
echo "[+] $subdomain_count subdominios encontrados"

read -r -p "¿Continuar con la detección de vivos? [si/no] " confirm
[[ $confirm == "si" ]] || { echo "[*] Abortado por el usuario."; exit 0; }

# 2. Verificar subdominios vivos
echo "[*] Comprobando puertos comunes…"
httpx -l subdomain.txt -ports 80,443,8080,8000,8888 -silent -threads 200 -o subdomains_alive.txt
alive_count=$(wc -l < subdomains_alive.txt)
echo "[+] $alive_count vivos"

[[ $alive_count -gt 0 ]] || { echo "[WARN] No hay subdominios vivos. Fin."; exit 0; }

# 3. Enumerar URLs (crawling y fuentes pasivas)
echo "[*] Recolectando URLs con Katana…"
katana -list subdomains_alive.txt -d 5 -silent -kf -jc -fx \
  -ef woff,css,png,svg,jpg,woff2,jpeg,gif -o katana_urls.txt

echo "[*] Recolectando URLs desde gauges (gau)…"

gau --threads 10 --subs --o gau_urls.txt --providers wayback,commoncrawl,otx,urlscan < subdomains_alive.txt

cat katana_urls.txt gau_urls.txt | urldedupe > allurls.txt
url_total=$(wc -l < allurls.txt)
echo "[+] $url_total URLs totales"

# 4. Detectar archivos potencialmente sensibles
grep -E -i '\.(xls[xm]?|json|pdf|sql|docx?|pptx?|txt|zip|tar\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|ya?ml|gz|config|csv|md5?)$' allurls.txt \
  | sort -u > sensitive_files.txt
sensitive_count=$(wc -l < sensitive_files.txt)
echo "[+] $sensitive_count archivos/urls sensibles"

# 5. Detectar endpoints con parámetros
echo "[*] Extrayendo endpoints con parámetros…"
grep -E '\?.+=.+' allurls.txt | anew param_urls.txt >/dev/null
param_count=$(wc -l < param_urls.txt)

# 6. Arjun para parámetros ocultos (con validación previa)
if [[ $param_count -gt 0 ]]; then
  echo "[*] Ejecutando Arjun sobre $param_count endpoints…"

  # Limpiar la lista (quitar vacíos y dejar solo http/https)
  grep -E '^https?://' param_urls.txt | sed '/^$/d' > param_urls_temp.txt

  # Validar cada URL antes de pasarla a Arjun
  > param_urls_clean.txt
  > param_urls_invalid.log
  while IFS= read -r url; do
    # Probar con curl HEAD (timeout 10s, silencioso, seguir redirecciones)
    if curl -Is --max-time 10 --location "$url" | head -1 | grep -q "HTTP"; then
      echo "$url" >> param_urls_clean.txt
    else
      echo "[-] URL inválida o sin respuesta: $url" | tee -a param_urls_invalid.log
    fi
  done < param_urls_temp.txt

  valid_count=$(wc -l < param_urls_clean.txt)
  if [[ $valid_count -gt 0 ]]; then
    echo "[*] Ejecutando Arjun sobre $valid_count endpoints válidos…"
    arjun -i param_urls_clean.txt -T 10 -oT arjun_output.txt
  else
    echo "[WARN] No se encontraron endpoints válidos para Arjun después de la validación"
  fi
else
  echo "[WARN] Sin endpoints con parámetros para Arjun"
fi

# 7. Verificación CORS rápida por cada host vivo
echo "[*] Verificando CORS…"
> cors_results.txt
while read -r url; do
  origin=$(awk -F/ '{print $3}' <<<"$url")
  cors=$(curl -ks -H "Origin: http://evil.com" -o /dev/null -w '%{http_code} ' -I "$url" \
         | grep -iE 'access-control-allow-origin|credentials' || true)
  [[ -n $cors ]] && echo "$url => $cors" >> cors_results.txt
done < <(cut -d/ -f1-3 subdomains_alive.txt | sort -u)

cors_count=$(wc -l < cors_results.txt)

# 8. Resumen
cat > resume_report.txt <<EOF
=== Resumen de Resultados ===
Fecha: $(date '+%F %T')
Dominios analizados     : $(wc -l < "$TARGET_LIST")
Subdominios encontrados  : $subdomain_count
Subdominios vivos        : $alive_count
URLs totales             : $url_total
Endpoints con parámetros : $param_count
Archivos sensibles       : $sensitive_count
Hosts con CORS expuesto  : $cors_count

Archivos generados:
- subdomain.txt
- subdomains_alive.txt
- allurls.txt
- sensitive_files.txt
- param_urls.txt
- arjun_output.txt
- cors_results.txt
EOF

echo "[+] Proceso completado. Consulta 'resume_report.txt'."

