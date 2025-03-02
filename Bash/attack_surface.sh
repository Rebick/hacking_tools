#!/bin/bash

# Paso 0: Verificar que las herramientas estén instaladas
tools=(httpx subfinder katana urldedupe gau arjun curl)
missing_tools=()

for tool in "${tools[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
        missing_tools+=("$tool")
    fi
done

if [ ${#missing_tools[@]} -ne 0 ]; then
    echo "Las siguientes herramientas no están instaladas: ${missing_tools[*]}"
    echo "Por favor, instálelas antes de continuar."
    exit 1
fi

echo "Todas las herramientas necesarias están instaladas."

# Paso 1: Encontrar subdominios
subfinder -d $(cat target.txt) -all -recursive > subdomain.txt
subdomain_count=$(wc -l < subdomain.txt)
echo "Se han encontrado $subdomain_count subdominios."

# Confirmar para continuar
read -p "¿Desea continuar con el filtrado de subdominios vivos? (si/no): " confirm
if [[ "$confirm" != "si" ]]; then
    echo "Proceso abortado."
    exit 0
fi

# Paso 2: Filtrar subdominios vivos
cat subdomain.txt | httpx -ports 80,443,8080,8000,8888 -threads 200 > subdomains_alive.txt
alive_count=$(wc -l < subdomains_alive.txt)
echo "Se han encontrado $alive_count subdominios vivos."

# Paso 3: Obtener URLs pasivas
katana -u subdomains_alive.txt -d 5 -kf -jc -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -o allurls.txt

# Paso 4: Buscar archivos sensibles
cat allurls.txt | grep -E '\.xls|\.xml|\.xlsx|\.json|\.pdf|\.sql|\.doc|\.docx|\.pptx|\.txt|\.zip|\.tar\.gz|\.tgz|\.bak|\.7z|\.rar|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.gz|\.config|\.csv|\.yaml|\.md|\.md5' > sensitive_files.txt
sensitive_count=$(wc -l < sensitive_files.txt)
echo "Se han encontrado $sensitive_count archivos sensibles."

# Paso 5: Recolección y ordenamiento de URLs
katana -u https://example.com -d 5 -f qurl | urldedupe > output.txt
katana -u https://example.com -d 5 | grep '=' | urldedupe | anew output.txt
cat output.txt | sed 's/=.*/=/' > final.txt
echo example.com | gau --mc 200 | urldedupe > urls.txt
cat urls.txt | grep -E '.php|.asp|.aspx|.jspx|.jsp' | grep '=' | sort > output.txt
cat output.txt | sed 's/=.*/=/' > final.txt

# Paso 6: Encontrar parámetros ocultos
arjun -u https://site.com/endpoint.php -oT arjun_output.txt -t 10 --rate-limit 10 --passive -m GET,POST --headers 'User-Agent: Mozilla/5.0'
arjun -u https://site.com/endpoint.php -oT arjun_output.txt -m GET,POST -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -t 10 --rate-limit 10 --headers 'User-Agent: Mozilla/5.0'

# Paso 7: Comprobar CORS
cors_check=$(curl -H 'Origin: http://example.com' -I https://etoropartners.com/wp-json/ | grep -i -e 'access-control-allow-origin' -e 'access-control-allow-methods' -e 'access-control-allow-credentials')

# Crear resumen
{
    echo "=== Resumen de Resultados ==="
    echo "Subdominios encontrados: $subdomain_count"
    echo "Subdominios vivos: $alive_count"
    echo "Archivos sensibles encontrados: $sensitive_count"
    echo "Verificación CORS:"
    echo "$cors_check"
} > resume_report.txt

echo "Proceso completo. Consulte 'resume_report.txt' para un resumen."
