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

# Verificar que el archivo 'target.txt' exista
if [ ! -f target.txt ]; then
    echo "Archivo 'target.txt' no encontrado. Por favor cree este archivo con los dominios a analizar."
    exit 1
fi

# Paso 1: Encontrar subdominios
echo "Buscando subdominios..."
while read -r domain; do
    subfinder -d "$domain" -all -recursive
done < target.txt > subdomain.txt

subdomain_count=$(wc -l < subdomain.txt)
echo "Se han encontrado $subdomain_count subdominios."

# Confirmar para continuar
read -p "¿Desea continuar con el filtrado de subdominios vivos? (si/no): " confirm
if [[ "$confirm" != "si" ]]; then
    echo "Proceso abortado."
    exit 0
fi

# Paso 2: Filtrar subdominios vivos
echo "Filtrando subdominios vivos..."
cat subdomain.txt | httpx -ports 80,443,8080,8000,8888 -threads 200 > subdomains_alive.txt
alive_count=$(wc -l < subdomains_alive.txt)
echo "Se han encontrado $alive_count subdominios vivos."

# Paso 3: Obtener URLs pasivas
echo "Recolectando URLs pasivas con Katana..."
katana -u subdomains_alive.txt -d 5 -kf -jc -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -o allurls.txt

# Paso 4: Buscar archivos sensibles
echo "Buscando archivos sensibles..."
cat allurls.txt | grep -E '\.xls|\.xml|\.xlsx|\.json|\.pdf|\.sql|\.doc|\.docx|\.pptx|\.txt|\.zip|\.tar\.gz|\.tgz|\.bak|\.7z|\.rar|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.gz|\.config|\.csv|\.yaml|\.md|\.md5' > sensitive_files.txt
sensitive_count=$(wc -l < sensitive_files.txt)
echo "Se han encontrado $sensitive_count archivos sensibles."

# Paso 5: Recolección y ordenamiento de URLs
echo "Recolectando y procesando URLs adicionales..."
while read -r alive_domain; do
    katana -u "$alive_domain" -d 5 -f qurl | urldedupe >> output.txt
    katana -u "$alive_domain" -d 5 | grep '=' | urldedupe | anew output.txt
    gau "$alive_domain" --mc 200 | urldedupe >> urls.txt
done < subdomains_alive.txt

cat urls.txt | grep -E '.php|.asp|.aspx|.jspx|.jsp' | grep '=' | sort > output_sorted.txt
cat output_sorted.txt | sed 's/=.*/=/' > final_urls.txt

# Paso 6: Encontrar parámetros ocultos
echo "Buscando parámetros ocultos con Arjun..."
while read -r endpoint; do
    arjun -u "$endpoint" -oT arjun_output.txt -t 10 --rate-limit 10 --passive -m GET,POST --headers 'User-Agent: Mozilla/5.0'
done < output_sorted.txt

# Paso 7: Comprobar CORS
echo "Verificando configuraciones CORS..."
while read -r alive_domain; do
    cors_check=$(curl -H 'Origin: http://example.com' -I "$alive_domain" | grep -i -e 'access-control-allow-origin' -e 'access-control-allow-methods' -e 'access-control-allow-credentials')
    if [[ ! -z "$cors_check" ]]; then
        echo "Dominio: $alive_domain"
        echo "$cors_check"
    fi
done < subdomains_alive.txt > cors_results.txt

# Crear resumen
{
    echo "=== Resumen de Resultados ==="
    echo "Subdominios encontrados: $subdomain_count"
    echo "Subdominios vivos: $alive_count"
    echo "Archivos sensibles encontrados: $sensitive_count"
    echo "Verificación CORS:"
    cat cors_results.txt
} > resume_report.txt

echo "Proceso completo. Consulte 'resume_report.txt' para un resumen."
