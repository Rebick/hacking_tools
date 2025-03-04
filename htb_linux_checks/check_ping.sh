#!/bin/bash

# Función para mostrar el uso del script
usage() {
    echo "Uso: $0 -t <target>"
    exit 1
}

# Verificar si se proporciona el argumento -t
while getopts "t:" opt; do
    case "$opt" in
        t) target="$OPTARG" ;;
        *) usage ;;
    esac
done

# Validar si se proporcionó un target
if [[ -z "$target" ]]; then
    usage
fi

# Función para mostrar el estado de la conexión
check_connection() {
    if ping -c 1 "$target" &> /dev/null; then
        echo -e "\e[32m[$(date)] Conexión con $target: OK\e[0m"
    else
        echo -e "\e[31m[$(date)] Conexión con $target: FALLIDA\e[0m"
    fi
}

# Bucle infinito para verificar la conexión en intervalos aleatorios
while true; do
    check_connection
    delay=$(( RANDOM % 600 + 300 ))  # Genera un tiempo entre 300s (5 min) y 900s (15 min)
    
    echo -e "\e[34mEsperando $((delay / 60)) minutos antes del próximo chequeo...\e[0m"
    
    for ((i=delay; i>0; i--)); do
        echo -ne "\rSiguiente verificación en: $i segundos..."
        sleep 1
    done
    echo ""
done
