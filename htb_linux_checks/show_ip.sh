#!/bin/bash

# Colores ANSI
COLORS=(31 32 33 34 35 36)  # Rojo, Verde, Amarillo, Azul, Magenta, Cian
INTERFACES=($(ip -o link show | awk -F': ' '{print $2}' | grep -v "^lo$"))

while true; do
    clear
    echo -e "\e[1;37m[INFO] Extrayendo direcciones IP de las interfaces...\e[0m"
    
    index=0
    for iface in "${INTERFACES[@]}"; do
        ip_addr=$(ip -o -4 addr show "$iface" | awk '{print $4}' | cut -d/ -f1)
        if [[ -n $ip_addr ]]; then
            color=${COLORS[index % ${#COLORS[@]}]}
            echo -e "\e[1;${color}m[INTERFAZ: $iface] IP: $ip_addr\e[0m"
            ((index++))
        else
            echo -e "\e[1;37m[INTERFAZ: $iface] No tiene IP asignada.\e[0m"
        fi
    done

    # Cuenta regresiva de 5 minutos (300 segundos)
    for ((i=300; i>0; i--)); do
        echo -ne "\e[1;37mActualizando en: $i segundos... \r\e[0m"
        sleep 1
    done
done
