#!/bin/bash

CONFIG_FILE="/home/rebick/Desktop/lab_rebick.ovpn"
LOG_FILE="/tmp/openvpn_status.log"
STATUS_FILE="/tmp/vpn_status.log"

# Función para monitorear la conexión
monitor_vpn() {
    while true; do
        if grep -q "Initialization Sequence Completed" "$LOG_FILE"; then
            echo -e "\e[1;32m[VPN ONLINE] La VPN está activa y conectada.\e[0m"
        elif grep -q "SIGTERM" "$LOG_FILE" || grep -q "event_wait : Interrupted system call" "$LOG_FILE"; then
            echo -e "\e[1;31m[VPN DOWN] La VPN ha sido desconectada.\e[0m"
        else
            echo -e "\e[1;33m[VPN INDETERMINADO] Estado no confirmado, esperando...\e[0m"
        fi
        sleep 5
    done
}

# Eliminar archivos previos
rm -f "$LOG_FILE" "$STATUS_FILE"

# Ejecutar OpenVPN en segundo plano y redirigir la salida
echo -e "\e[1;34m[INFO] Iniciando OpenVPN con configuración: $CONFIG_FILE...\e[0m"
sudo openvpn --config "$CONFIG_FILE" > "$LOG_FILE" 2>&1 &

# Obtener el PID del proceso OpenVPN
VPN_PID=$!

# Iniciar monitoreo en segundo plano
monitor_vpn &
MONITOR_PID=$!

# Manejar la señal de interrupción para detener VPN correctamente
trap "echo -e '\n\e[1;31m[INFO] Terminando VPN...\e[0m'; sudo kill $VPN_PID; kill $MONITOR_PID; exit" SIGINT SIGTERM

# Esperar a que OpenVPN termine
wait $VPN_PID
