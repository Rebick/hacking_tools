#!/usr/bin/env bash
set -euo pipefail

########################################
# CONFIGURACIÓN
########################################
CONFIG_FILE=${1:-"/home/rebick/Desktop/lab_rebick.ovpn"}   # admite ruta por parámetro
LOG_FILE="/tmp/openvpn_status.log"
STATUS_FILE="/tmp/vpn_status.log"
MONITOR_INTERVAL=5        # s entre chequeos de log
IDLE_LIMIT=$((2*60*60))   # ► 2 h de inactividad ◄

########################################
# COLORES
########################################
RED='\e[1;31m'; GREEN='\e[1;32m'; YELLOW='\e[1;33m'
BLUE='\e[1;34m'; CYAN='\e[1;36m'; NC='\e[0m'

########################################
# FUNCIONES AUXILIARES
########################################
die()  { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }
info() { echo -e "${BLUE}[INFO] ${NC}$*"; }
ok()   { echo -e "${GREEN}[OK]   ${NC}$*"; }
warn() { echo -e "${YELLOW}[WARN] ${NC}$*"; }

check_prereqs() {
    [[ $EUID -eq 0 ]]              || die "Debes ejecutar el script como root o con sudo."
    command -v openvpn &>/dev/null || die "OpenVPN no está instalado o no está en \$PATH."
    [[ -f $CONFIG_FILE && -r $CONFIG_FILE ]] || die "No puedo leer '$CONFIG_FILE'."

    if pgrep -f "openvpn --config $CONFIG_FILE" &>/dev/null; then
        warn "Ya hay un OpenVPN usando '$CONFIG_FILE'. Salgo para no duplicar."
        exit 0
    fi

    : >"$LOG_FILE"    || die "No puedo escribir en '$LOG_FILE'."
    : >"$STATUS_FILE" || die "No puedo escribir en '$STATUS_FILE'."
}

monitor_vpn() {
    while true; do
        if grep -q "Initialization Sequence Completed" "$LOG_FILE"; then
            echo -e "${GREEN}[VPN ONLINE]${NC} La VPN está activa."
        elif grep -qE "SIGTERM|event_wait : Interrupted system call" "$LOG_FILE"; then
            echo -e "${RED}[VPN DOWN]${NC} La VPN se desconectó."
        else
            echo -e "${YELLOW}[VPN ?]${NC} Esperando confirmación..."
        fi
        sleep "$MONITOR_INTERVAL"
    done
}

idle_watch() {
    local last_key epoch
    last_key=$(date +%s)

    while kill -0 "$VPN_PID" &>/dev/null; do
        # Espera 1 s: si se presiona alguna tecla, reinicia el contador
        if read -r -t 1 -n 1 _key; then
            last_key=$(date +%s)
        fi

        epoch=$(date +%s)
        if (( epoch - last_key >= IDLE_LIMIT )); then
            echo -e "\n${CYAN}[IDLE]${NC} 2 h sin actividad. Cerrando VPN…"
            kill "$VPN_PID" 2>/dev/null || true
            kill "$MONITOR_PID" 2>/dev/null || true
            exit 0
        fi
    done
}

########################################
# FLUJO PRINCIPAL
########################################
check_prereqs

info "Iniciando OpenVPN con: $CONFIG_FILE"
openvpn --config "$CONFIG_FILE" >"$LOG_FILE" 2>&1 &
VPN_PID=$!

monitor_vpn &
MONITOR_PID=$!

idle_watch &                    # ← arranca el watchdog
IDLE_PID=$!

trap '
  echo -e "\n${RED}[CTRL-C]${NC} Cerrando VPN…";
  kill $VPN_PID $MONITOR_PID $IDLE_PID 2>/dev/null || true;
  exit
' INT TERM

wait "$VPN_PID"
