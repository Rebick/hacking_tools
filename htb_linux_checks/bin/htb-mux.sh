#!/usr/bin/env bash
# htb-mux.sh — Layout tmux para HTB (3 arriba + 2 abajo apiladas)
# Uso:
#   ./htb-mux.sh <IP_OBJETIVO> <NOMBRE_BOX> [opciones]
#   ./htb-mux.sh 10.10.10.175 Sniper --reset
set -euo pipefail

VERSION="1.5.0"

# ===== Defaults configurables por env =====
HTB_BASE="${HTB_BASE:-$HOME/htb}"       # raíz de boxes
BOTTOM_HEIGHT="${BOTTOM_HEIGHT:-55}"    # % altura franja inferior (10..90)
SESSION_PREFIX="${SESSION_PREFIX:-htb_}"

# Rutas a tus scripts (puedes sobreescribir via env)
VPN_MONITOR="${VPN_MONITOR:-/home/rebick/Documents/Pen/REBICK/hacking_tools/htb_linux_checks/vpn_monitor.sh}"
PING_CHECK="${PING_CHECK:-/home/rebick/Documents/Pen/REBICK/hacking_tools/htb_linux_checks/check_ping.sh}"

# ===== utilidades =====
die(){ echo "ERROR: $*" >&2; exit 1; }
have(){ command -v "$1" >/dev/null 2>&1; }
validate_ip(){
  local ip="$1"
  [[ "$ip" =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])$ ]]
}

print_help(){
cat <<'EOF'
htb-mux.sh — Crea una sesión tmux con 3 paneles arriba (VPN / PING / VPN)
y 2 paneles abajo apiladas (Trabajo #1 y #2). En el panel 1:
- Crea/asegura directorios nmap, content y exploits
- Ejecuta un escaneo Nmap (puertos abiertos -> -sC -sV) y guarda en nmap/nmap-<IP>.txt

USO:
  htb-mux.sh <IP_OBJETIVO> <NOMBRE_BOX> [opciones]

EJEMPLOS:
  htb-mux.sh 10.10.10.175 Sniper
  htb-mux.sh 10.10.10.175 Sniper --reset
  BOTTOM_HEIGHT=65 htb-mux.sh 10.10.10.175 Sniper

OPCIONES:
  -h, --help           Muestra esta ayuda y sale
      --version        Muestra la versión y sale
      --reset          Mata la sesión existente de esa box y la recrea
      --attach-only    Si la sesión existe, solo se adjunta; si no, error
      --height <N>     Porcentaje de alto de la franja inferior (def: 55)
      --base   <PATH>  Directorio raíz de boxes (def: $HOME/htb)
EOF
}

# ===== Parseo de flags =====
RESET=0
ATTACH_ONLY=0
IP_ARG=""
BOX_ARG=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) print_help; exit 0;;
    --version) echo "$VERSION"; exit 0;;
    --reset) RESET=1; shift;;
    --attach-only) ATTACH_ONLY=1; shift;;
    --height) [[ $# -ge 2 ]] || die "--height requiere un valor"; BOTTOM_HEIGHT="$2"; shift 2;;
    --base)   [[ $# -ge 2 ]] || die "--base requiere una ruta"; HTB_BASE="$2"; shift 2;;
    --) shift; break;;
    -*) die "Flag desconocida: $1. Usa --help";;
    *) if [[ -z "$IP_ARG" ]]; then IP_ARG="$1"; else BOX_ARG="${BOX_ARG:-$1}"; fi; shift;;
  esac
done

# ===== Validaciones =====
[[ -n "${IP_ARG:-}" && -n "${BOX_ARG:-}" ]] || { print_help; die "Faltan argumentos: IP y NOMBRE_BOX"; }
validate_ip "$IP_ARG" || die "IP inválida: $IP_ARG"
have tmux || die "tmux no está instalado. Instálalo: sudo apt install tmux"
have nmap || echo "AVISO: nmap no está en PATH; el panel 1 fallará." >&2
[[ -f "$VPN_MONITOR" ]] || echo "AVISO: No encontré VPN_MONITOR: $VPN_MONITOR" >&2
[[ -f "$PING_CHECK"  ]] || echo "AVISO: No encontré PING_CHECK : $PING_CHECK"  >&2

if ! [[ "$BOTTOM_HEIGHT" =~ ^[0-9]+$ && "$BOTTOM_HEIGHT" -ge 10 && "$BOTTOM_HEIGHT" -le 90 ]]; then
  die "--height debe ser entero entre 10 y 90 (recibido: $BOTTOM_HEIGHT)"
fi

# ===== Carpeta de box =====
BOXDIR="$HTB_BASE/$BOX_ARG"
if [[ -d "$BOXDIR" ]]; then
  echo "[htb-mux] Usando box existente: $BOXDIR"
else
  echo "[htb-mux] Creando box: $BOXDIR"
  mkdir -p "$BOXDIR"/{content,nmap,exploits}
fi

SESSION="${SESSION_PREFIX}${BOX_ARG}"

# ===== Sesión =====
if (( RESET )); then
  tmux kill-session -t "$SESSION" 2>/dev/null || true
fi

if tmux has-session -t "$SESSION" 2>/dev/null; then
  if (( ATTACH_ONLY )); then exec tmux attach -t "$SESSION"; fi
  echo "[htb-mux] Sesión '$SESSION' ya existe → adjuntando."
  exec tmux attach -t "$SESSION"
fi

# ===== Nueva sesión y layout (3 arriba, 2 abajo apiladas) =====
tmux new-session -d -s "$SESSION" -n "HTB" -c "$BOXDIR"

# Pane inicial (arriba-izq) — ya nace en $BOXDIR
TOP_LEFT="$(tmux display-message -p '#{pane_id}')"

# Franja inferior (pane superior de la franja) en $BOXDIR
BOTTOM_TOP="$(tmux split-window -v -p "$BOTTOM_HEIGHT" -c "$BOXDIR" -P -F '#{pane_id}')"

# Completar fila superior en $BOXDIR: TL | TM | TR
tmux select-pane -t "$TOP_LEFT"
TOP_RIGHT="$(tmux split-window -h -c "$BOXDIR" -P -F '#{pane_id}')"
tmux select-pane -t "$TOP_LEFT"
TOP_MID="$(tmux split-window -h -c "$BOXDIR" -P -F '#{pane_id}')"

# Abajo: apilados en $BOXDIR
tmux select-pane -t "$BOTTOM_TOP"
BOTTOM_BOTTOM="$(tmux split-window -v -c "$BOXDIR" -P -F '#{pane_id}')"

# ===== Comandos en panes =====
# Arriba-izq: VPN monitor (sudo)
tmux send-keys -t "$TOP_LEFT"  "cd '$BOXDIR'; sudo '$VPN_MONITOR'" C-m

# Arriba-medio: ping check
tmux send-keys -t "$TOP_MID"   "cd '$BOXDIR'; '$PING_CHECK' -t $IP_ARG" C-m

# Arriba-der: VPN monitor normal
tmux send-keys -t "$TOP_RIGHT" "cd '$BOXDIR'; '$VPN_MONITOR'" C-m

# Abajo-arriba (PANEL 1): mkdir + Nmap full → servicios, output en nmap/nmap-<IP>.txt
tmux send-keys -t "$BOTTOM_TOP" \
  "cd '$BOXDIR'; mkdir -p '$BOXDIR'/nmap '$BOXDIR'/content '$BOXDIR'/exploits; \
target='$IP_ARG'; \
ports=\$(nmap -p- --min-rate=1000 -Pn -T4 \$target | grep '^[0-9]' | cut -d '/' -f 1 | tr '\n' ',' | sed 's/,\$//'); \
echo \"[*] Puertos detectados: \$ports\"; \
sudo nmap -p\$ports -Pn -sC -sV \$target -oN '$BOXDIR'/nmap/nmap-\$target.txt" C-m

# Abajo-abajo (PANEL 2): libre
tmux send-keys -t "$BOTTOM_BOTTOM" "cd '$BOXDIR'; clear; echo 'Panel trabajo #2 listo'" C-m

# Arranca enfocado en el pane de trabajo
tmux select-pane -t "$BOTTOM_TOP"
exec tmux attach -t "$SESSION"
