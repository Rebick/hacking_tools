#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import sys
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

def which_or_die(bin_name: str):
    path = shutil.which(bin_name)
    if not path:
        print(f"[!] No encuentro '{bin_name}' en PATH. Instálalo (pipx/pip) o ajusta tu entorno.", file=sys.stderr)
        sys.exit(2)
    return path

def make_outdir(base: str | None) -> Path:
    if base:
        p = Path(base).expanduser().resolve()
    else:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        p = Path.cwd() / f"bloodhound_{ts}"
    p.mkdir(parents=True, exist_ok=True)
    return p

def build_cmd(bh_bin: str, args: argparse.Namespace, outdir: Path) -> list[str]:
    cmd = [
        bh_bin,
        "-u", args.username,
        "-p", args.password,
        "-d", args.domain,
        "-ns", args.nameserver,
        "-c", args.collect,
        "-o", str(outdir),
    ]
    if args.dc:
        cmd += ["-dc", args.dc]
    if args.dns_tcp:
        cmd.append("--dns-tcp")
    if args.zip:
        cmd.append("--zip")
    return cmd

def run_cmd(cmd: list[str]) -> int:
    print("[*] Ejecutando:", " ".join([c if c != "\n" else "\\n" for c in cmd]))
    print("-" * 80)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    try:
        for line in proc.stdout:
            print(line, end="")
    except KeyboardInterrupt:
        print("\n[!] Interrumpido por el usuario. Enviando SIGINT al proceso…")
        proc.terminate()
    finally:
        proc.wait()
    print("-" * 80)
    return proc.returncode

def main():
    ap = argparse.ArgumentParser(
        description="Wrapper para ejecutar bloodhound-python con credenciales y compresión ZIP.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("-u", "--username", required=True, help="Usuario (p. ej. henry)")
    ap.add_argument("-p", "--password", required=True, help="Password (entre comillas si tiene caracteres especiales)")
    ap.add_argument("-d", "--domain",   required=True, help="Dominio (p. ej. tombwatcher.htb)")
    ap.add_argument("-n", "--nameserver", dest="nameserver", required=True, help="IP del DNS/DC (p. ej. 10.10.11.72)")
    ap.add_argument("-c", "--collect", default="All", help="Conjuntos de recolección (All, Group, Session, etc.)")
    ap.add_argument("--dc", help="Hostname/FQDN del DC (si lo conoces, p. ej. DC01.tombwatcher.htb)")
    ap.add_argument("--dns-tcp", action="store_true", help="Forzar DNS sobre TCP (útil si UDP falla)")
    ap.add_argument("--no-zip", dest="zip", action="store_false", help="No generar ZIP al finalizar")
    ap.add_argument("-o", "--output", help="Directorio de salida (por defecto crea uno timestamped en el cwd)")
    ap.add_argument("--bh-bin", default="bloodhound-python", help="Binario/comando a usar")
    args = ap.parse_args()

    bh_bin = which_or_die(args.bh_bin)
    outdir = make_outdir(args.output)
    cmd = build_cmd(bh_bin, args, outdir)

    rc = run_cmd(cmd)
    if rc == 0:
        print(f"[+] Finalizado OK. Revisa los archivos en: {outdir}")
        # Sugerir ZIP si existe
        zips = list(outdir.glob("*.zip"))
        if zips:
            print(f"[+] ZIP generado: {zips[0]}")
        else:
            print("[i] No se encontró ZIP (quizá usaste --no-zip).")
    else:
        print(f"[!] bloodhound-python terminó con código {rc}. Revisa la salida arriba.", file=sys.stderr)
    sys.exit(rc)

if __name__ == "__main__":
    main()
