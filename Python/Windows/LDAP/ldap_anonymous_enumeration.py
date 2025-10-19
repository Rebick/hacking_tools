#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ldap_enum.py — Enumeración básica de LDAP/AD con bind anónimo.

Ejemplos:
  python3 ldap_enum.py --target 10.10.11.72 --dc DC01.tombwatcher.htb
  python3 ldap_enum.py --target 10.10.11.72 --dc DC01.tombwatcher.htb --users-limit 500 --out-users users.txt
  python3 ldap_enum.py --target 10.10.11.72 --dc DC01.tombwatcher.htb --ssl --port 636 --insecure

Notas:
- Deriva el Base DN a partir del FQDN de dominio de --dc (p. ej. tombwatcher.htb -> DC=tombwatcher,DC=htb)
- Para LDAP anónimo en AD, algunas configuraciones pueden denegar listados: el script lo indicará.
"""

import argparse
import socket
import sys
from typing import List, Optional, Tuple, Dict

try:
    from ldap3 import Server, Connection, ALL, SUBTREE, BASE, ALL_ATTRIBUTES, Tls
    from ldap3.core.exceptions import LDAPSocketOpenError, LDAPException
except Exception as e:
    print("[!] Falta la librería ldap3. Instálala con: pip install ldap3", file=sys.stderr)
    sys.exit(2)

import ssl
import re
import math
import json

# ------------------------- Utilidades -------------------------

def fqdn_to_domain(fqdn: str) -> str:
    """
    Extrae el dominio de un FQDN de DC (p.ej., 'DC01.tombwatcher.htb' -> 'tombwatcher.htb')
    Si ya es dominio, lo retorna tal cual.
    """
    parts = fqdn.strip().split(".")
    if len(parts) >= 2:
        # Si el primer label parece nombre de host (DC01), devolvemos lo demás
        return ".".join(parts[1:]) if len(parts) > 2 else ".".join(parts)
    return fqdn

def domain_to_base_dn(domain: str) -> str:
    """
    'tombwatcher.htb' -> 'DC=tombwatcher,DC=htb'
    """
    labels = [p for p in domain.strip().split(".") if p]
    return ",".join(f"DC={l}" for l in labels)

def test_tcp(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

def filetime_100ns_to_str(neg_100ns: int) -> str:
    """
    AD guarda maxPwdAge/minPwdAge/lockoutDuration/lockoutObservationWindow como enteros
    negativos en intervalos de 100 nanosegundos.
    Convierte a una representación humana (días, horas, minutos).
    """
    # valores suelen ser negativos; usamos valor absoluto
    val = abs(int(neg_100ns))
    seconds = val / 10_000_000
    # Formateo simple
    days = int(seconds // 86400)
    seconds -= days * 86400
    hours = int(seconds // 3600)
    seconds -= hours * 3600
    minutes = int(seconds // 60)
    return f"{days}d {hours}h {minutes}m"

def get_first_attr(entry, attr: str, default=None):
    try:
        v = entry[attr].value
        return v if v is not None else default
    except Exception:
        return default

# ------------------------- LDAP Lógica -------------------------

def make_server(host: str, port: int, use_ssl: bool, insecure: bool):
    tls = None
    if use_ssl:
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        tls = Tls(validate=ssl.CERT_NONE if insecure else ssl.CERT_REQUIRED, version=ssl.PROTOCOL_TLS_CLIENT, ca_certs_file=None, ca_certs_path=None, local_private_key_password=None, ca_certs=None, local_private_key_file=None, local_certificate_file=None, ciphers=None)
        tls.ssl_context = ctx
    return Server(host, port=port, use_ssl=use_ssl, get_info=ALL, tls=tls)

def anonymous_bind(server: Server, timeout: int) -> Tuple[Optional[Connection], Optional[str]]:
    try:
        conn = Connection(server, auto_bind=True, receive_timeout=timeout)  # bind anónimo
        return conn, None
    except LDAPSocketOpenError as e:
        return None, f"LDAP socket error: {e}"
    except LDAPException as e:
        return None, f"LDAP error: {e}"
    except Exception as e:
        return None, str(e)

def fetch_domain_policy(conn: Connection, base_dn: str) -> Dict[str, str]:
    """
    Recupera atributos de política de contraseñas/lockout del objeto de dominio (entrada base).
    """
    attrs = [
        "minPwdLength",
        "pwdHistoryLength",
        "maxPwdAge",
        "minPwdAge",
        "lockoutThreshold",
        "lockoutDuration",
        "lockOutObservationWindow",
        "pwdProperties",
        "msDS-PasswordComplexityEnabled"  # puede no existir
    ]
    ok = conn.search(search_base=base_dn, search_filter="(objectClass=domainDNS)", search_scope=BASE, attributes=attrs)
    policy = {}
    if not ok or len(conn.entries) == 0:
        return policy

    e = conn.entries[0]
    # atributos numéricos y conversiones
    policy["minPwdLength"] = str(get_first_attr(e, "minPwdLength", "N/D"))
    policy["pwdHistoryLength"] = str(get_first_attr(e, "pwdHistoryLength", "N/D"))

    maxPwdAge = get_first_attr(e, "maxPwdAge")
    minPwdAge = get_first_attr(e, "minPwdAge")
    lockoutDuration = get_first_attr(e, "lockoutDuration")
    lockObs = get_first_attr(e, "lockOutObservationWindow")

    if maxPwdAge is not None:
        policy["maxPwdAge"] = filetime_100ns_to_str(int(maxPwdAge))
    else:
        policy["maxPwdAge"] = "N/D"

    if minPwdAge is not None:
        policy["minPwdAge"] = filetime_100ns_to_str(int(minPwdAge))
    else:
        policy["minPwdAge"] = "N/D"

    if lockoutDuration is not None:
        policy["lockoutDuration"] = filetime_100ns_to_str(int(lockoutDuration))
    else:
        policy["lockoutDuration"] = "N/D"

    if lockObs is not None:
        policy["lockoutObservationWindow"] = filetime_100ns_to_str(int(lockObs))
    else:
        policy["lockoutObservationWindow"] = "N/D"

    policy["lockoutThreshold"] = str(get_first_attr(e, "lockoutThreshold", "N/D"))
    policy["pwdProperties"] = str(get_first_attr(e, "pwdProperties", "N/D"))
    policy["msDS-PasswordComplexityEnabled"] = str(get_first_attr(e, "msDS-PasswordComplexityEnabled", "N/D"))

    return policy

def enumerate_users(conn: Connection, base_dn: str, limit: int = 2000, page_size: int = 500) -> List[str]:
    """
    Enumera sAMAccountName de usuarios (excluye equipos) usando paginación.
    """
    users: List[str] = []
    cookie = None
    retrieved = 0
    search_filter = "(&(objectClass=user)(!(objectClass=computer)))"
    attributes = ["sAMAccountName"]

    while True:
        conn.extend.standard.paged_search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=attributes,
            paged_size=page_size,
            generator=False
        )
        # ldap3 guarda resultados en conn.response
        for r in conn.response:
            if r.get("type") != "searchResEntry":
                continue
            attrs = r.get("attributes") or {}
            name = attrs.get("sAMAccountName")
            if name:
                users.append(name)
                retrieved += 1
                if retrieved >= limit:
                    return users
        # Si no hay más páginas, salimos
        # (ldap3 en modo generator=False consume todo; si queremos cortar antes, ya devolvimos por límite)
        break

    return users

# ------------------------- CLI y flujo -------------------------

def main():
    ap = argparse.ArgumentParser(
        prog="ldap_enum.py",
        description="Enumeración LDAP/AD (bind anónimo): política de contraseñas y usuarios (sAMAccountName).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    ap.add_argument("--target", required=True, help="IP/host del LDAP/DC (p. ej., 10.10.11.72)")
    ap.add_argument("--dc", required=True, help="FQDN del DC (p. ej., DC01.tombwatcher.htb)")
    ap.add_argument("--port", type=int, default=389, help="Puerto LDAP (389/636)")
    ap.add_argument("--ssl", action="store_true", help="Usar LDAPS (SSL) — típico en 636")
    ap.add_argument("--insecure", action="store_true", help="No validar certificado TLS (LDAPS)")
    ap.add_argument("--timeout", type=int, default=15, help="Timeout de conexión/búsqueda (s)")
    ap.add_argument("--users-limit", type=int, default=500, help="Máximo de usuarios a mostrar (sAMAccountName)")
    ap.add_argument("--out-users", default=None, help="Guardar usuarios en un archivo (uno por línea)")
    ap.add_argument("--out-policy", default=None, help="Guardar política de contraseñas en JSON")
    args = ap.parse_args()

    # 0) Conectividad rápida
    print(f"[*] Objetivo: {args.target}:{args.port} — SSL={'Sí' if args.ssl else 'No'}")
    if not test_tcp(args.target, args.port, timeout=2.0):
        print("[!] No se pudo abrir TCP al puerto especificado (¿firewall/puerto cerrado?).")
        # seguimos, por si ldap3 aún logra conectar con distinta ruta

    # 1) Derivar dominio/base DN
    domain = fqdn_to_domain(args.dc)
    base_dn = domain_to_base_dn(domain)
    print(f"[*] Dominio: {domain}  |  Base DN: {base_dn}")

    # 2) Crear server y bind anónimo
    server = make_server(args.target, args.port, args.ssl, args.insecure)
    print("[*] Intentando bind anónimo…")
    conn, err = anonymous_bind(server, args.timeout)
    if not conn:
        print(f"[!] Bind anónimo falló: {err}")
        sys.exit(1)
    print("[+] Bind anónimo: OK")

    try:
        # 3) Política de contraseñas
        print("[*] Consultando política de contraseñas en el objeto de dominio…")
        policy = fetch_domain_policy(conn, base_dn)
        if policy:
            print("[+] Política de contraseñas (valores principales):")
            for k in [
                "minPwdLength",
                "pwdHistoryLength",
                "minPwdAge",
                "maxPwdAge",
                "lockoutThreshold",
                "lockoutDuration",
                "lockoutObservationWindow",
                "pwdProperties",
                "msDS-PasswordComplexityEnabled"
            ]:
                v = policy.get(k, "N/D")
                print(f"    - {k}: {v}")
        else:
            print("[!] No se pudo recuperar la política (¿anon bind restringido?).")

        if args.out_policy:
            with open(args.out_policy, "w", encoding="utf-8") as fh:
                json.dump(policy, fh, indent=2, ensure_ascii=False)
            print(f"[+] Política guardada en: {args.out_policy}")

        # 4) Enumeración de usuarios
        print(f"[*] Enumerando usuarios (sAMAccountName), límite {args.users_limit}…")
        users = enumerate_users(conn, base_dn, limit=args.users_limit)
        if users:
            print(f"[+] Usuarios encontrados: {len(users)} (mostrando hasta {args.users_limit})")
            for u in users[:args.users_limit]:
                print(f"    {u}")
            if args.out_users:
                with open(args.out_users, "w", encoding="utf-8") as fh:
                    fh.write("\n".join(users) + "\n")
                print(f"[+] Listado guardado en: {args.out_users}")
        else:
            print("[!] No se listaron usuarios (bind anónimo puede estar limitado, o base DN incorrecto).")

    finally:
        try:
            conn.unbind()
        except Exception:
            pass

if __name__ == "__main__":
    main()
