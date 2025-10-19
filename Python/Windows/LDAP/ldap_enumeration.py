import argparse, sys, traceback
from ldap3 import Tls
import ssl
from typing import Optional, Tuple
from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, BASE
from ldap3.core.exceptions import LDAPSocketOpenError, LDAPException
from datetime import timedelta


def sanitize_cred(s: Optional[str]) -> Optional[str]:
    if s is None:
        return None
    return s.replace("\x00", "").replace("\ufeff", "").strip()

def fqdn_to_domain(fqdn: str) -> str:
    """
    'DC01.tombwatcher.htb' -> 'tombwatcher.htb'
    Si ya es dominio, lo retorna tal cual.
    """
    parts = (fqdn or "").strip().split(".")
    if len(parts) >= 2:
        return ".".join(parts[1:]) if len(parts) > 2 else ".".join(parts)
    return fqdn

def normalize_domain(domain: Optional[str]) -> Optional[str]:
    """
    Normaliza el dominio: 'TOMBWATCHER.HTB' -> 'tombwatcher.htb'
    Devuelve None si no hay dominio usable.
    """
    if not domain:
        return None
    d = domain.strip().strip(".")
    return d.lower() if d else None

def normalize_username(username: str) -> str:
    """
    Recorta y valida username.
    """
    return (username or "").strip()

def build_upn(username: str, domain: Optional[str]) -> Optional[str]:
    """
    user + domain -> user@domain (UPN). Devuelve None si falta info.
    """
    u = normalize_username(username)
    d = normalize_domain(domain)
    if not u or not d:
        return None
    return f"{u}@{d}"

def build_downlevel(username: str, domain: Optional[str]) -> Optional[str]:
    """
    user + domain -> DOMAIN\\user (down-level logon name). Devuelve None si falta info.
    Para NTLM.
    """
    u = normalize_username(username)
    d = normalize_domain(domain)
    if not u or not d:
        return None
    # DOMINIO en mayúsculas es clásico, pero no obligatorio
    return f"{d.split('.')[0].upper()}\\{u}"

def auth_bind_ntlm(server: Server, domain: Optional[str], username: str, password: str, timeout: int = 15) -> Tuple[Optional[Connection], Optional[str]]:
    """
    Bind autenticado con NTLM usando 'DOMAIN\\user'.
    """
    dl = build_downlevel(username, domain)
    if not dl:
        return None, "Faltan dominio/usuario para NTLM (formato DOMAIN\\user)."
    try:
        conn = Connection(server, user=dl, password=password, authentication=NTLM, receive_timeout=timeout, auto_bind=True)
        return conn, None
    except (LDAPSocketOpenError, LDAPException) as e:
        return None, f"NTLM bind falló: {e}"
    except Exception as e:
        return None, f"NTLM error: {e}"

def auth_bind_simple_upn(server: Server, domain: Optional[str], username: str, password: str, timeout: int = 15) -> Tuple[Optional[Connection], Optional[str]]:
    """
    Bind autenticado SIMPLE usando 'user@domain' (UPN).
    """
    upn = build_upn(username, domain)
    if not upn:
        return None, "Faltan dominio/usuario para SIMPLE (formato user@domain)."
    try:
        conn = Connection(server, user=upn, password=password, authentication=SIMPLE, receive_timeout=timeout, auto_bind=True)
        return conn, None
    except (LDAPSocketOpenError, LDAPException) as e:
        return None, f"SIMPLE (UPN) bind falló: {e}"
    except Exception as e:
        return None, f"SIMPLE (UPN) error: {e}"

def smart_auth_bind(server: Server, domain: Optional[str], username: str, password: str, timeout: int = 15) -> Tuple[Optional[Connection], Optional[str], Optional[str]]:
    """
    Intenta autenticación en este orden:
      1) NTLM con DOMAIN\\user
      2) SIMPLE con user@domain
    Devuelve (conn, metodo, error). 'metodo' ∈ {'NTLM','SIMPLE'} o None.
    """
    # 1) NTLM
    conn, err = auth_bind_ntlm(server, domain, username, password, timeout=timeout)
    if conn:
        return conn, "NTLM", None
    last_err = err

    # 2) SIMPLE (UPN)
    conn, err = auth_bind_simple_upn(server, domain, username, password, timeout=timeout)
    if conn:
        return conn, "SIMPLE", None
    if err:
        last_err = f"{last_err} | {err}" if last_err else err

    return None, None, last_err or "No se pudo autenticar con NTLM ni SIMPLE."

def fetch_base_dn_from_rootdse(conn: Connection) -> Optional[str]:
    """
    Intenta obtener el Base DN desde RootDSE:
      - Primero defaultNamingContext (AD).
      - Si no existe, usa namingContexts[0] como fallback (LDAP genérico).
    """
    try:
        if conn.search(
            search_base="",
            search_filter="(objectClass=*)",
            search_scope="BASE",
            attributes=["*", "+"],  # traer todo, incluidos operacionales
        ):
            if not conn.entries:
                return None
            e = conn.entries[0]
            # AD clásico
            try:
                v = e["defaultNamingContext"].value  # puede no existir
                if v:
                    return str(v)
            except Exception:
                pass
            # Fallback genérico
            try:
                ncs = e["namingContexts"].values if "namingContexts" in e else None
                if ncs and len(ncs) > 0:
                    return str(ncs[0])
            except Exception:
                pass
    except Exception:
        pass
    return None

def domain_to_base_dn(domain: str) -> str:
    """'tombwatcher.htb' -> 'DC=tombwatcher,DC=htb'"""
    labels = [p for p in (domain or "").split(".") if p]
    return ",".join(f"DC={l}" for l in labels)

def resolve_base_dn_from_dc_or_rootdse(conn, dc_fqdn: str) -> str:
    """
    Intenta obtener el Base DN desde RootDSE; si falla, lo deriva del --dc.
    """
    root_dn = fetch_base_dn_from_rootdse(conn)
    if root_dn:
        return root_dn
    # Fallback: derivar del FQDN de --dc
    domain = fqdn_to_domain(dc_fqdn)
    return domain_to_base_dn(domain)
def make_server(host: str, port: int, use_ssl: bool, insecure: bool) -> Server:
    tls = None
    if use_ssl:
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        tls = Tls()
        tls.ssl_context = ctx
    return Server(host, port=port, use_ssl=use_ssl, get_info=ALL, tls=tls)

def make_authenticated_connection(
    target: str,
    port: int,
    use_ssl: bool,
    insecure: bool,
    dc_fqdn: str,
    username: str,
    password: str,
    timeout: int = 15,
):
    server = make_server(target, port, use_ssl, insecure)

    # Dominio para NTLM/UPN
    domain = fqdn_to_domain(dc_fqdn)

    conn, metodo, err = smart_auth_bind(server, domain, username, password, timeout=timeout)
    if not conn:
        raise RuntimeError(f"No se pudo autenticar con LDAP: {err}")

    base_dn = resolve_base_dn_from_dc_or_rootdse(conn, dc_fqdn)
    return conn, metodo, base_dn


def anonymous_bind(server: Server, timeout: int):
    try:
        conn = Connection(server, auto_bind=True, receive_timeout=timeout)
        return conn, None
    except LDAPSocketOpenError as e:
        return None, f"LDAP socket error: {e}"
    except LDAPException as e:
        return None, f"LDAP error: {e}"
    except Exception as e:
        return None, str(e)


def ensure_auth_or_anonymous(
    target: str,
    port: int,
    use_ssl: bool,
    insecure: bool,
    dc_fqdn: str,
    username: Optional[str],
    password: Optional[str],
    timeout: int = 15,
):
    """
    Si vienen -u y -p (aunque sean cadenas vacías), intenta autenticado.
    Si no vienen (None), usa bind anónimo.
    Devuelve: (conn, base_dn, auth_mode) con auth_mode ∈ {"NTLM","SIMPLE","ANON"}
    """
    # ¿Nos pasaron flags -u/-p?
    username = sanitize_cred(username)
    password = sanitize_cred(password)


    if username and password:
        conn, metodo, base_dn = make_authenticated_connection(
            target, port, use_ssl, insecure, dc_fqdn, username, password, timeout=timeout
        )
        return conn, base_dn, metodo

    # Anónimo si faltan -u o -p
    server = make_server(target, port, use_ssl, insecure)
    conn, err = anonymous_bind(server, timeout)
    if not conn:
        raise RuntimeError(f"Bind anónimo falló: {err}")

    # Resolver BaseDN (RootDSE o derivado del --dc)
    base_dn = resolve_base_dn_from_dc_or_rootdse(conn, dc_fqdn)
    return conn, base_dn, "ANON"
def duration_to_str(value) -> str:
    """
    Acepta:
      - int/str con unidades de 100ns (normal en AD: negativos)
      - datetime.timedelta (ldap3 puede convertirlo automáticamente)
    Devuelve: 'Xd Yh Zm'
    """
    # timedelta → segundos
    if isinstance(value, timedelta):
        seconds = abs(value.total_seconds())
    else:
        # int/str de 100ns (negativo en AD)
        try:
            val = int(value)
        except Exception:
            return "N/D"
        seconds = abs(val) / 10_000_000.0

    days = int(seconds // 86400)
    seconds -= days * 86400
    hours = int(seconds // 3600)
    seconds -= hours * 3600
    minutes = int(seconds // 60)
    return f"{days}d {hours}h {minutes}m"

def run_connect_and_print(target, dc_fqdn, port=389, use_ssl=False, insecure=False,
                          username: Optional[str]=None, password: Optional[str]=None, timeout=15):
    print(f"[*] Conectando a LDAP {target}:{port}  SSL={'Sí' if use_ssl else 'No'}")
    # 1) Conexión (anónima o autenticada)
    try:
        conn, base_dn, mode = ensure_auth_or_anonymous(
            target=target, port=port, use_ssl=use_ssl, insecure=insecure,
            dc_fqdn=dc_fqdn, username=username, password=password, timeout=timeout
        )
        print(f"[+] Bind {mode}: OK  |  Base DN: {base_dn}")
    except Exception as e:
        print(f"[!] Error de autenticación/LDAP: {e}")
        import traceback as _tb
        _tb.print_exc(limit=2)
        return 1

    try:
        # 2) RootDSE (tolerante a atributos faltantes)
        if conn.search(search_base="", search_filter="(objectClass=*)", search_scope="BASE", attributes=["*", "+"]):
            e = conn.entries[0] if conn.entries else None
            dnc = None; ncs = []
            if e:
                try: dnc = str(e["defaultNamingContext"].value)
                except Exception: pass
                try: ncs = [str(x) for x in (e["namingContexts"].values if "namingContexts" in e else [])]
                except Exception: pass
            if dnc: print(f"[+] RootDSE.defaultNamingContext: {dnc}")
            if ncs: print(f"[+] RootDSE.namingContexts[0]: {ncs[0]}")
        else:
            print("[!] No se pudo leer RootDSE (pero el bind fue OK).")

        # 3) Password Policy (resumen)
        print("\n[=] Password Policy (resumen)")
        policy = fetch_domain_policy(conn, base_dn)
        if policy:
            for k in ("maxPwdAge","minPwdAge","lockoutDuration","lockOutObservationWindow"):
                v = g(k, None)
                policy[k] = duration_to_str(v) if v is not None else "N/D"

        else:
            print(" - No accesible con este bind (o base DN incorrecto).")

        # 4) Usuarios (muestra)
        print("\n[=] Usuarios (muestra)")
        users = enumerate_users(conn, base_dn, limit=25)
        if users:
            for u in users:
                print(f" - {u}")
            print(f"Total mostrados: {len(users)} (solo muestra)")
        else:
            print(" - No listados (bind/ACL restringido o filtro/base DN incorrectos).")

        return 0
    except Exception as ex:
        print(f"[!] Error en enumeración: {ex}")
        import traceback as _tb
        _tb.print_exc(limit=2)
        return 1
    finally:
        try: conn.unbind()
        except Exception: pass

def filetime_100ns_to_str(neg_100ns: int) -> str:
    val = abs(int(neg_100ns))
    seconds = val / 10_000_000
    d = int(seconds // 86400); seconds -= d * 86400
    h = int(seconds // 3600);  seconds -= h * 3600
    m = int(seconds // 60)
    return f"{d}d {h}h {m}m"

def fetch_domain_policy(conn: Connection, base_dn: str) -> dict:
    attrs = [
        "minPwdLength", "pwdHistoryLength", "maxPwdAge", "minPwdAge",
        "lockoutThreshold", "lockoutDuration", "lockOutObservationWindow",
        "pwdProperties", "msDS-PasswordComplexityEnabled"
    ]
    ok = conn.search(search_base=base_dn, search_filter="(objectClass=domainDNS)",
                     search_scope=BASE, attributes=attrs)
    if not ok or not conn.entries:
        return {}
    e = conn.entries[0]
    def g(a, default="N/D"):
        try:
            v = e[a].value
            return v if v is not None else default
        except Exception:
            return default
    policy = {
        "minPwdLength": str(g("minPwdLength")),
        "pwdHistoryLength": str(g("pwdHistoryLength")),
        "lockoutThreshold": str(g("lockoutThreshold")),
        "pwdProperties": str(g("pwdProperties")),
        "msDS-PasswordComplexityEnabled": str(g("msDS-PasswordComplexityEnabled")),
    }
    for k in ("maxPwdAge","minPwdAge","lockoutDuration","lockOutObservationWindow"):
        v = g(k, None)
        policy[k] = filetime_100ns_to_str(int(v)) if v is not None else "N/D"
    return policy

def enumerate_users(conn: Connection, base_dn: str, limit: int = 50) -> list[str]:
    users = []
    ok = conn.search(search_base=base_dn,
                     search_filter="(&(objectClass=user)(!(objectClass=computer)))",
                     search_scope=SUBTREE,
                     attributes=["sAMAccountName"])
    if not ok:
        return users
    for r in conn.response:
        if r.get("type") != "searchResEntry":
            continue
        name = (r.get("attributes") or {}).get("sAMAccountName")
        if name:
            users.append(name)
            if len(users) >= limit:
                break
    return users

    
def main():
    ap = argparse.ArgumentParser(description="LDAP enum (anónimo o autenticado con -u/-p).")
    ap.add_argument("--target", required=True, help="IP/host LDAP")
    ap.add_argument("--dc", required=True, help="FQDN del DC (p.ej., DC01.tombwatcher.htb)")
    ap.add_argument("--port", type=int, default=389, help="Puerto LDAP (389/636)")
    ap.add_argument("--ssl", action="store_true", help="LDAPS (SSL)")
    ap.add_argument("--insecure", action="store_true", help="No validar TLS (LDAPS)")
    ap.add_argument("-u", "--username", default=None, help="Usuario (opcional)")
    ap.add_argument("-p", "--password", default=None, help="Password (opcional)")
    ap.add_argument("--timeout", type=int, default=15, help="Timeout (s)")
    args = ap.parse_args()

    sys.exit(
        run_connect_and_print(
            target=args.target, dc_fqdn=args.dc, port=args.port,
            use_ssl=args.ssl, insecure=args.insecure,
            username=args.username, password=args.password,
            timeout=args.timeout
        )
    )

if __name__ == "__main__":
    main()
