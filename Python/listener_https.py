import http.server
import ssl

def run_https_server():
    server_address = ('0.0.0.0', 443)  # Cambia el puerto si es necesario
    handler = http.server.SimpleHTTPRequestHandler
    httpd = http.server.HTTPServer(server_address, handler)

    # Envolver el socket con SSL
    httpd.socket = ssl.wrap_socket(
        httpd.socket,
        server_side=True,
        certfile='localhost.pem',
        ssl_version=ssl.PROTOCOL_TLSv1_2
    )

    print("[+] HTTPS Server running on https://0.0.0.0:443")
    httpd.serve_forever()

if __name__ == "__main__":
    run_https_server()
