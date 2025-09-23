import socket
import threading
import re
import base64
import requests
import jwt
import ssl
from jwt.algorithms import RSAAlgorithm
from http import HTTPStatus

SESSION_COOKIE_NAME = "auth_token"

PORT = 2222
TOKEN = "letmein"
SOCKET_DIR = "/tmp"
SOCKET_SUFFIX = ".sock"
DOMAIN = ".wkube.iiasa.ac.at"

JWKS_URL = "https://accelerator-api.iiasa.ac.at/.well-known/jwks.json"
EXPECTED_KID = "rsa-key-2024-07"
_jwks_cache = {}


context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile="/path/to/cert.pem", keyfile="/path/to/key.pem")
context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
context.set_ciphers("ECDHE+AESGCM")


def connect_unix_socket(subdomain):
    path = f"{SOCKET_DIR}/{subdomain}{SOCKET_SUFFIX}"
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(path)
    return s


def parse_headers(data):
    headers = {}
    lines = data.split(b"\r\n")
    for line in lines[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            headers[k.strip().lower()] = v.strip()
    return headers

def extract_subdomain(host: bytes) -> str:
    host = host.decode().split(":")[0]
    if host.endswith(DOMAIN):
        return host.replace(DOMAIN, "")
    return None



def handle_http(client):
    data = client.recv(4096)
    if not data:
        client.close()
        return

    headers = parse_headers(data)
    host_header = headers.get(b"host")
    if not host_header:
        client.send(b"HTTP/1.1 400 Bad Request\r\n\r\nMissing Host header")
        client.close()
        return

    subdomain = extract_subdomain(host_header)
    if not subdomain:
        client.send(b"HTTP/1.1 400 Bad Request\r\n\r\nInvalid Host")
        client.close()
        return

    # --- authentication removed ---
    # Just forward the request to backend

    try:
        backend = connect_unix_socket(subdomain)
        backend.sendall(data)

        response_data = b""
        while True:
            chunk = backend.recv(4096)
            if not chunk:
                break
            response_data += chunk

        backend.close()
        client.sendall(response_data)

    except Exception as e:
        client.send(b"HTTP/1.1 502 Bad Gateway\r\n\r\nBackend error\n")
        print(f"[HTTP] Proxy error: {e}")
    finally:
        client.close()


def handle_tls(client):
    try:
        tls_client = context.wrap_socket(client, server_side=True)
        handle_http(tls_client)  # same logic as before, just using decrypted stream
    except ssl.SSLError as e:
        print(f"[TLS] SSL error: {e}")
        client.close()


def handle_ssh(client):
    try:
        # --- token prompt removed ---
        client.send(b"Subdomain: ")
        subdomain = client.recv(1024).strip().decode()

        if not re.match(r"^[a-zA-Z0-9\\-]+$", subdomain):
            client.send(b"Invalid subdomain format\n")
            client.close()
            return

        client.send(b"Connecting...\n")
        backend = connect_unix_socket(subdomain)

        def forward(src, dst):
            try:
                while True:
                    data = src.recv(4096)
                    if not data:
                        break
                    dst.sendall(data)
            finally:
                src.close()
                dst.close()

        threading.Thread(target=forward, args=(client, backend)).start()
        threading.Thread(target=forward, args=(backend, client)).start()

    except Exception as e:
        print(f"[SSH] Error: {e}")
        client.close()
        
def handle_client(client):
    try:
        peek = client.recv(8, socket.MSG_PEEK)

        # HTTP (for redirect)
        if peek.startswith(b"GET") or peek.startswith(b"POST") or b"HTTP" in peek:
            data = client.recv(4096)  # consume the request
            headers = parse_headers(data)
            host = headers.get(b"host")

            if not host:
                client.send(
                    b"HTTP/1.1 400 Bad Request\r\n\r\nMissing Host header"
                )
                client.close()
                return
            
            location = f"https://{host.decode()}/"

            client.send(
                b"HTTP/1.1 301 Moved Permanently\r\n"
                + f"Location: {location}\r\n".encode()
                + b"Content-Length: 0\r\n\r\n"
            )
            client.close()
            return

        # TLS detection: first byte is 0x16 (Handshake), next 2 bytes are version
        if len(peek) >= 3 and peek[0] == 0x16 and peek[1] == 0x03:
            handle_tls(client)
            return

        # SSH detection: starts with ASCII "SSH-"
        if peek.startswith(b'SSH-'):
            handle_ssh(client)
            return

        # Unknown protocol
        client.send(b"Unrecognized protocol. Only SSH and TLS are supported.\n")
        client.close()

    except Exception as e:
        print(f"[Error] Connection handling failed: {e}")
        client.close()

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", PORT))
    s.listen(50)
    print(f"Gateway listening on port {PORT}...")

    while True:
        client, _ = s.accept()
        threading.Thread(target=handle_client, args=(client,)).start()

if __name__ == "__main__":
    main()
