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


def extract_jwt_from_auth(headers):
    auth = headers.get(b'authorization')
    if not auth or not auth.startswith(b"Bearer "):
        return None
    token = auth.split(b" ", 1)[1].decode()
    if verify_jwt(token):
        return token
    return None

def get_public_key(kid):
    global _jwks_cache
    if kid in _jwks_cache:
        return _jwks_cache[kid]

    try:
        resp = requests.get(JWKS_URL)
        resp.raise_for_status()
        jwks = resp.json()
        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                pubkey = RSAAlgorithm.from_jwk(key)
                _jwks_cache[kid] = pubkey
                return pubkey
    except Exception as e:
        print(f"Failed to fetch JWKS: {e}")
    return None


def verify_jwt(token):
    try:
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")
        if kid != EXPECTED_KID:
            print(f"Unexpected key ID: {kid}")
            return False
        pubkey = get_public_key(kid)
        if not pubkey:
            return False
        token_details = jwt.decode(token, pubkey, algorithms=["RS256"], audience=None)  # Adjust audience if needed
        # TODO verify further token details. Before that make a backend and frontend to get token for this just as device token
        return True
    except Exception as e:
        print(f"JWT verification failed: {e}")
        return False

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

def is_valid_cookie(headers):
    cookies = headers.get(b'cookie')
    if not cookies:
        return False
    cookie_str = cookies.decode()
    for part in cookie_str.split(";"):
        if part.strip().startswith(f"{SESSION_COOKIE_NAME}="):
            token = part.strip().split("=", 1)[1]
            return verify_jwt(token)
    return False

def is_valid_basic_auth(headers):
    auth = headers.get(b'authorization')
    if not auth or not auth.startswith(b"Bearer "):
        return False
    token = auth.split(b" ", 1)[1].decode()
    return verify_jwt(token)

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

    jwt_from_cookie = is_valid_cookie(headers)
    jwt_from_auth = extract_jwt_from_auth(headers)

    # If neither JWT source is valid, reject the request
    if not jwt_from_cookie and not jwt_from_auth:
        client.send(
            b"HTTP/1.1 401 Unauthorized\r\n"
            b"WWW-Authenticate: Bearer realm=\"Access Required\"\r\n"
            b"Content-Type: text/plain\r\n\r\n"
            b"Unauthorized: Valid token required\n"
        )
        client.close()
        return

    # If valid via Authorization header but not cookie, set cookie
    set_cookie = b""
    if jwt_from_auth and not jwt_from_cookie:
        set_cookie = (
            f"Set-Cookie: {SESSION_COOKIE_NAME}={jwt_from_auth}; Path=/; HttpOnly\r\n".encode()
        )

    # Forward to backend
    try:
        backend = connect_unix_socket(subdomain)
        backend.sendall(data)

        # Read response from backend
        response_data = b""
        while True:
            chunk = backend.recv(4096)
            if not chunk:
                break
            response_data += chunk

        backend.close()

        # Inject Set-Cookie header into response (optional)
        if set_cookie:
            parts = response_data.split(b"\r\n\r\n", 1)
            if len(parts) == 2:
                headers, body = parts
                headers += b"\r\n" + set_cookie
                response_data = headers + b"\r\n\r\n" + body

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
        # Step 1: Authenticate
        client.send(b"Token: ")
        token = client.recv(1024).strip()
        if not verify_jwt(token):
            client.send(b"Access denied\n")
            client.close()
            return

        # Step 2: Ask for subdomain
        client.send(b"Subdomain: ")
        subdomain = client.recv(1024).strip().decode()

        # Validate subdomain format (alphanumeric and hyphens)
        if not re.match(r"^[a-zA-Z0-9\-]+$", subdomain):
            client.send(b"Invalid subdomain format\n")
            client.close()
            return

        client.send(b"Access granted. Connecting...\n")

        backend = connect_unix_socket(subdomain)

        # Step 3: Proxy data between client and backend
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
