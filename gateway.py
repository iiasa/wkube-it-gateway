import socket
import threading
import re
import base64
from http import HTTPStatus

SESSION_COOKIE_NAME = "auth_token"

PORT = 2222
TOKEN = "letmein"
SOCKET_DIR = "/tmp"
SOCKET_SUFFIX = ".sock"
DOMAIN = ".wkube.iiasa.ac.at"

def extract_subdomain(host_header: bytes) -> str:
    try:
        host = host_header.decode().split(":")[0]  # remove port
        if host.endswith(DOMAIN):
            subdomain = host.replace(DOMAIN, "")
            return subdomain
    except Exception as e:
        print(f"Failed to parse subdomain: {e}")
    return None

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
            val = part.strip().split("=")[1]
            if val == TOKEN:
                return True
    return False

def is_valid_basic_auth(headers):
    auth = headers.get(b'authorization')
    if not auth or not auth.startswith(b"Basic "):
        return False
    encoded = auth.split(b" ", 1)[1]
    try:
        decoded = base64.b64decode(encoded).decode()
        username, password = decoded.split(":", 1)
        return password == TOKEN
    except Exception:
        return False

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

    # Check for cookie or basic auth
    if not is_valid_cookie(headers) and not is_valid_basic_auth(headers):
        client.send(
            b"HTTP/1.1 401 Unauthorized\r\n"
            b"WWW-Authenticate: Basic realm=\"Access Required\"\r\n"
            b"Content-Type: text/plain\r\n\r\n"
            b"Unauthorized: Valid token required\n"
        )
        client.close()
        return

    # If basic auth was valid but no cookie, issue a Set-Cookie header
    set_cookie = b""
    if is_valid_basic_auth(headers) and not is_valid_cookie(headers):
        set_cookie = (
            f"Set-Cookie: {SESSION_COOKIE_NAME}={TOKEN}; Path=/; HttpOnly\r\n".encode()
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
def handle_tcp(client):
    try:
        client.send(b"Token: ")
        token = client.recv(1024).strip()
        if token.decode() != TOKEN:
            client.send(b"Access denied\n")
            client.close()
            return

        client.send(b"Access granted. Connecting...\n")

        # Get SNI-style domain (hacky): read peeked Host header manually
        peek = client.recv(256, socket.MSG_PEEK)
        match = re.search(rb'Host: ([a-zA-Z0-9\-]+)\.wkube\.iiasa\.ac\.at', peek)
        if not match:
            client.send(b"No valid Host found for backend\n")
            client.close()
            return

        subdomain = match.group(1).decode()

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
        print(f"[TCP] Error: {e}")
        client.close()

def handle_client(client):
    try:
        peek = client.recv(16, socket.MSG_PEEK)
        if peek.startswith(b"GET") or peek.startswith(b"POST") or b"HTTP" in peek:
            handle_http(client)
        else:
            handle_tcp(client)
    except Exception as e:
        print(f"Connection error: {e}")
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
