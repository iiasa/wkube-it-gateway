// Full Go conversion of the Python gateway with complete socket forwarding logic
package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	Port              = ":2222"
	SessionCookieName = "auth_token"
	SocketDir         = "/tmp"
	SocketSuffix      = ".sock"
	DomainSuffix      = ".wkube.iiasa.ac.at"
	JWKSUrl           = "https://accelerator-api.iiasa.ac.at/.well-known/jwks.json"
	ExpectedKid       = "rsa-key-2024-07"
	CertPath          = "/path/to/cert.pem"
	KeyPath           = "/path/to/key.pem"
)

var jwksCache sync.Map

func getPublicKey(kid string) (any, error) {
	if val, ok := jwksCache.Load(kid); ok {
		return val, nil
	}
	resp, err := http.Get(JWKSUrl)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var jwks struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, err
	}
	for _, raw := range jwks.Keys {
		var keyMap map[string]interface{}
		json.Unmarshal(raw, &keyMap)
		if keyMap["kid"] == ExpectedKid {
			pubkey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(raw))
			if err == nil {
				jwksCache.Store(ExpectedKid, pubkey)
				return pubkey, nil
			}
		}
	}
	return nil, fmt.Errorf("no matching key")
}

func verifyJWT(tokenStr string) bool {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		header := token.Header
		if kid, ok := header["kid"].(string); ok && kid == ExpectedKid {
			return getPublicKey(kid)
		}
		return nil, fmt.Errorf("invalid kid")
	})
	return err == nil && token.Valid
}

func extractSubdomain(host string) string {
	host = strings.Split(host, ":")[0]
	if strings.HasSuffix(host, DomainSuffix) {
		return strings.TrimSuffix(host, DomainSuffix)
	}
	return ""
}

func parseHeaders(data []byte) map[string]string {
	headers := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			headers[strings.ToLower(strings.TrimSpace(parts[0]))] = strings.TrimSpace(parts[1])
		}
	}
	return headers
}

func forward(src, dst net.Conn) {
	defer src.Close()
	defer dst.Close()
	io.Copy(dst, src)
}

func connectUnixSocket(subdomain string) (net.Conn, error) {
	path := filepath.Join(SocketDir, subdomain+SocketSuffix)
	return net.Dial("unix", path)
}

func handleHTTP(conn net.Conn) {
	defer conn.Close()
	data := make([]byte, 4096)
	n, _ := conn.Read(data)
	headers := parseHeaders(data[:n])
	host := headers["host"]
	if host == "" {
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\nMissing Host header"))
		return
	}
	subdomain := extractSubdomain(host)
	if subdomain == "" {
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\nInvalid Host"))
		return
	}

	jwtToken := ""
	if auth := headers["authorization"]; strings.HasPrefix(auth, "Bearer ") {
		token := strings.TrimPrefix(auth, "Bearer ")
		if verifyJWT(token) {
			jwtToken = token
		}
	}
	if jwtToken == "" && headers["cookie"] != "" {
		for _, part := range strings.Split(headers["cookie"], ";") {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, SessionCookieName+"=") {
				token := strings.TrimPrefix(part, SessionCookieName+"=")
				if verifyJWT(token) {
					jwtToken = token
				}
			}
		}
	}

	if jwtToken == "" {
		conn.Write([]byte("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer realm=\"Access Required\"\r\n\r\nUnauthorized"))
		return
	}

	backend, err := connectUnixSocket(subdomain)
	if err != nil {
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\nBackend connection failed"))
		return
	}
	backend.Write(data[:n])
	go forward(backend, conn)
	forward(conn, backend)
}

func handleTLS(conn net.Conn) {
	cert, err := tls.LoadX509KeyPair(CertPath, KeyPath)
	if err != nil {
		log.Println("[TLS] Cert error:", err)
		conn.Close()
		return
	}
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
	}
	tlsConn := tls.Server(conn, config)
	if err := tlsConn.Handshake(); err != nil {
		log.Println("[TLS] Handshake error:", err)
		tlsConn.Close()
		return
	}
	handleHTTP(tlsConn)
}

func handlePlainHTTP(conn net.Conn) {
	data := make([]byte, 4096)
	n, _ := conn.Read(data)
	headers := parseHeaders(data[:n])
	host := headers["host"]
	if host == "" {
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\nMissing Host header"))
		conn.Close()
		return
	}
	location := fmt.Sprintf("https://%s/", host)
	conn.Write([]byte("HTTP/1.1 301 Moved Permanently\r\nLocation: " + location + "\r\nContent-Length: 0\r\n\r\n"))
	conn.Close()
}

func handleSSH(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	conn.Write([]byte("Token: "))
	token, _ := reader.ReadString('\n')
	token = strings.TrimSpace(token)
	if !verifyJWT(token) {
		conn.Write([]byte("Access denied\n"))
		return
	}
	conn.Write([]byte("Subdomain: "))
	subdomain, _ := reader.ReadString('\n')
	subdomain = strings.TrimSpace(subdomain)
	if matched, _ := regexp.MatchString(`^[a-zA-Z0-9\-]+$`, subdomain); !matched {
		conn.Write([]byte("Invalid subdomain format\n"))
		return
	}
	conn.Write([]byte("Access granted. Connecting...\n"))
	backend, err := connectUnixSocket(subdomain)
	if err != nil {
		conn.Write([]byte("Backend connection failed\n"))
		return
	}
	go forward(conn, backend)
	forward(backend, conn)
}

func handleConnection(conn net.Conn) {
	peek := make([]byte, 8)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(peek); err != nil {
		conn.Close()
		return
	}
	conn.SetReadDeadline(time.Time{})

	if bytes.HasPrefix(peek, []byte("GET")) || bytes.Contains(peek, []byte("HTTP")) {
		handlePlainHTTP(conn)
		return
	}
	if peek[0] == 0x16 && peek[1] == 0x03 {
		handleTLS(conn)
		return
	}
	if bytes.HasPrefix(peek, []byte("SSH-")) {
		handleSSH(conn)
		return
	}
	conn.Write([]byte("Unrecognized protocol. Only SSH and TLS are supported.\n"))
	conn.Close()
}

func main() {
	ln, err := net.Listen("tcp", Port)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Gateway listening on", Port)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("[Accept Error]", err)
			continue
		}
		go handleConnection(conn)
	}
}
