// Full Go conversion of the Python gateway with complete socket forwarding logic (hardened)
package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	Port              = ":6473"
	SessionCookieName = "auth_token"
	SocketDir         = "/tmp"
	SocketSuffix      = ".sock"
	DomainSuffix      = ".wkube.iiasa.ac.at"
	JWKSUrl           = "https://accelerator-api.iiasa.ac.at/.well-known/jwks.json"
	ExpectedKid       = "rsa-key-2024-07"
	CertPath          = "/etc/ssl/certs/tls.crt"
	KeyPath           = "/etc/ssl/certs/tls.key"
)

var (
	// Reused TLS config, loaded once.
	tlsConfig *tls.Config

	// Precompiled regex for subdomain sanity checks (used by SSH).
	subdomainRe = regexp.MustCompile(`^[a-zA-Z0-9\-]+$`)

	// A list of common HTTP methods for quick plaintext detection.
	httpMethods = [][]byte{
		[]byte("GET "), []byte("POST "), []byte("PUT "),
		[]byte("DELETE "), []byte("HEAD "), []byte("OPTIONS "),
		[]byte("PATCH "), []byte("TRACE "), []byte("CONNECT "),
	}
)

// bufferedConn lets us Peek without losing bytes, then present a net.Conn whose Read drains from the bufio.Reader first.
type bufferedConn struct {
	net.Conn
	br *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.br.Read(p) }

func initTLSConfig() error {
	cert, err := tls.LoadX509KeyPair(CertPath, KeyPath)
	if err != nil {
		return fmt.Errorf("load keypair: %w", err)
	}
	tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		// Keep a sensible, modern baseline; let Go negotiate ECDHE suites.
		// Explicit list optional; these are fine for RSA certs:
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
	}
	return nil
}

func extractSubdomain(host string) string {
	host = strings.Split(host, ":")[0]
	if strings.HasSuffix(host, DomainSuffix) {
		return strings.TrimSuffix(host, DomainSuffix)
	}
	return ""
}

func connectUnixSocket(subdomain string) (net.Conn, error) {
	path := filepath.Join(SocketDir, subdomain+SocketSuffix)
	return net.Dial("unix", path)
}

// bidirectionalCopy wires src<->dst until both directions finish.
// It does not close the passed conns itself; the caller owns closing.
func bidirectionalCopy(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	// Direction a -> b
	go func() {
		defer wg.Done()
		_, _ = io.Copy(b, a)
		// Try half-close if supported to signal EOF without tearing down both ways.
		type closeWriter interface{ CloseWrite() error }
		if cw, ok := b.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
	}()

	// Direction b -> a
	go func() {
		defer wg.Done()
		_, _ = io.Copy(a, b)
		if cw, ok := a.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
	}()

	wg.Wait()
}

// handleHTTP terminates TLS (if any) before calling this, and then proxies HTTP to the backend Unix socket.
func handleHTTP(conn net.Conn) {
	defer conn.Close()

	// Parse the HTTP request robustly.
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		log.Printf("[HTTP] read request error: %v", err)
		_, _ = io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
		return
	}

	host := req.Host
	if host == "" {
		log.Printf("[HTTP] missing Host header")
		_, _ = io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\n\r\nMissing Host header")
		return
	}

	subdomain := extractSubdomain(host)
	if subdomain == "" {
		log.Printf("[HTTP] invalid host %q", host)
		_, _ = io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\n\r\nInvalid Host")
		return
	}

	// --- Auth/JWT checks intentionally omitted (explicitly removed) ---

	backend, err := connectUnixSocket(subdomain)
	if err != nil {
		log.Printf("[HTTP] backend connect failed: subdomain=%s err=%v", subdomain, err)
		_, _ = io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\n\r\nBackend connection failed")
		return
	}
	defer backend.Close()

	// Ensure the Host header is preserved.
	req.URL.Scheme = ""        // proxying raw HTTP/1.1
	req.URL.Host = ""          // must be empty for RequestURI form
	req.RequestURI = req.URL.RequestURI()

	// Forward the parsed request to the backend.
	if err := req.Write(backend); err != nil {
		log.Printf("[HTTP] write to backend failed: subdomain=%s err=%v", subdomain, err)
		return
	}

	// After initial request/headers/body, tunnel both ways (for upgrades like WebSocket).
	bidirectionalCopy(conn, backend)
}

// handleTLS wraps the connection with TLS using the global tlsConfig, then delegates to handleHTTP.
func handleTLS(conn net.Conn) {
	if tlsConfig == nil {
		log.Println("[TLS] tlsConfig is nil (not initialized)")
		_ = conn.Close()
		return
	}
	tlsConn := tls.Server(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("[TLS] handshake error: %v", err)
		_ = tlsConn.Close()
		return
	}
	handleHTTP(tlsConn)
}

// handlePlainHTTP reads a plaintext HTTP request and 301-redirects to HTTPS while preserving the path/query.
func handlePlainHTTP(conn net.Conn) {
	defer conn.Close()

	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		log.Printf("[HTTP-PLAIN] read request error: %v", err)
		_, _ = io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
		return
	}

	if req.Host == "" {
		_, _ = io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\n\r\nMissing Host header")
		return
	}

	location := "https://" + req.Host + req.URL.RequestURI()
	resp := fmt.Sprintf("HTTP/1.1 301 Moved Permanently\r\nLocation: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", location)
	if _, err := io.WriteString(conn, resp); err != nil {
		log.Printf("[HTTP-PLAIN] failed to write redirect: %v", err)
	}
}

// handleSSH provides a tiny prompt, validates subdomain, and then wires stdin/stdout to the Unix socket.
func handleSSH(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	_, _ = conn.Write([]byte("Subdomain: "))
	subdomain, err := reader.ReadString('\n')
	if err != nil {
		_, _ = conn.Write([]byte("Read error\n"))
		return
	}
	subdomain = strings.TrimSpace(subdomain)
	if !subdomainRe.MatchString(subdomain) {
		_, _ = conn.Write([]byte("Invalid subdomain format\n"))
		return
	}

	_, _ = conn.Write([]byte("Connecting...\n"))
	backend, err := connectUnixSocket(subdomain)
	if err != nil {
		log.Printf("[SSH] backend connect failed: subdomain=%s err=%v", subdomain, err)
		_, _ = conn.Write([]byte("Backend connection failed\n"))
		return
	}
	defer backend.Close()

	// Wire up both directions until EOF.
	bidirectionalCopy(conn, backend)
}

func looksLikeHTTP(peek []byte) bool {
	for _, m := range httpMethods {
		if bytes.HasPrefix(peek, m) {
			return true
		}
	}
	// Fallback heuristic.
	return bytes.Contains(peek, []byte("HTTP/"))
}

func handleConnection(conn net.Conn) {
	// Short classification timeout to avoid slowloris on first read.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	br := bufio.NewReader(conn)
	peek, err := br.Peek(8)
	if err != nil {
		_ = conn.Close()
		return
	}
	_ = conn.SetReadDeadline(time.Time{}) // clear deadline

	// Wrap so subsequent reads drain from br (including peeked bytes).
	bconn := &bufferedConn{Conn: conn, br: br}

	switch {
	case looksLikeHTTP(peek):
		log.Printf("[CONN] plaintext HTTP from %s", conn.RemoteAddr())
		handlePlainHTTP(bconn)
		return

	// TLS record header: 0x16 (Handshake), 0x03 (TLS major), next is minor {0x01..0x04}
	case len(peek) >= 3 && peek[0] == 0x16 && peek[1] == 0x03:
		log.Printf("[CONN] TLS from %s", conn.RemoteAddr())
		handleTLS(bconn)
		return

	case bytes.HasPrefix(peek, []byte("SSH-")):
		log.Printf("[CONN] SSH from %s", conn.RemoteAddr())
		handleSSH(bconn)
		return

	default:
		_, _ = bconn.Write([]byte("Unrecognized protocol. Only SSH and TLS are supported.\n"))
		_ = bconn.Close()
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	if err := initTLSConfig(); err != nil {
		log.Fatalf("[BOOT] TLS init failed: %v", err)
	}

	ln, err := net.Listen("tcp", Port)
	if err != nil {
		log.Fatalf("[BOOT] listen error: %v", err)
	}
	log.Println("[BOOT] Gateway listening on", Port)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[ACCEPT] error: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}
