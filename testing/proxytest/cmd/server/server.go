package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gofrs/uuid/v5"

	"github.com/elastic/elastic-agent-libs/testing/certutil"
	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
)

var defaultTLS = struct {
	capriv crypto.PrivateKey
	cacert *x509.Certificate
	tls    *tls.Config
}{}

var defaultTr = http.DefaultTransport

func main() {
	ctx := context.Background()

	logger := slog.New(
		slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
				if a.Key == slog.TimeKey && len(groups) == 0 {

					t := a.Value.Time()
					a.Value = slog.StringValue(t.Format(time.RFC3339Nano))

				}
				return a
			},
		}),
	)

	caPriv, caCert, tlsconf, err := loadTLSConfig()
	if err != nil {
		panic(err)
	}

	defaultTLS.capriv = caPriv
	defaultTLS.cacert = caCert
	defaultTLS.tls = tlsconf

	addr := "localhost:4242"
	var listenCfg net.ListenConfig
	ln, err := listenCfg.Listen(ctx, "tcp", addr)
	if err != nil {
		panic(err)
	}
	defer func() {
		err := ln.Close()
		if err != nil {
			logger.Error("server.Run: error while closing listener.", "error", err)
		}
	}()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := uuid.Must(uuid.NewV4()).String()
		logger := logger.With("req_id", reqID)
		if r.Method == http.MethodConnect {
			handleHTTPS(w, r, logger)
			return
		}

		_, err = w.Write([]byte("[%s] Hello World"))
		if err != nil {
			logger.Error("error writing response", "err", err)
		}
	})

	srv := httptest.NewUnstartedServer(handler)
	srv.Listener = ln
	srv.TLS = defaultTLS.tls

	srv.StartTLS()
	logger.Info("server: listening on " + addr)
	<-ctx.Done()
}

func loadTLSConfig() (crypto.PrivateKey, *x509.Certificate, *tls.Config, error) {
	// TODO: fix me
	wd := "/home/ainsoph/devel/github.com/elastic/elastic-agent/testing/proxytest/cmd/certs"
	tlsToLoad := tlscommon.ServerConfig{
		CAs: []string{
			filepath.Join(wd, "client-ca.pem"),
			"/etc/ssl/certs/ca-certificates.crt",
		},
		Certificate: tlscommon.CertificateConfig{
			Certificate: filepath.Join(wd, "proxy-localhost.pem"),
			Key:         filepath.Join(wd, "proxy-localhost_key.pem"),
		},
	}
	commonTLSCfg, err := tlscommon.LoadTLSServerConfig(&tlsToLoad)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("could not load TLS certificates: %v", err)
	}

	caPriv, caCert := certutil.LoadCA(wd+"/proxy-ca.pem", wd+"/proxy-ca_key.pem")
	defaultTLS = struct {
		capriv crypto.PrivateKey
		cacert *x509.Certificate
		tls    *tls.Config
	}{
		capriv: caPriv,
		cacert: caCert,
		tls: &tls.Config{
			ClientCAs:    commonTLSCfg.ClientCAs,
			RootCAs:      commonTLSCfg.ClientCAs,
			Certificates: commonTLSCfg.Certificates,
			ClientAuth:   tls.RequireAndVerifyClientCert,
		},
	}

	return caPriv, caCert, &tls.Config{
		ClientCAs:    commonTLSCfg.ClientCAs,
		RootCAs:      commonTLSCfg.ClientCAs,
		Certificates: commonTLSCfg.Certificates,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}, nil
}

func handleHTTPS(w http.ResponseWriter, r *http.Request, logger *slog.Logger) {
	logger.Info("handling CONNECT")

	clientCon, err := hijack(w)
	if err != nil {
		http500Error(clientCon, "cannot handle request", err, logger)
		return
	}
	defer clientCon.Close()

	// Hijack successful, w is now useless, let's make sure it isn't used by
	// mistake ;)
	w = nil
	logger.Info("hijacked request")

	// ==================== CONNECT accepted, let the client know
	_, err = clientCon.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	if err != nil {
		http500Error(clientCon, "failed to send 200-OK after CONNECT", err, logger)
		return
	}

	// ==================== TLS handshake
	// client will proceed to perform the TLS handshake with the "target",
	// which we're impersonating.

	// generate a TLS certificate matching the target's host
	cert, err := newTLSCert(r.URL)
	if err != nil {
		http500Error(clientCon, "failed generating certificate", err, logger)
		return
	}

	tlscfg := defaultTLS.tls.Clone()
	tlscfg.Certificates = []tls.Certificate{*cert}
	clientTLSConn := tls.Server(clientCon, tlscfg)
	defer clientTLSConn.Close()
	err = clientTLSConn.Handshake()
	if err != nil {
		http500Error(clientCon, "failed TLS handshake with client", err, logger)
		return
	}

	clientTLSReader := bufio.NewReader(clientTLSConn)

	notEOF := func(r *bufio.Reader) bool {
		_, err = r.Peek(1)
		return !errors.Is(err, io.EOF)
	}

	// ==================== Handle the actual request
	for notEOF(clientTLSReader) {

		// read request from the client sent after the 1s CONNECT request
		req, err := http.ReadRequest(clientTLSReader)
		if err != nil {
			http500Error(clientTLSConn, "failed reading client request", err, logger)
			return
		}

		// carry over the original remote addr
		req.RemoteAddr = r.RemoteAddr

		// TODO: add what ever request manipulation is needed
		host := r.Host
		if strings.Contains(host, "elasticc.co") {
			host = strings.Replace(host, "elasticc.co", "elastic.co", 1)
			logger.Info("replaced host", "old", r.Host, "new", host)
		}

		// copy host, the read request does not have it
		req.URL, err = url.Parse("https://" + host + req.URL.String())
		if err != nil {
			http500Error(clientTLSConn, "failed reading request URL from client", err, logger)
			return
		}

		// when modifying the request, RequestURI isn't updated and it isn't
		// needed anyway, so remove it.
		req.RequestURI = ""
		cleanUpHeaders(r.Header)

		// perform the actual request to the target
		resp, err := defaultTr.RoundTrip(req)
		if err != nil {
			http500Error(clientTLSConn, "failed performing request to target", err, logger)
			return
		}

		// Send response from target to client
		// 1st - the status code
		_, err = clientTLSConn.Write([]byte("HTTP/1.1 " + resp.Status + "\r\n"))
		if err != nil {
			http500Error(clientTLSConn, "failed writing response status line", err, logger)
			return
		}

		// 2nd - the headers
		if err = resp.Header.Write(clientTLSConn); err != nil {
			http500Error(clientTLSConn, "failed writing TLS response header", err, logger)
			return
		}
		// 3rd - indicates the headers are done and the body will follow
		if _, err = clientTLSConn.Write([]byte("\r\n")); err != nil {
			http500Error(clientTLSConn, "failed writing TLS header/body separator", err, logger)
			return
		}

		// copy the body else
		_, err = io.CopyBuffer(clientTLSConn, resp.Body, make([]byte, 4096))
		if err != nil {
			http500Error(clientTLSConn, "failed writing response body", err, logger)
			return
		}

		resp.Body.Close()
	}
	logger.Info("EOF reached, finishing HTTPS handler")
}

func hijack(w http.ResponseWriter) (net.Conn, error) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprint(w, "cannot handle request")
		return nil, errors.New("http.ResponseWriter does not support hijacking")
	}

	clientCon, _, err := hijacker.Hijack()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, err = fmt.Fprint(w, "cannot handle request")

		return nil, fmt.Errorf("could not Hijack HTTPS CONNECT request: %w", err)
	}

	return clientCon, err
}

func cleanUpHeaders(h http.Header) {
	// Transport wil take care of it
	h.Del("Accept-Encoding")

	h.Del("Proxy-Connection")
	h.Del("Proxy-Authenticate")
	h.Del("Proxy-Authorization")
	h.Del("Connection")
}

func newTLSCert(u *url.URL) (*tls.Certificate, error) {
	// generate the certificate key - it needs to be RSA because Elastic Defend
	// do not support EC :/
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("could not create RSA private key: %w", err)
	}
	host := u.Hostname()

	var name string
	var ips []net.IP
	ip := net.ParseIP(host)
	if ip == nil { // host isn't an IP, therefore it must be an DNS
		name = host
	} else {
		ips = append(ips, ip)
	}

	cert, _, err := certutil.GenerateGenericChildCert(
		name,
		ips,
		priv,
		&priv.PublicKey,
		defaultTLS.capriv,
		defaultTLS.cacert)
	if err != nil {
		return nil, fmt.Errorf("could not generate TLS certificate for %s: %w",
			host, err)
	}

	return cert, nil
}

func generateHTTPResponse(statusCode int, body []byte) []byte {
	resp := bytes.Buffer{}
	resp.WriteString(fmt.Sprintf("HTTP/1.1 %d %s\r\n",
		statusCode, http.StatusText(statusCode)))
	resp.WriteString("Content-Type: text/plain\r\n")
	resp.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
	resp.WriteString("\r\n")
	if len(body) > 0 {
		resp.Write(body)
	}

	return resp.Bytes()
}

func http500Error(clientCon net.Conn, msg string, err error, logger *slog.Logger) {
	httpError(clientCon, http.StatusInternalServerError, msg, err, logger)
}

func httpError(clientCon net.Conn, status int, msg string, err error, logger *slog.Logger) {
	logger.Error(msg, "error", err)

	_, err = clientCon.Write(generateHTTPResponse(status, []byte(msg)))
	if err != nil {
		logger.Error("failed writing response", "err", err)
	}
}

// simpleHijack ...
// keeping just for reference
func simpleHijack(clientCon net.Conn, host string, logger *slog.Logger) {
	// ========================== Connect to target
	if strings.Contains(host, "elasticc") {
		oldHost := host
		host = strings.Replace(host, "elasticc", "elastic", 1)
		logger.Info("rewiring host", "old", oldHost, "new", host)
	}
	targetCon, err := net.Dial("tcp", host)
	if err != nil {
		httpError(clientCon,
			http.StatusBadGateway,
			fmt.Sprintf("could not connect to %q", host),
			err,
			logger)
		return
	}
	logger.Info("net.Dial connected to target")

	_, err = clientCon.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	if err != nil {
		http500Error(clientCon, "failed to send 200-OK after CONNECT", err, logger)
		return
	}

	logger.Info("sent 200 Connection established to client")
	var wg sync.WaitGroup
	wg.Add(2)
	go copyOrWarn(targetCon, clientCon, &wg, logger)
	go copyOrWarn(clientCon, targetCon, &wg, logger)
	wg.Wait()
}

func copyOrWarn(dst io.Writer, src io.Reader, wg *sync.WaitGroup, logger *slog.Logger) {
	if _, err := io.Copy(dst, src); err != nil {
		logger.Warn(fmt.Sprintf("Error copying to client: %v", err))
	}
	wg.Done()
}
