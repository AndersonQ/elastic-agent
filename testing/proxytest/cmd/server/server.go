package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"path/filepath"
	"strings"
	"sync"

	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
)

func main() {
	ctx := context.Background()

	wd := "/home/ainsoph/devel/github.com/elastic/elastic-agent/testing/proxytest/cmd/certs"
	tlscfg := tlscommon.ServerConfig{
		CAs: []string{
			filepath.Join(wd, "client-ca.pem"),
			"/etc/ssl/certs/ca-certificates.crt",
		},
		Certificate: tlscommon.CertificateConfig{
			Certificate: filepath.Join(wd, "proxy-localhost.pem"),
			Key:         filepath.Join(wd, "proxy-localhost_key.pem"),
		},
	}
	commonTLSCfg, err := tlscommon.LoadTLSServerConfig(&tlscfg)
	if err != nil {
		panic(err)
	}

	addr := "localhost:4242"

	var listenCfg net.ListenConfig
	ln, err := listenCfg.Listen(ctx, "tcp", addr)
	if err != nil {
		panic(err)
	}
	defer func() {
		err := ln.Close()
		if err != nil {
			slog.Error("server.Run: error while closing listener.", "error", err)
		}
	}()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bs, err := httputil.DumpRequest(r, true)
		if err != nil {
			slog.Error("server.Run: error while dumping request", "error", err)
		}

		fmt.Println("========================== Request Dump ==========================")
		fmt.Println(string(bs))
		fmt.Println("========================== Request Dump END ==========================")

		if r.Method == http.MethodConnect {
			handleHTTPS(w, r)
			return
		}
		_, err = w.Write([]byte("Hello World"))
		if err != nil {
			fmt.Printf("Error writing response: %v\n", err)
		}
	})

	srv := httptest.NewUnstartedServer(handler)
	srv.Listener = ln
	srv.TLS = &tls.Config{
		ClientCAs:    commonTLSCfg.ClientCAs,
		RootCAs:      commonTLSCfg.ClientCAs,
		Certificates: commonTLSCfg.Certificates,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	srv.StartTLS()
	slog.Info("server: listening on " + addr)
	<-ctx.Done()
}

func handleHTTPS(w http.ResponseWriter, r *http.Request) {
	slog.Info("handling CONNECT")

	// ========================== http.Hijacker
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		msg := "httpserver does not support hijacking"
		slog.Info(msg)
		_, _ = fmt.Fprint(w, msg)
		return
	}

	// ========================== Hijack
	clientCon, _, err := hijacker.Hijack()
	if err != nil {
		msg := "could not Hijack HTTPS CONNECT request"
		slog.Error(msg, "err", err)

		w.WriteHeader(http.StatusInternalServerError)
		_, err = fmt.Fprint(w, msg)
		if err != nil {
			slog.Error("failed writing response", "err", err)
		}
		return
	}
	slog.Info("hijacked CONNECT request")
	defer func() {
		if err = clientCon.Close(); err != nil {
			slog.Error("failed to close client connection", "err", err)
		}
	}()

	// Hijack successfully, w is now useless, let's make sure it isn't used by
	// mistake ;)
	w = nil

	// ========================== Connect to target
	host := r.URL.Host
	if strings.Contains(host, "elasticc") {
		host = strings.Replace(host, "elasticc", "elastic", 1)
		slog.Info("rewiring host", "old", r.URL.Host, "new", host)
	}
	targetCon, err := net.Dial("tcp", host)
	if err != nil {
		msg := fmt.Sprintf("could not connect to %q: %#v", host, err.Error())
		slog.Error(msg)

		_, err = clientCon.Write(generateHTTPResponse(http.StatusBadGateway, []byte(msg)))
		if err != nil {
			slog.Error("failed writing response", "err", err)
		}
		return
	}
	slog.Info("net.Dial connected to target")

	_, err = clientCon.Write([]byte("HTTP/1.0 200 Connection established\r\n\r\n"))

	slog.Info("sent 200 Connection established to client")
	var wg sync.WaitGroup
	wg.Add(2)
	go copyOrWarn(targetCon, clientCon, &wg)
	go copyOrWarn(clientCon, targetCon, &wg)
	wg.Wait()
}

func generateHTTPResponse(statusCode int, body []byte) []byte {
	resp := bytes.Buffer{}
	resp.WriteString(fmt.Sprintf("HTTP/1.0 %d %s\r\n",
		statusCode, http.StatusText(statusCode)))
	resp.WriteString("Content-Type: text/plain\r\n")
	resp.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
	resp.WriteString("\r\n")
	if len(body) > 0 {
		resp.Write(body)
	}

	return resp.Bytes()
}

func copyOrWarn(dst io.Writer, src io.Reader, wg *sync.WaitGroup) {
	if _, err := io.Copy(dst, src); err != nil {
		slog.Warn(fmt.Sprintf("Error copying to client: %v", err))
	}
	wg.Done()
}
