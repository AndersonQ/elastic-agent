package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/elastic/elastic-agent-libs/testing/certutil"
	"github.com/elastic/elastic-agent/testing/proxytest"
)

func main() {
	caClientPair, certClientPair, err := certutil.NewCAAndCerts()
	if err != nil {
		panic(fmt.Errorf("failed generating client certificaets: %w", err))
	}
	savePair("", "client-ca", caClientPair)
	savePair("", "client-cert", certClientPair)

	caProxyPair, certProxyPair, err := certutil.NewCAAndCerts()
	if err != nil {
		panic(fmt.Errorf("failed generating proxy certificaets: %w", err))
	}
	savePair("", "proxy-ca", caProxyPair)
	savePair("", "proxy-cert", certProxyPair)

	rootCertPool := x509.NewCertPool()
	rootCertPool.AppendCertsFromPEM(caProxyPair.Cert)

	// fleetTLSServer.TLS = &tls.Config{ //nolint:gosec // it's just a test
	//			RootCAs:      fleetRootCertPool,
	//			Certificates: []tls.Certificate{cert},
	//			ClientCAs:    agentRootCertPool,
	//			ClientAuth:   tls.RequireAndVerifyClientCert,
	//		}

	proxyCerts, err := tls.X509KeyPair(certProxyPair.Cert, certProxyPair.Key)
	tlsConfig := &tls.Config{
		RootCAs:      rootCertPool,
		Certificates: []tls.Certificate{proxyCerts},
		// MinVersion:   tls.VersionTLS10,
	}

	proxytest.New(
		proxytest.WithTLS(tlsConfig),
		proxytest.WithAddress(":44439"),
		proxytest.WithRequestLog("proxy", func(format string, a ...any) {
			slog.Info(fmt.Sprintf(format, a...))
		}))

	fmt.Println("press CTRL+C to exit")
	<-make(chan struct{})
}

func savePair(dest string, name string, pair certutil.Pair) {
	err := os.WriteFile(filepath.Join(dest, name+".pem"), pair.Cert, 0o600)
	if err != nil {
		panic(fmt.Errorf("could not save %s certificate: %w", name, err))
	}

	err = os.WriteFile(filepath.Join(dest, name+"_key.pem"), pair.Key, 0o600)
	if err != nil {
		panic(fmt.Errorf("could not save %s certificate key: %w", name, err))
	}
}
