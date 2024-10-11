package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"os"
	"time"

	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
)

func main() {
	slog.SetDefault(slog.New(
		slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
				if a.Key == slog.TimeKey && len(groups) == 0 {

					t := a.Value.Time()
					a.Value = slog.StringValue(t.Format(time.RFC3339Nano))

				}
				return a
			},
		}),
	))

	wd := "/home/ainsoph/devel/github.com/elastic/elastic-agent/testing/proxytest/cmd/certs/"

	proxyURL, err := httpcommon.NewProxyURIFromString("https://localhost:4242")
	if err != nil {
		panic(fmt.Errorf("failed to parse proxy URL: %v", err))
	}
	httpSettings := httpcommon.HTTPTransportSettings{
		Proxy: httpcommon.HTTPClientProxySettings{
			URL: proxyURL,
		},
		TLS: &tlscommon.Config{
			VerificationMode: tlscommon.VerifyFull,
			CAs: []string{
				wd + "proxy-ca.pem",
				"/etc/ssl/certs/ca-certificates.crt"},
			Certificate: tlscommon.CertificateConfig{
				Certificate: wd + "client-localhost.pem",
				Key:         wd + "client-localhost_key.pem",
			},
		},
	}

	rt, err := httpSettings.RoundTripper()
	if err != nil {
		err = fmt.Errorf("failed to make roundtripper: %v", err)
		slog.Error(err.Error())
		panic(err)
	}

	c := http.Client{Transport: rt}
	// r, err := http.NewRequest(http.MethodGet, "https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.15.2-linux-x86_64.tar.gz", nil)
	r, err := http.NewRequest(http.MethodGet, "https://elasticc.co", nil)
	if err != nil {
		err = fmt.Errorf("failed to create request: %v", err)
		slog.Error(err.Error())
		panic(err)
	}

	bs, err := httputil.DumpRequest(r, true)
	if err != nil {
		panic(err)
	}
	fmt.Println("====================== REQUEST")
	fmt.Println(string(bs))

	fmt.Println("====================== END REQUEST\n")

	resp, err := c.Do(r)
	if err != nil {
		err = fmt.Errorf("failed to make request: %v", err)
		slog.Error(err.Error())
		panic(err)
	}

	// f, err := os.Create(wd + "downloaded-filebeat-8.15.2-linux-x86_64.tar.gz")
	// if err != nil {
	// 	panic(fmt.Errorf("failed to create file: %v", err))
	// }
	//
	// _, err = io.CopyBuffer(f, resp.Body, make([]byte, 16*1024*1024))
	// if err != nil {
	// 	panic(fmt.Errorf("failed to save data to file: %v", err))
	// }
	//
	bs, err = httputil.DumpResponse(resp, true)
	if err != nil {
		panic(err)
	}
	fmt.Println("====================== RESPONSE")
	fmt.Println(string(bs))
	fmt.Println("====================== END RESPONSE\n")
}
