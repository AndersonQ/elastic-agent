package main

import (
	"fmt"
	"net/http"
	"net/http/httputil"

	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
)

func main() {
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
		panic(fmt.Errorf("failed to make roundtripper: %v", err))
	}

	c := http.Client{Transport: rt}
	r, err := http.NewRequest(http.MethodGet, "https://elasticc.co", nil)
	if err != nil {
		panic(fmt.Errorf("failed to create request: %v", err))
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
		panic(fmt.Errorf("failed to make request: %v", err))
	}

	bs, err = httputil.DumpResponse(resp, true)
	if err != nil {
		panic(err)
	}
	fmt.Println("====================== RESPONSE")
	fmt.Println(string(bs))
	fmt.Println("====================== END RESPONSE\n")
}
