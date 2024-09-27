package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	fingers "nscan/plugins/zfingers"
	"time"
)

var (
	fuzzs = []string{"/nacos"}
)

func main() {
	eg, err := fingers.NewEngine()
	if err != nil {
		panic(err)
	}
	u, _ := url.Parse("http://10.1.30.205:8080")
	fmt.Println(u)
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS10, InsecureSkipVerify: true},
		TLSHandshakeTimeout: 5 * time.Second,
		DisableKeepAlives:   false,
		// Proxy:           http.ProxyURL(u),
	}
	client := &http.Client{Transport: tr, Timeout: time.Second * 3}
	target := "https://10.1.1.1"
	// target := "http://10.1.1.106:8001"
	// target := "http://10.1.1.161:8001/v3/api-docs"
	req, _ := http.NewRequest("GET", target, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		for _, fuzz := range fuzzs {
			resp2, err := client.Get(target + fuzz)
			if err == nil && resp2.StatusCode != 404 {
				resp = resp2
				break
			}
		}
	}
	result, err := eg.DetectResponse(resp)
	if err != nil {
		panic(err)
	}
	fmt.Println(result)
}
