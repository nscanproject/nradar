package main

import (
	"crypto/tls"
	"net/http"
	"nscan/plugins/discover"
	"nscan/plugins/log"
	"nscan/plugins/poc"
)

func main() {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	// resp, err := client.Get("http://10.1.1.57:9001")
	resp, err := client.Get("http://10.1.2.254:8080")
	if err != nil {
		panic(err)
	}
	result, err := discover.FingerEG.DetectResponse(resp)
	if err != nil {
		panic(err)
	}
	var tags []string
	for tag, _ := range result {
		tags = append(tags, tag)
	}
	// r := poc.POCcheck(tags, "http://10.1.1.57:9001", "http://10.1.1.57:9001", true)
	r := poc.POCcheck(tags, "http://10.1.2.254:8009", "http://10.1.2.254:8009")
	log.Logger.Debug().Msgf("scan result:%+v", r)
}
