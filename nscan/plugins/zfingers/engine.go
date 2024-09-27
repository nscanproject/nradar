package fingers

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"nscan/plugins/zfingers/common"
	"nscan/plugins/zfingers/fingerprinthub"
	"nscan/plugins/zfingers/fingers"
	wappalyzer "nscan/plugins/zfingers/wappalyzer"
)

func NewEngine() (*Engine, error) {
	engine := &Engine{}
	fingersEngine, err := fingers.NewFingersEngine(fingers.HTTPFingerData, fingers.SocketFingerData)
	if err != nil {
		return nil, err
	}
	engine.FingersEngine = fingersEngine

	fingerPrintEngine, err := fingerprinthub.NewFingerPrintHubEngine()
	if err != nil {
		return nil, err
	}
	engine.FingerPrintEngine = fingerPrintEngine

	wappalyzerEngine, err := wappalyzer.NewWappalyzeEngine()
	if err != nil {
		return nil, err
	}
	engine.WappalyzerEngine = wappalyzerEngine

	return engine, nil
}

type Engine struct {
	FingersEngine     *fingers.FingersRules
	FingerPrintEngine fingerprinthub.FingerPrintHubs
	WappalyzerEngine  *wappalyzer.Wappalyze
}

func (engine *Engine) DetectResponse(resp *http.Response) (common.Frameworks, error) {
	var raw bytes.Buffer

	raw.WriteString(fmt.Sprintf("%s %s\r\n", resp.Proto, resp.Status))
	for k, v := range resp.Header {
		for _, i := range v {
			raw.WriteString(fmt.Sprintf("%s: %s\r\n", k, i))
		}
	}
	raw.WriteString("\r\n")
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	raw.Write(body)
	_ = resp.Body.Close()
	frames := make(common.Frameworks)
	if engine.FingersEngine != nil {
		var cert string
		if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
			cert = strings.Join(resp.TLS.PeerCertificates[0].DNSNames, ",")
		}
		fs, _ := engine.FingersEngine.HTTPMatch(raw.Bytes(), cert)
		frames.Merge(fs)
	}

	if engine.FingerPrintEngine != nil {
		fs := engine.FingerPrintEngine.Match(resp.Header, string(body))
		frames.Merge(fs)
	}

	if engine.WappalyzerEngine != nil {
		fs := engine.WappalyzerEngine.Fingerprint(resp.Header, body)
		frames.Merge(fs)
	}

	return frames, err
}
