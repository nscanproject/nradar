package discover

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"nscan/common/argx"
	"nscan/plugins/common"
	"nscan/plugins/log"
	fingers "nscan/plugins/zfingers"
	zfCommon "nscan/plugins/zfingers/common"
	"nscan/utils"
	"time"

	"github.com/Ullaakut/nmap/v3"
)

var FingerEG *fingers.Engine

func init() {
	var err error
	FingerEG, err = fingers.NewEngine()
	if err != nil {
		log.Logger.Warn().Msgf("http_finger engine init with error:%s", err.Error())
	} else {
		if argx.Verbose {
			log.Logger.Debug().Msgf("http_finger engine init susscefully")
		}
	}
}

type PortScanner struct {
	Targets []common.Target
	Cancel  context.CancelFunc
}

func NewScanner() *PortScanner {
	return &PortScanner{}
}

func (p *PortScanner) Run(scanInfo common.ScanInfo) (err error) {
	var (
		sc     *nmap.Scanner
		result *nmap.Run
	)
	if scanInfo.Ctx == nil || scanInfo.CancelFunc == nil {
		scanInfo.Ctx, scanInfo.CancelFunc = context.WithCancel(context.Background())
	}
	p.Cancel = scanInfo.CancelFunc
	sc, err = nmap.NewScanner(scanInfo.Ctx,
		nmap.WithICMPEchoDiscovery(),
		nmap.WithTargets(scanInfo.Host...), nmap.WithPorts(scanInfo.Port...),
		nmap.WithServiceInfo(), nmap.WithOSDetection(),
		nmap.WithMinRate(5000), nmap.WithMinParallelism(64),
	)
	if err != nil {
		return err
	}
	start := time.Now()
	log.Logger.Debug().Msgf("%s start scanning %s", common.DISCOVE_TASK, scanInfo.Host)
	result, _, err = sc.Run()
	log.Logger.Debug().Msgf("%s finish scanning %s, cost %fs",
		common.DISCOVE_TASK, scanInfo.Host, time.Since(start).Seconds())
	var hostMap = map[string]bool{}
	for _, host := range scanInfo.Host {
		hostMap[host] = false
	}
	for _, host := range result.Hosts {
		if host.Status.State != "up" {
			// In fact, the host will not show it at all if it is already down.
			log.Logger.Warn().Msgf("%s host %s is down", common.DISCOVE_TASK, scanInfo.Host)
			continue
		}
		log.Logger.Warn().Msgf("%s host %s is up", common.DISCOVE_TASK, scanInfo.Host)
		var target common.Target
		for _, addr := range host.Addresses {
			if addr.AddrType == "ipv4" {
				target.IP = addr.Addr
			} else if addr.AddrType == "ipv6" {
				target.IP = addr.Addr
			} else if addr.AddrType == "mac" {
				target.MAC = addr.Addr
				target.MACVendor = addr.Vendor
			}
		}
		delete(hostMap, target.IP)
		for _, osMatch := range host.OS.Matches {
			var osInfo common.OSInfo
			osInfo.Name = osMatch.Name
			osInfo.Accuracy = osMatch.Accuracy
			osInfo.DeviceType = osMatch.Classes[0].Type
			for _, osClass := range osMatch.Classes {
				for _, cpe := range osClass.CPEs {
					osInfo.CPEs = append(osInfo.CPEs, string(cpe))
				}
			}
			osInfo.CPEs = utils.Deduplication(osInfo.CPEs)
			target.OSInfos = append(target.OSInfos, osInfo)
		}
		for _, port := range host.Ports {
			if port.State.State != "open" {
				log.Logger.Debug().Msgf("discard one target[%s:%d] which is not open", target.IP, port.ID)
				continue
			}
			var srvInfo common.ServiceInfo
			srvInfo.Port = int(port.ID)
			srvInfo.Proto = port.Protocol
			srvInfo.Method = port.Service.Method
			srvInfo.State = port.State.State
			srvInfo.Product = port.Service.Product
			srvInfo.Service = port.Service.Name
			srvInfo.Version = port.Service.Version
			if port.Service.Product != "" {
				srvInfo.Tags = append(srvInfo.Tags, port.Service.Product)
			}
			if port.Service.Name != "" {
				srvInfo.Tags = append(srvInfo.Tags, port.Service.Name)
			}
			var schema string
			if port.Service.Name == "http" {
				schema = "http"
			}
			if port.Service.Name == "http" && port.Service.Tunnel == "ssl" {
				schema = "https"
			}
			if port.Service.Name == "https" {
				schema = "https"
			}
			if schema != "" {
				srvInfo.Url = fmt.Sprintf("%s://%s:%d", schema, target.IP, srvInfo.Port)
				log.Logger.Debug().Msgf("%s start scanning %s", common.HTTP_TASK, srvInfo.Url)
				result, err := doHTTPProbe(srvInfo.Url)
				//todo poc tag manage
				if err != nil {
					log.Logger.Error().Msgf("%s finish scanning %s with error:%s", common.HTTP_TASK, srvInfo.Url, err.Error())
				} else {
					log.Logger.Debug().Msgf("%s finish scanning %s, result:%+v", common.HTTP_TASK, srvInfo.Url, result)
					for tag, frame := range result {
						if frame.Cpe != "" {
							srvInfo.CPEs = append(srvInfo.CPEs, frame.Cpe)
						}
						srvInfo.Tags = append(srvInfo.Tags, tag)
					}
				}
			}
			for _, cpe := range port.Service.CPEs {
				srvInfo.CPEs = append(srvInfo.CPEs, string(cpe))
			}
			srvInfo.CPEs = utils.Deduplication(srvInfo.CPEs)
			target.ServiceInfos = append(target.ServiceInfos, srvInfo)
		}
		p.Targets = append(p.Targets, target)
	}
	//reportHostDown(hostMap)
	return
}

func (p *PortScanner) DiscoverAlive(scanInfo common.ScanInfo) (err error) {
	var (
		sc     *nmap.Scanner
		result *nmap.Run
	)
	if scanInfo.Ctx == nil || scanInfo.CancelFunc == nil {
		scanInfo.Ctx, scanInfo.CancelFunc = context.WithCancel(context.Background())
	}
	p.Cancel = scanInfo.CancelFunc
	sc, err = nmap.NewScanner(scanInfo.Ctx,
		nmap.WithICMPEchoDiscovery(),
		nmap.WithTargets(scanInfo.Host...),
		nmap.WithSYNDiscovery([]string{"21-23", "25", "80", "110", "139", "443", "445", "3389"}...),
		nmap.WithUDPDiscovery([]string{"137-138", "161"}...),
		nmap.WithMinRate(5000), nmap.WithMinParallelism(64),
	)
	if err != nil {
		return err
	}
	start := time.Now()
	log.Logger.Debug().Msgf("%s start scanning %s", common.DISCOVE_TASK, scanInfo.Host)
	result, _, err = sc.Run()
	log.Logger.Debug().Msgf("%s finish scanning %s, cost %fs",
		common.DISCOVE_TASK, scanInfo.Host, time.Since(start).Seconds())
	var hostMap = map[string]bool{}
	for _, host := range scanInfo.Host {
		hostMap[host] = false
	}
	for _, host := range result.Hosts {
		if host.Status.State != "up" {
			// In fact, the host will not show it at all if it is already down.
			log.Logger.Warn().Msgf("%s host %s is down", common.DISCOVE_TASK, scanInfo.Host)
			continue
		}
		log.Logger.Warn().Msgf("%s host %s is up", common.DISCOVE_TASK, scanInfo.Host)
		var target common.Target
		for _, addr := range host.Addresses {
			if addr.AddrType == "ipv4" {
				target.IP = addr.Addr
			} else if addr.AddrType == "ipv6" {
				target.IP = addr.Addr
			} else if addr.AddrType == "mac" {
				target.MAC = addr.Addr
				target.MACVendor = addr.Vendor
			}
		}
		delete(hostMap, target.IP)
		for _, osMatch := range host.OS.Matches {
			var osInfo common.OSInfo
			osInfo.Name = osMatch.Name
			osInfo.Accuracy = osMatch.Accuracy
			osInfo.DeviceType = osMatch.Classes[0].Type
			for _, osClass := range osMatch.Classes {
				for _, cpe := range osClass.CPEs {
					osInfo.CPEs = append(osInfo.CPEs, string(cpe))
				}
			}
			osInfo.CPEs = utils.Deduplication(osInfo.CPEs)
			target.OSInfos = append(target.OSInfos, osInfo)
		}
		for _, port := range host.Ports {
			if port.State.State != "open" {
				log.Logger.Debug().Msgf("discard one target[%s:%d] which is not open", target.IP, port.ID)
				continue
			}
			var srvInfo common.ServiceInfo
			srvInfo.Port = int(port.ID)
			srvInfo.Proto = port.Protocol
			srvInfo.Method = port.Service.Method
			srvInfo.State = port.State.State
			srvInfo.Product = port.Service.Product
			srvInfo.Service = port.Service.Name
			srvInfo.Version = port.Service.Version
			if port.Service.Product != "" {
				srvInfo.Tags = append(srvInfo.Tags, port.Service.Product)
			}
			if port.Service.Name != "" {
				srvInfo.Tags = append(srvInfo.Tags, port.Service.Name)
			}
			var schema string
			if port.Service.Name == "http" {
				schema = "http"
			}
			if port.Service.Name == "http" && port.Service.Tunnel == "ssl" {
				schema = "https"
			}
			if port.Service.Name == "https" {
				schema = "https"
			}
			if schema != "" {
				srvInfo.Url = fmt.Sprintf("%s://%s:%d", schema, target.IP, srvInfo.Port)
				log.Logger.Debug().Msgf("%s start scanning %s", common.HTTP_TASK, srvInfo.Url)
				result, err := doHTTPProbe(srvInfo.Url)
				//todo poc tag manage
				if err != nil {
					log.Logger.Error().Msgf("%s finish scanning %s with error:%s", common.HTTP_TASK, srvInfo.Url, err.Error())
				} else {
					log.Logger.Debug().Msgf("%s finish scanning %s, result:%+v", common.HTTP_TASK, srvInfo.Url, result)
					for tag, frame := range result {
						if frame.Cpe != "" {
							srvInfo.CPEs = append(srvInfo.CPEs, frame.Cpe)
						}
						srvInfo.Tags = append(srvInfo.Tags, tag)
					}
				}
			}
			for _, cpe := range port.Service.CPEs {
				srvInfo.CPEs = append(srvInfo.CPEs, string(cpe))
			}
			srvInfo.CPEs = utils.Deduplication(srvInfo.CPEs)
			target.ServiceInfos = append(target.ServiceInfos, srvInfo)
		}
		p.Targets = append(p.Targets, target)
	}
	//reportHostDown(hostMap)
	return
}

func reportHostDown(hostMap map[string]bool) {
	for host, _ := range hostMap {
		log.Logger.Warn().Msgf("host[%s] is down", host)
	}
}

func (p *PortScanner) Stop() (err error) {
	p.Cancel()
	return
}

var (
	fuzzs = []string{"/nacos"}
)

func doHTTPProbe(targetUrl string) (result zfCommon.Frameworks, err error) {
	client := &http.Client{Timeout: time.Second * 3, Transport: &http.Transport{
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS10, InsecureSkipVerify: true},
		TLSHandshakeTimeout: 5 * time.Second,
		DisableKeepAlives:   false,
	}}
	resp, err := client.Get(targetUrl)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		for _, fuzz := range fuzzs {
			// url.JoinPath(targetUrl,fuzz)
			resp2, err := client.Get(targetUrl + fuzz)
			if err != nil {
				continue
			}
			if resp2.StatusCode != 404 {
				resp = resp2
				break
			}
			resp2.Body.Close()
		}
	}
	result, err = FingerEG.DetectResponse(resp)
	return
}
