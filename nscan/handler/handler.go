package handler

import (
	"context"
	"fmt"
	"nscan/plugins/log"
	"runtime"

	"github.com/malfunkt/iprange"
)

type DefaultHandler struct {
	ScanInfo ScanInfo
	Context  context.Context
}

func NewDefaultHandler(ctx context.Context, si ScanInfo) *DefaultHandler {
	return &DefaultHandler{Context: ctx, ScanInfo: si}
}

func (h *DefaultHandler) Handle() (err error) {
	if h.ScanInfo.Host == "" {
		log.Logger.Warn().Msgf("No host represent, quit handling")
		return
	}
	var hosts []string
	list, err := iprange.ParseList(h.ScanInfo.Host)
	if err != nil {
		log.Logger.Error().Msgf("Parse host with error[%s]", err.Error())
		return
	}
	for _, ip := range list.Expand() {
		hosts = append(hosts, ip.String())
	}
	groupSize := runtime.NumCPU() * 2
	fmt.Println("group size:", groupSize)
	return
}
