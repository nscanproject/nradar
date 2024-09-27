package main

import (
	"context"
	"fmt"
	"nscan/handler"
	"nscan/plugins/common"
	"nscan/plugins/discover"
	"nscan/plugins/log"
	"nscan/plugins/poc/nucleis"
	"nscan/utils"
	"time"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

func main() {
	demo1()
}

func demo1() {
	start := time.Now()
	ctx, cancel := context.WithCancel(context.Background())
	sc := discover.NewScanner()
	err := sc.Run(common.ScanInfo{
		Host:       []string{"10.1.1.1}",
		Port:       "22",
		Ctx:        ctx,
		CancelFunc: cancel,
	})
	if err != nil {
		log.Logger.Error().Msgf("discover run with error:%s", err.Error())
	}
	for _, target := range sc.Targets {
		for _, srvInfo := range target.ServiceInfos {
			var pocIds []string
			for _, tag := range srvInfo.Tags {
				if pocIds0, ok := nucleis.POCIdMappings[tag]; ok {
					pocIds = append(pocIds, pocIds0...)
				}
			}
			pocIds = utils.Deduplication(pocIds)
			if len(pocIds) == 0 {
				log.Logger.Debug().Msgf("no need to poc with [%s:%d]", target.IP, srvInfo.Port)
				continue
			}
			ne, err := nuclei.NewNucleiEngineCtx(
				ctx, nuclei.DisableUpdateCheck(),
				nuclei.WithTemplateFilters(nuclei.TemplateFilters{IDs: pocIds}),
			)
			if err != nil {
				log.Logger.Error().Msgf("nuclei new with error:%s", err.Error())
			}
			var url string
			if srvInfo.Url != "" {
				url = srvInfo.Url
			} else {
				url = fmt.Sprintf("%s:%d", target.IP, srvInfo.Port)
			}
			ne.LoadTargets([]string{url}, false)
			ne.ExecuteWithCallback(func(event *output.ResultEvent) {
				log.Logger.Warn().Msgf("Found poc:%+v", event.Info.Classification.CVEID)
			})
		}
	}
	log.Logger.Debug().Msgf("total cost %fs", time.Since(start).Seconds())
}

func parse1() {
	h := handler.NewDefaultHandler(context.Background(), handler.ScanInfo{
		Host: "1.1.1.1-100,1.1.1.101-200",
	})
	h.Handle()
}
