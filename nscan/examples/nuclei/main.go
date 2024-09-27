package main

import (
	"context"
	"fmt"
	"nscan/plugins/log"
	nucleis "nscan/plugins/poc/nucleis"
	"sync"
	"time"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

func main() {
	// official_simple()
	// private_simple()
	// concurrent_simple()
	concurrent_official()
}

func concurrent_official() {
	var wg sync.WaitGroup
	nc, _ := nuclei.NewThreadSafeNucleiEngineCtx(context.Background(), nuclei.DisableUpdateCheck())
	wg.Add(3)
	go func() {
		nc.GlobalResultCallback(func(event *output.ResultEvent) {
			fmt.Printf("found %s from %s\n", event.TemplateID, event.Matched)
		})
	}()
	for i := 1; i <= 3; i++ {
		go func(i int) {
			if i == 1 {
				nc.ExecuteNucleiWithOpts([]string{"http://10.1.1.57:9001"},
					nuclei.WithTemplateFilters(nuclei.TemplateFilters{Tags: []string{"gitlab"}}))
			} else if i == 2 {
				nc.ExecuteNucleiWithOpts([]string{"http://10.1.1.106:8001"},
					nuclei.WithTemplateFilters(nuclei.TemplateFilters{Tags: []string{"nacos"}}))
			} else if i == 3 {
				nc.ExecuteNucleiWithOpts([]string{"10.1.1.1:22"},
					nuclei.WithTemplateFilters(nuclei.TemplateFilters{Tags: []string{"ssh"}}))
			}
			wg.Done()
		}(i)
	}
	wg.Wait()
	defer nc.Close()
}

func concurrent_simple() {
	var wg sync.WaitGroup
	wg.Add(3)
	for i := 0; i < 3; i++ {
		go func(i int) {
			nc, _ := nuclei.NewNucleiEngine()
			nc.LoadTargets([]string{fmt.Sprintf("10.1.%d.1/24", (i + 20))}, false)
			if i == 1 {
				nc.Close()
				return
			}
			nc.ExecuteWithCallback()
			wg.Done()
		}(i)
	}
	wg.Wait()
}

func private_simple() {
	fmt.Printf("nucleis.POCIdMappings: %v\n", nucleis.POCIdMappings)
}

func official_simple() {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(time.Second * 20)
		cancel()
	}()
	ne, err := nuclei.NewNucleiEngineCtx(ctx, nuclei.WithTemplateFilters(nuclei.TemplateFilters{
		IDs: []string{"CVE-2008-5161"},
	}))
	if err != nil {
		panic(err)
	}
	ne.LoadTargets([]string{"10.1.1.1:22"}, false)
	err = ne.ExecuteWithCallback(func(event *output.ResultEvent) {
		if event.Info.Classification != nil {
			log.Logger.Warn().Msgf("Found poc:%+v from [%s]", event.Info.Classification.CVEID, event.Matched)
		} else {
			log.Logger.Warn().Msgf("Found poc:%+v from [%s]", event.TemplateID, event.Matched)
		}
	})
	if err != nil {
		panic(err)
	}
	defer ne.Close()
}
