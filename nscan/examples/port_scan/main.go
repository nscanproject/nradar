package main

import (
	"context"
	"fmt"
	"nscan/common/argx"
	"nscan/plugins/common"
	"nscan/plugins/discover"
)

func main() {
	argx.Verbose = true
	ctx, cancel := context.WithCancel(context.Background())
	sc := discover.NewScanner()
	sc.Run(common.ScanInfo{
		Host:       []string{"10.1.1.1/24"},
		Port:       []string{"1-65535"},
		Ctx:        ctx,
		CancelFunc: cancel,
	})
	for _, target := range sc.Targets {
		fmt.Println(target)
	}
}
