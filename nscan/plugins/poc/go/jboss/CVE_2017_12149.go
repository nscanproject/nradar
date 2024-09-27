package jboss

import (
	"fmt"
	"nscan/plugins/log"
	"nscan/utils"
)

func CVE_2017_12149(url string) bool {
	if req, err := utils.HttpRequset(url+"/invoker/readonly", "GET", "", false, nil); err == nil {
		if req.StatusCode == 500 {
			log.Logger.Warn().Msg(fmt.Sprintf("Found vuln Jboss CVE_2017_12149|%s\n", url))
			return true
		}
	}
	return false
}
