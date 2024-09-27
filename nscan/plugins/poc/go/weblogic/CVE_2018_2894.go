package weblogic

import (
	"fmt"
	"nscan/plugins/log"
	"nscan/utils"
)

func CVE_2018_2894(url string) bool {
	if req, err := utils.HttpRequset(url+"/ws_utc/begin.do", "GET", "", false, nil); err == nil {
		if req2, err2 := utils.HttpRequset(url+"/ws_utc/config.do", "GET", "", false, nil); err2 == nil {
			if req.StatusCode == 200 || req2.StatusCode == 200 {
				log.Logger.Warn().Msg(fmt.Sprintf("Found vuln Weblogic CVE_2018_2894|%s\n", url))
				return true
			}
		}
	}
	return false
}
