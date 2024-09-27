package weblogic

import (
	"fmt"
	"nscan/plugins/log"
	"nscan/utils"
)

func CVE_2014_4210(url string) bool {
	if req, err := utils.HttpRequset(url+"/uddiexplorer/SearchPublicRegistries.jsp", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 {
			log.Logger.Warn().Msg(fmt.Sprintf("Found vuln Weblogic CVE_2014_4210|%s\n", url))
			return true
		}
	}
	return false
}
