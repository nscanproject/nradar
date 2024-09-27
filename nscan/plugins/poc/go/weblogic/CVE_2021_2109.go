package weblogic

import (
	"fmt"
	"nscan/plugins/log"
	"nscan/utils"
	"strings"
)

func CVE_2021_2109(url string) bool {
	if req, err := utils.HttpRequset(url+"/console/css/%252e%252e%252f/consolejndi.portal", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "Weblogic") {
			log.Logger.Warn().Msg(fmt.Sprintf("Found vuln Weblogic CVE_2021_2109|%s\n", url))
			return true
		}
	}
	return false
}
