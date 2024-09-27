package jenkins

import (
	"fmt"
	"nscan/plugins/log"
	"nscan/utils"
	"strings"
)

func CVE_2018_1000110(u string) bool {
	if req, err := utils.HttpRequset(u, "GET", "", false, nil); err == nil {
		if req.Header.Get("X-Jenkins-Session") != "" {
			if req2, err := utils.HttpRequset(u+"/search/?q=a", "GET", "", false, nil); err == nil {
				if strings.Contains(req2.Body, "Search for 'a'") {
					log.Logger.Warn().Msg(fmt.Sprintf("Found vuln Jenkins CVE_2018_1000110|%s\n", u))
					return true
				}
			}
		}
	}
	return false
}
