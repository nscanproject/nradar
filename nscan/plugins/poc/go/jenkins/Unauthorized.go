package jenkins

import (
	"fmt"
	"nscan/plugins/log"
	"nscan/utils"
	"strings"
)

func Unauthorized(u string) bool {
	if req, err := utils.HttpRequset(u, "GET", "", false, nil); err == nil {
		if req.Header.Get("X-Jenkins-Session") != "" {
			if req2, err := utils.HttpRequset(u+"/script", "GET", "", false, nil); err == nil {
				if req2.StatusCode == 200 && strings.Contains(req2.Body, "Groovy script") {
					log.Logger.Warn().Msg(fmt.Sprintf("Found vuln Jenkins Unauthorized script|%s\n", u+"/script"))
					return true
				}
			}
			if req2, err := utils.HttpRequset(u+"/computer/(master)/scripts", "GET", "", false, nil); err == nil {
				if req2.StatusCode == 200 && strings.Contains(req2.Body, "Groovy script") {
					log.Logger.Warn().Msg(fmt.Sprintf("Found vuln Jenkins Unauthorized script|%s\n", u+"/computer/(master)/scripts"))
					return true
				}
			}
		}
	}
	return false
}
