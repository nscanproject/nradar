package brute

import (
	"fmt"
	"nscan/plugins/log"
	"nscan/utils"
)

func Jboss_brute(url string) (username string, password string) {
	if req, err := utils.HttpRequsetBasic("asdasdascsacacs", "asdasdascsacacs", url+"/jmx-console/", "GET", "", false, nil); err == nil {
		if req.StatusCode == 401 {
			for uspa := range jbossuserpass {
				if req2, err2 := utils.HttpRequsetBasic(jbossuserpass[uspa].username, jbossuserpass[uspa].password, url+"/jmx-console/", "GET", "", false, nil); err2 == nil {
					if req2.StatusCode == 200 || req2.StatusCode == 403 {
						log.Logger.Warn().Msg(fmt.Sprintf("Found vuln Jboss password|%s:%s|%s\n", jbossuserpass[uspa].username, jbossuserpass[uspa].password, url))
						return jbossuserpass[uspa].username, jbossuserpass[uspa].password
					}
				}
			}
		}
	}
	return "", ""
}
