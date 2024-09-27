package tomcat

import (
	"fmt"
	"nscan/plugins/log"
	"nscan/utils"
)

func CVE_2017_12615(url string) bool {
	if req, err := utils.HttpRequset(url+"/vtset.txt", "PUT", "test", false, nil); err == nil {
		if req.StatusCode == 204 || req.StatusCode == 201 {
			log.Logger.Warn().Msg(fmt.Sprintf("Found vuln Tomcat CVE_2017_12615|--\"%s/vtest.txt\"\n", url))
			return true
		}
	}
	return false
}
