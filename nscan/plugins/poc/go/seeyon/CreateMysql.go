package seeyon

import (
	"fmt"
	"nscan/plugins/log"
	"nscan/utils"
	"strings"
)

//createMysql.jsp 数据库敏感信息泄

func CreateMysql(u string) bool {
	var vuln = false
	if req, err := utils.HttpRequset(u+"/yyoa/createMysql.jsp", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "root") {
			log.Logger.Warn().Msg(fmt.Sprintf("Found vuln seeyon CreateMysql|%s\n", u+"/yyoa/createMysql.jsp"))
			vuln = true
		}
	}
	if req, err := utils.HttpRequset(u+"/yyoa/ext/createMysql.jsp", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "root") {
			log.Logger.Warn().Msg(fmt.Sprintf("Found vuln seeyon CreateMysql|%s\n", u+"/yyoa/ext/createMysql.jsp"))
			vuln = true
		}
	}
	return vuln
}
