package mcms

import (
	"fmt"
	"nscan/plugins/log"
	"nscan/utils"
	"strings"
)

// mcms 5.2.7 /cms/content/list
func Front_Sql_inject(u string) bool {

	if req, err := utils.HttpRequset(u+"/cms/content/list", "POST", "categoryId=1'", false, nil); err == nil {
		if strings.Contains(req.Body, "error in your SQL") {
			log.Logger.Warn().Msg(fmt.Sprintf("Found mcms_sql_inject|\"%s\"\n", u+"/cms/content/list|POST:categoryId"))
			return true
		}
	}

	return false
}
