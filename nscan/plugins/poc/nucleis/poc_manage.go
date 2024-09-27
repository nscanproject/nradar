package nucleis

import (
	"encoding/json"
	"nscan/common/argx"
	"nscan/plugins/log"
)

func init() {
	err := json.Unmarshal(POCIdMappingData, &POCIdMappings)
	if err != nil {
		log.Logger.Error().Msgf("POCIdMapping parse with error:%s", err.Error())
	} else {
		if argx.Verbose {
			log.Logger.Debug().Msgf("Successfully loaded %d type of poc mappings", len(POCIdMappings))
		}
	}
}
