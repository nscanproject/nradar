package utils

func GroupStrsBySize(rawHosts []string, maxSize int) (finalHostGroups [][]string) {
	numGroups := len(rawHosts) / maxSize
	if len(rawHosts)%maxSize != 0 {
		numGroups++
	}

	finalHostGroups = make([][]string, numGroups)

	for i := 0; i < numGroups-1; i++ {
		finalHostGroups[i] = rawHosts[i*maxSize : (i+1)*maxSize]
	}

	finalHostGroups[numGroups-1] = rawHosts[(numGroups-1)*maxSize:]

	return
}
