package utils

import (
	"fmt"
	"time"
)

func BeautifyDuration(d time.Duration) (result string) {
	resultNum, count := tryGoUpperSecond(float64(d))
	unit := "ns"
	switch count {
	case 0:
		unit = "ns"
	case 1:
		unit = "μs"
	case 2:
		unit = "ms"
	case 3:
		unit = "s"
		//todo no need 4 now [min|hour|day|month|year]
	}
	return fmt.Sprintf("%d%s", uint64(resultNum), unit)
}

func tryGoUpperSecond(input float64) (float64, int) {
	var count int
	if input < 1000 {
		return input, count
	}
	tmpRes := input / float64(1000)
	count++
	if tmpRes < 1000 || count > 3 {
		return tmpRes, count
	}
	return tryGoUpperSecond(tmpRes)
}

func FormatTime(t time.Time, format ...string) string {
	if len(format) > 0 {
		return t.Format(format[0])
	}
	return t.Format("2006-01-02 15:04:05")
}
