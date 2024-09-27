package utils

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/malfunkt/iprange"
)

func TestGroupStrsBySize(t *testing.T) {
	list, _ := iprange.ParseList("1.1.1.1/24")
	var hosts []string
	for _, ip := range list.Expand() {
		hosts = append(hosts, ip.String())
	}
	subGroups := GroupStrsBySize(hosts, runtime.NumCPU()*2)
	fmt.Println(len(subGroups))
}
