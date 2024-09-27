package main

import (
	"nscan/common/argx"
	"nscan/engine"
)

func main() {
	argx.Verbose = true
	engine.Default().Serve(true, ":9527")
}
