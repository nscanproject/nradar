package main

import (
	"context"
	"fmt"
	"log"

	"github.com/Ullaakut/nmap/v3"
)

func main() {
	scanner, err := nmap.NewScanner(
		context.Background(),
		nmap.WithTargets("10.1.1.1"),
		// nmap.WithServiceInfo(),
		// nmap.WithOSDetection(),
	)
	if err != nil {
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	progress := make(chan float32, 1)

	go func() {
		for p := range progress {
			fmt.Printf("Progress: %v %%\n", p)
		}
	}()
	result, warnings, err := scanner.Progress(progress).Run()
	if len(*warnings) > 0 {
		log.Printf("run finished with warnings: %s\n", *warnings)
	}
	if err != nil {
		log.Fatalf("unable to run nmap scan: %v", err)
	}
	fmt.Printf("Nmap done: %d hosts up scanned in %.2f seconds\n", len(result.Hosts), result.Stats.Finished.Elapsed)
}
