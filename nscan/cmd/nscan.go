package main

import (
	"fmt"
	"nscan/common/argx"
	"nscan/engine"
	"strings"

	"github.com/spf13/cobra"
)

const (
	APP_NAME = "scan"
	VER      = "V1.0.1"
)

var (
	rootCmd = &cobra.Command{
		Use:   APP_NAME,
		Short: "Scan is a fast and customizable asset and vulnerability scanner",
		Long:  "A comprehensive asset scanning tool; a highly customizable vulnerability scanner. For assets, it encompasses but is not limited to asset liveliness detection, service fingerprint information, operating systems, device types, and web information. Regarding vulnerabilities, it includes but is not limited to CPE-based vulnerabilities linked to service fingerprints and proof-of-concept (PoC) exploits.",
		Run: func(cmd *cobra.Command, args []string) {
			if argx.Target == "" {
				fmt.Println("No target specified, use -t 2 specify one. e.g: scan -t 1.1.1.1,192.168.0.0/16,10.0.0.0/8")
			} else {
				targets := strings.Split(argx.Target, ",")
				var port2Scan = strings.Split(argx.Port, ",")
				if len(port2Scan) == 0 || port2Scan[0] == "" {
					port2Scan = engine.CommonPorts
				}
				engine.Default().Scan("[SCAN]", engine.Target{
					Hosts:       targets,
					Ports:       port2Scan,
					ServiceScan: argx.ServiceScan,
					OSScan:      argx.OSScan,
					CPEScan:     argx.CPEScan,
					POC:         argx.POCScan,
				})
			}
		},
	}
	versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Show the version of " + APP_NAME,
		Long:  "Show the version of " + APP_NAME,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Scan version", VER)
		},
	}
	restCmd = &cobra.Command{
		Use:   "rest",
		Short: "Run as rest server",
		Long:  "Run as rest server, the default port is 9527",
		Run: func(cmd *cobra.Command, args []string) {
			engine.Default().Serve(false, argx.Addr)
		},
	}
)

func main() {
	// os.Args = append(os.Args, "-t", "10.1.1.1")
	rootCmd.PersistentFlags().BoolVarP(&argx.Verbose, "verbose", "v", false, "verbose output")

	rootCmd.Flags().StringVarP(&argx.Target, "target", "t", "", "designate the target 4 scan")
	rootCmd.Flags().StringVarP(&argx.Port, "port", "p", "", "designate the port 4 scan")

	restCmd.Flags().StringVarP(&argx.Addr, "bind", "b", ":9527", "serve as restful server")

	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(restCmd)
	rootCmd.Execute()
}
