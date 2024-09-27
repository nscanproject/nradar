package common

import "context"

type ScanInfo struct {
	Host       []string
	Port       []string
	Ctx        context.Context
	CancelFunc context.CancelFunc
}

type Scanner interface {
	Run(ScanInfo) error
	Stop() error
}
