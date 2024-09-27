package engine

import (
	"context"
	"time"
)

type engine struct {
	ScanTimeout  time.Duration
	Ratelimit    uint32
	TaskParallel uint8
	ScanProxy    ScanProxy
	Options      []Option
}

type Option func()

type ScanProxy struct {
	Host string
	Port int
}

type Target struct {
	Hosts                             []string `json:"hosts"`
	Ports                             []string `json:"ports,omitempty"`
	ServiceScan, OSScan, CPEScan, POC bool
}

type Task struct {
	Target
	Active   bool
	Progress float64
	Cancel   context.CancelFunc
}

type TaskStatus struct {
	TaskId   string  `json:"taskId"`
	Progress float64 `json:"progress"`
	Status   string  `json:"status"`
}
