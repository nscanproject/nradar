package entity

import (
	"nscan/engine/model/entity/common"
)

type Task struct {
	common.EntityBase
	Name        string `gorm:"column:name;index"`
	Description string
	Status      string
	StartTime   string `gorm:"column:start_time"`
	EndTime     string `gorm:"column:end_time"`
	Target      string
	Port        string
}

type TaskRecord struct {
	common.EntityBase
	TaskId    uint64  `gorm:"column:task_id;index"`
	ScanInfo  string  `gorm:"column:scan_info"`
	StartTime string  `gorm:"column:start_time"`
	EndTime   string  `gorm:"column:end_time"`
	Progress  float64 `gorm:"column:progress"`
	OSName    string
}

type Address struct {
	common.EntityBase
	TaskId   uint64 `gorm:"column:task_id;index"`
	RecordId uint64 `gorm:"column:record_id;uniqueIndex"`
	Addr     string `gorm:"column:addr"`
	AddrType string `gorm:"column:addr_type"`
	Vendor   string `gorm:"column:vendor"`
}

type PortInfo struct {
	common.EntityBase
	TaskId                                                          uint64 `gorm:"column:task_id;index"`
	RecordId                                                        uint64 `gorm:"column:record_id;uniqueIndex"`
	Port                                                            uint16 `gorm:"column:port"`
	Open                                                            bool
	Product, Service, Version, Method, Url, Finger, Tag, ScreenShot string
	CPE                                                             common.Strs
	CVE                                                             common.Strs
}
