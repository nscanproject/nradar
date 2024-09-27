package common

import (
	"database/sql/driver"
	"strings"
)

type EntityBase struct {
	Id      uint64 `gorm:"column:id;PRIMARY_KEY;AUTO_INCREMENT"`
	Deleted bool   `gorm:"column:deleted;uniqueIndex"`
}

type Strs []string

func (m *Strs) Scan(val interface{}) error {
	s := val.([]uint8)
	ss := strings.Split(string(s), "|")
	*m = ss
	return nil
}

func (m Strs) Value() (driver.Value, error) {
	str := strings.Join(m, "|")
	return str, nil
}
