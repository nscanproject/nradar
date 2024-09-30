package common

import (
	"database/sql/driver"
	"strings"
)

type EntityBase struct {
	Id      uint64 `gorm:"primary_key;type:bigint(20) auto_increment;not null;comment:'ID';"`
	Deleted bool   `gorm:"column:deleted;index"`
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
