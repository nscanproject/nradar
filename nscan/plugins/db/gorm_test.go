package db

import (
	"testing"
)

func TestInitGorm(t *testing.T) {
	_, f, err := InitGorm()
	if err != nil {
		panic(err)
	}
	defer f()
	t.Logf("gorm init success\n")
}
