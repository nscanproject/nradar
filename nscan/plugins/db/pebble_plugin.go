package db

import "github.com/cockroachdb/pebble"

var Local *pebble.DB

func NewLocalDB(dbName string) (err error) {
	if Local, err = pebble.Open(dbName, &pebble.Options{}); err != nil {
		return
	}
	return
}

func CloseLocalDB() {
	if Local != nil {
		Local.Close()
	}
}
