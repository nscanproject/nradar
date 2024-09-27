package db

import (
	"fmt"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/schema"
)

var (
	//todo: config
	DB  *gorm.DB
	dsn = "host=10.1.30.166 port=5432 user=root dbname=postgres password=root"
)

type DBOption func()

func InitGorm(opts ...DBOption) (*gorm.DB, func(), error) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("db init error:%+v\n", r)
		}
	}()
	for _, opt := range opts {
		opt()
	}
	var cleanFunc func()
	var dialector = postgres.Open(dsn)
	db, err := gorm.Open(dialector, &gorm.Config{
		NamingStrategy: schema.NamingStrategy{
			TablePrefix:   "t_",
			SingularTable: true,
		},
		Logger: logger.Default.LogMode(logger.Warn),
	})
	if err != nil {
		return nil, cleanFunc, err
	}
	DB = db
	sqlDB, err := db.DB()
	if err != nil {
		return nil, cleanFunc, err
	}
	cleanFunc = func() {
		sqlDB.Close()
	}
	sqlDB.SetMaxIdleConns(128)
	sqlDB.SetMaxOpenConns(64)
	sqlDB.SetConnMaxLifetime(60 * time.Second)
	return db, cleanFunc, nil
}

func MonitorDB() {
	for {
		if DB == nil {
			fmt.Printf("db is nil,reconection will start\n")
			InitGorm()
		}
		time.Sleep(time.Millisecond * 500)
	}
}
