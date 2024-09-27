package main

import (
	"fmt"
	"nscan/examples/ipgeo/qqwry/model"
	"os"
	"strings"

	"github.com/malfunkt/iprange"
	"github.com/xiaoqidun/qqwry"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

//

func main() {
	db := getDBConn()
	save2DB(db)
	// qIP("1.12.184.146")
}

func qIP(ip string) {
	err := qqwry.LoadFile("qqwry.dat")
	if err != nil {
		panic(err)
	}
	// qqwry.LoadData(QQwryBuf)
	res, err := qqwry.QueryIP(ip)
	if err != nil {
		panic(err)
	}
	fmt.Println(res)
}

func getDBConn() *gorm.DB {
	dsn := "root:yuan@info@tcp(10.1.2.217:3306)/awdb?charset=utf8mb4&parseTime=True&loc=Local"
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		panic(err)
	}
	return db
	// var t model.TAwdb
	// err = db.Model(&t).First(&t).Error
	// if err != nil {
	// 	panic(err)
	// }
}

func save2DB(db *gorm.DB) {
	err := qqwry.LoadFile("qqwry.dat")
	if err != nil {
		panic(err)
	}
	// qqwry.LoadData(QQwryBuf)
	CidrBuf, err := os.ReadFile("cidr.txt")
	if err != nil {
		panic(err)
	}
	splits := strings.Split(string(CidrBuf), "\n")

	for i1, cidr := range splits {
		ips, err := iprange.ParseList(cidr)
		if err != nil {
			continue
		}
		var awdbs []model.TAwdb
		for _, ip := range ips.Expand() {
			res, err := qqwry.QueryIP(ip.String())
			if err != nil {
				continue
			}
			var awdb model.TAwdb
			awdb.Country = res.Country
			awdb.City = res.City
			awdb.District = res.District
			awdb.IP = res.IP
			awdb.ISP = res.ISP
			awdb.Province = res.Province
			// err = db.Model(&model.TAwdb{}).Create(&awdb).Error
			// if err != nil {
			// 	fmt.Printf("[%v] insert into db failed[%v]\n", awdb, err)
			// } else {
			// 	fmt.Printf("[%v] insert into db successfully\n", awdb)
			// }
			awdbs = append(awdbs, awdb)
		}
		awdbsGroup := GroupStrsBySize(awdbs, 1000)
		for index, group := range awdbsGroup {
			err := db.Model(&model.TAwdb{}).CreateInBatches(&group, len(group)).Error
			if err != nil {
				fmt.Printf("[%v] insert into db failed[%v]\n", index, err)
			} else {
				fmt.Printf("[%v] insert into db successfully\n", index)
			}
		}
		fmt.Println("current progress:", (float64(i1+1) / float64(len(splits))))
	}
}

func GroupStrsBySize(rawHosts []model.TAwdb, maxSize int) (finalHostGroups [][]model.TAwdb) {
	numGroups := len(rawHosts) / maxSize
	if len(rawHosts)%maxSize != 0 {
		numGroups++
	}

	finalHostGroups = make([][]model.TAwdb, numGroups)

	for i := 0; i < numGroups-1; i++ {
		finalHostGroups[i] = rawHosts[i*maxSize : (i+1)*maxSize]
	}

	finalHostGroups[numGroups-1] = rawHosts[(numGroups-1)*maxSize:]

	return
}
