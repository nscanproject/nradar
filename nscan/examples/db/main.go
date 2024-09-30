package main

import (
	"fmt"
	"nscan/engine/model/entity"
	"nscan/plugins/db"
)

func main() {
	_, f, err := db.InitGorm()
	defer f()

	if err != nil {
		panic(err)
	}
	task := entity.Task{
		//EntityBase: common.EntityBase{
		//	Id:      0,
		//	Deleted: false,
		//},
		Name:        "1",
		Description: "1",
		Status:      "1",
		StartTime:   "1",
		//EndTime:     "1",
		Target: "1",
		//Port:        "1",
	}
	if err = db.DB.Model(&task).Create(&task).Error; err != nil {
		panic(err)
	}
	fmt.Println(task)

}
