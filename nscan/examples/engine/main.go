package main

import (
	"nscan/engine"
	"nscan/plugins/log"
	"time"

	"github.com/gin-gonic/gin"
)

func main() {
	go func() {
		r := gin.Default()
		r.GET("/task/:taskId", func(ctx *gin.Context) {
			taskId := ctx.Param("taskId")
			taskRaw, _ := engine.TaskPool.Load(taskId)
			taskRaw.(*engine.Task).Cancel()
		})
		r.Run(":8000")
	}()
	go func() {
		for {
			time.Sleep(time.Second)
			engine.TaskPool.Range(func(key, value any) bool {
				log.Logger.Debug().Msgf("task[%v] running,progress:%f", key, value.(*engine.Task).Progress)
				return true
			})
		}
	}()
	eg := engine.Default()
	eg.Scan("1", engine.Target{
		Hosts: []string{"10.1.1.81"},
	})
}
