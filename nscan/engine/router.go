package engine

import (
	"fmt"
	"net/http"
	"nscan/common/argx"
	"nscan/plugins/db"
	"nscan/utils"
	"time"

	"github.com/gin-gonic/gin"
)

func logFormat(param gin.LogFormatterParams) string {
	// your custom format
	return fmt.Sprintf(`%s [%s->%s total cost %s]
%s %s | %s %d
%s
---------------------------------------------------------------------------------------------------------------
`,
		param.TimeStamp.Format(time.DateTime),
		param.ClientIP,
		param.Request.Host,
		utils.BeautifyDuration(param.Latency),
		param.Method,
		param.Path,
		param.Request.Proto,
		param.StatusCode,
		param.Request.UserAgent(),
	)
}

func initRouter(enableManageFunc bool, addr ...string) error {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(CORSMiddleware(), gin.LoggerWithFormatter(logFormat), gin.Recovery())

	apiGroup := r.Group("/api/task")
	apiGroup.GET("/running", runningTask)
	apiGroup.GET("/pending", pendingTask)
	apiGroup.GET("/finished", finishedTask)
	apiGroup.POST("/cancel/:taskId", cancelTask)
	apiGroup.POST("/run", runTask)

	if enableManageFunc {
		if err := db.NewLocalDB("local.bin"); err != nil {
			panic(err)
		}
		defer db.CloseLocalDB()
		taskGroup := r.Group("/task")
		taskGroup.GET("/all", all)
		taskGroup.POST("/createTask", createTask)
		taskGroup.POST("/deleteTasks", delTasks)
	}
	if argx.Verbose {
		fmt.Printf("Listening and serving HTTP on %s\n", addr)
	}
	return r.Run(addr...)
}

func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

func runningTask(ctx *gin.Context) {
	var tasks []TaskStatus
	TaskPool.Range(func(key, value any) bool {
		taskId := key.(string)
		task := value.(*Task)
		if taskId != "" && task != nil && task.Active {
			tasks = append(tasks, TaskStatus{
				TaskId:   taskId,
				Progress: task.Progress,
				Status:   "running",
			})
		}
		return true
	})
	ctx.JSON(http.StatusOK, tasks)
}

func pendingTask(ctx *gin.Context) {
	var tasks []TaskStatus
	PendingTaskPool.Range(func(key, value any) bool {
		taskId := key.(string)
		task := value.(*Task)
		if taskId != "" && task != nil && !task.Active {
			tasks = append(tasks, TaskStatus{
				TaskId:   taskId,
				Progress: task.Progress,
				Status:   "pending",
			})
		}
		return true
	})
	ctx.JSON(http.StatusOK, tasks)
}

func finishedTask(ctx *gin.Context) {
	var tasks []TaskStatus
	TaskPool.Range(func(key, value any) bool {
		taskId := key.(string)
		task := value.(*Task)
		if taskId != "" && task != nil && !task.Active && task.Progress == 1 {
			tasks = append(tasks, TaskStatus{
				TaskId:   taskId,
				Progress: task.Progress,
				Status:   "finished",
			})
		}
		return true
	})
	ctx.JSON(http.StatusOK, tasks)
}

func cancelTask(ctx *gin.Context) {
	taskId := ctx.Param("taskId")
	if taskRaw, exist := TaskPool.Load(taskId); exist {
		if taskRaw != nil {
			taskRaw.(*Task).Cancel()
		}
	}
	deleteTask(taskId)
	ctx.JSON(http.StatusOK, "success")
}

func runTask(ctx *gin.Context) {
	var target Target
	if err := ctx.ShouldBindJSON(&target); err != nil {
		ctx.JSON(http.StatusOK, "Something wrong with request body")
		return
	}
	taskIdNum := maxTaskNum.Add(1)
	taskId := fmt.Sprintf("HTTP-%d", taskIdNum)
	go defaultEngine.Scan(taskId, target)
	ctx.JSON(http.StatusOK, "success")
}
