package engine

import (
	"encoding/json"
	"fmt"
	"github.com/cockroachdb/pebble"
	"github.com/gin-gonic/gin"
	"net/http"
	"nscan/engine/model"
	"nscan/plugins/db"
	"strconv"
	"sync"
	"sync/atomic"
)

const (
	CREATE_TASK_KET = "#CREATE_TASK_KEY"

	STATUS_NOT_START = iota - 1
	STATUS_RUNNING
	STATUS_FINISHED
)

var (
	taskId = atomic.Uint64{}
)

func init() {
	var maxTaskId uint64
	if db.Local != nil {
		iter, _ := db.Local.NewIter(nil)
		for iter.First(); iter.Valid(); iter.Next() {
			if buf, err := iter.ValueAndErr(); err != nil {
				fmt.Println("db local get error", err)
				continue
			} else {
				var task model.Task
				if err := json.Unmarshal(buf, &task); err != nil {
					fmt.Println("unmarshal error", err)
					continue
				}
				if task.Id == "" {
					continue
				}
				num, _ := strconv.ParseUint(task.Id, 10, 64)
				if num > maxTaskId {
					maxTaskId = num
				}
			}
		}
	}
	taskId.Store(maxTaskId)
}

func createTask(ctx *gin.Context) {
	var lock sync.Mutex
	lock.Lock()
	defer lock.Unlock()
	var t model.Task
	if err := ctx.ShouldBindJSON(&t); err != nil {
		ctx.JSON(http.StatusOK, model.Result{
			Code: http.StatusBadRequest,
			Msg:  "wrong protocol struct, refuse 2 handle",
		})
		return
	}
	taskId.Add(1)
	t.Id = fmt.Sprintf("%d", taskId.Load())
	t.Status = STATUS_NOT_START
	buf, err := json.Marshal(t)
	if err != nil {
		ctx.JSON(http.StatusOK, model.Result{
			Code: http.StatusInternalServerError,
			Msg:  err.Error(),
		})
		return
	}
	if err := db.Local.Set([]byte(CREATE_TASK_KET+t.Id), buf, pebble.Sync); err != nil {
		ctx.JSON(http.StatusOK, model.Result{
			Code: http.StatusInternalServerError,
			Msg:  err.Error(),
		})
		return
	}
	ctx.JSON(http.StatusOK, model.Result{
		Code: 200,
		Msg:  "success",
	})
}

func delTasks(ctx *gin.Context) {
	var ids []string
	if err := ctx.ShouldBindJSON(&ids); err != nil {
		ctx.JSON(http.StatusOK, model.Result{
			Code: http.StatusBadRequest,
			Msg:  err.Error(),
		})
		return
	}
	batch := db.Local.NewBatchWithSize(len(ids))
	for _, id := range ids {
		key := CREATE_TASK_KET + id
		if err := batch.Delete([]byte(key), pebble.Sync); err != nil {
			fmt.Printf("delete %s error:%+v\n", key, err)
			ctx.JSON(http.StatusOK, model.Result{
				Code: http.StatusInternalServerError,
				Msg:  err.Error(),
			})
			return
		}
	}
	batch.Commit(pebble.Sync)
	ctx.JSON(http.StatusOK, model.Result{
		Code: http.StatusOK,
		Msg:  "success",
	})
}

func all(ctx *gin.Context) {
	var lock sync.RWMutex
	lock.RLock()
	defer lock.RUnlock()
	var tasks []model.Task
	if iter, err := db.Local.NewIter(nil); err != nil {
		fmt.Println("db local iter error", err)
		ctx.JSON(http.StatusOK, model.Result{
			Code: http.StatusInternalServerError,
			Msg:  err.Error(),
		})
		return
	} else {
		defer iter.Close()
		for iter.First(); iter.Valid(); iter.Next() {
			if buf, err := iter.ValueAndErr(); err != nil {
				fmt.Println("db local get error", err)
				continue
			} else {
				var task model.Task
				if err := json.Unmarshal(buf, &task); err != nil {
					fmt.Println("unmarshal error", err)
					continue
				}
				if task.Name != "" {
					tasks = append(tasks, task)
				}
			}
		}
	}
	ctx.JSON(http.StatusOK, model.Result{
		Code: http.StatusOK,
		Msg:  "success",
		Data: tasks,
	})

}
