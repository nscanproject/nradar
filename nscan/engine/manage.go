package engine

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
	"nscan/engine/model"
	"nscan/engine/model/entity"
	"nscan/plugins/db"
	"nscan/plugins/log"
	"nscan/utils"
	"sync"
	"sync/atomic"
	"time"
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
	t.Status = STATUS_NOT_START
	var taskEntity, _ = buildTaskEntityFromTask(t)
	if err := db.DB.Model(&entity.Task{}).Create(&taskEntity).Error; err != nil {
		ctx.JSON(http.StatusOK, model.Result{
			Code: http.StatusInternalServerError,
			Msg:  err.Error(),
		})
		return
	}
	//if err := db.Local.Set([]byte(CREATE_TASK_KET+t.Id), buf, pebble.Sync); err != nil {
	//
	//}
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
	db.DB.Begin()
	err1 := db.DB.Model(&entity.Task{}).Where("id in (?)", ids).Update("deleted", true).Error
	err2 := db.DB.Model(&entity.TaskRecord{}).Where("task_id in (?)", ids).Update("deleted", true).Error
	err3 := db.DB.Model(&entity.PortInfo{}).Where("task_id in (?)", ids).Update("deleted", true).Error
	err4 := db.DB.Model(&entity.Address{}).Where("task_id in (?)", ids).Update("deleted", true).Error
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		log.Logger.Error().Msgf("del tasks[task,record,portInfo,address] errors:%+v,%+v,%+v,%+v\n", err1, err2, err3, err4)
		db.DB.Rollback()
		ctx.JSON(http.StatusOK, model.Result{
			Code: http.StatusInternalServerError,
			Msg:  fmt.Sprintf("delete task ids[%+v] with error", ids),
		})
		return
	} else {
		db.DB.Commit()
	}
	//batch := db.Local.NewBatchWithSize(len(ids))
	//for _, id := range ids {
	//	key := CREATE_TASK_KET + id
	//	if err := batch.Delete([]byte(key), pebble.Sync); err != nil {
	//		fmt.Printf("delete %s error:%+v\n", key, err)
	//		ctx.JSON(http.StatusOK, model.Result{
	//			Code: http.StatusInternalServerError,
	//			Msg:  err.Error(),
	//		})
	//		return
	//	}
	//}
	//batch.Commit(pebble.Sync)
	ctx.JSON(http.StatusOK, model.Result{
		Code: http.StatusOK,
		Msg:  "success",
	})
}

func all(ctx *gin.Context) {
	var tasks []model.Task
	var taskEntities []entity.Task
	if err := db.DB.Model(&entity.Task{}).Where("deleted = ?", false).Find(&taskEntities).Error; err != nil {
		ctx.JSON(http.StatusOK, model.Result{
			Code: http.StatusInternalServerError,
			Msg:  err.Error(),
			Data: tasks,
		})
	}
	for _, taskEntity := range taskEntities {
		if task, succ := buildTaskEntityFromTask(taskEntity); succ {
			tasks = append(tasks, task.(model.Task))
		}
	}
	ctx.JSON(http.StatusOK, model.Result{
		Code: http.StatusOK,
		Msg:  "success",
		Data: tasks,
	})
}

func allNames(ctx *gin.Context) {
	var tasks []string
	if err := db.DB.Model(&entity.Task{}).Select("name").Where("deleted = ?", false).Scan(&tasks).Error; err != nil {
		ctx.JSON(http.StatusOK, model.Result{
			Code: http.StatusInternalServerError,
			Msg:  err.Error(),
			Data: tasks,
		})
	}
	ctx.JSON(http.StatusOK, model.Result{
		Code: http.StatusOK,
		Msg:  "success",
		Data: tasks,
	})
}

func buildTaskEntityFromTask(t1 any) (t2 any, succ bool) {
	if tm, ok := t1.(model.Task); ok {
		t2 = entity.Task{
			Name:        tm.Name,
			Description: tm.Description,
			Status:      STATUS_NOT_START,
			StartTime:   utils.FormatTime(time.Now()),
			Target:      tm.Target,
			Port:        "",
		}
		succ = true
	} else if te, ok := t1.(entity.Task); ok {
		t2 = model.Task{
			Id:          te.Id,
			Name:        te.Name,
			Target:      te.Target,
			Description: te.Description,
			Status:      te.Status,
			Tags:        nil,
			ScreenShot:  "",
		}
		succ = true
	}
	return
}
