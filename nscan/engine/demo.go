package engine

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"nscan/engine/model"
)

func getInfo(ctx *gin.Context) {
	ctx.JSON(http.StatusOK, model.Result{
		Code: 200,
		Msg:  "success",
		Data: "Go home",
	})
}
