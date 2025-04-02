package user

import (
	json2 "encoding/json"
	"errors"
	"fmt"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"net/http"
	"oauth-server-go/cmm"
)

type Handler struct {
	service Service
}

func Routing(route *gin.Engine) {
	handler := Handler{service: NewDefaultService()}

	auth := route.Group("/auth")
	auth.POST("/login", handler.handleLogin)
}

func (h Handler) handleLogin(c *gin.Context) {
	session := sessions.Default(c)

	var req LoginRequest
	if err := c.ShouldBindBodyWithJSON(&req); err != nil {
		handling(err, c)
		return
	}

	if loginModel, err := h.service.Login(&req); err != nil {
		handling(err, c)
	} else {
		json, _ := json2.Marshal(loginModel)

		session.Set("login", json)
		_ = session.Save()

		c.JSON(http.StatusOK, cmm.NewOK(cmm.MsgOK))
	}
}

func handling(err error, c *gin.Context) {
	if errors.Is(err, ErrRequireParamsMissing) {
		c.JSON(http.StatusBadRequest, cmm.NewErr(cmm.ErrMsgBadRequest, "require parameters are missing"))
	} else if errors.Is(err, ErrAccountNotFound) || errors.Is(err, ErrPasswordNotMatch) {
		c.JSON(http.StatusBadRequest, cmm.NewErr(cmm.ErrMsgBadState, "id/password is not match"))
	} else if errors.Is(err, ErrAccountLocked) {
		c.JSON(http.StatusBadRequest, cmm.NewErr(cmm.ErrMsgBadState, "account is locked"))
	} else {
		fmt.Printf("%v\n", err)
		c.JSON(http.StatusInternalServerError, cmm.NewErr(cmm.ErrMsgUnknown, "internal server error"))
	}
}
