package user

import (
	json2 "encoding/json"
	"errors"
	"fmt"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"net/http"
	"oauth-server-go/cmm"
	"oauth-server-go/conf"
)

type Handler struct {
	srv Service
}

func NewHandler(srv Service) *Handler {
	return &Handler{srv: srv}
}

func Routing(route *gin.Engine) {
	repo := NewRepository(conf.GetDB())
	srv := NewService(repo, NewBcryptHasher())

	handler := NewHandler(srv)

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

	if login, err := h.srv.Login(&req); err == nil {
		json, _ := json2.Marshal(login)

		session.Set("login", json)
		_ = session.Save()

		c.JSON(http.StatusOK, cmm.NewOK(cmm.MsgOK))
	} else {
		handling(err, c)
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
