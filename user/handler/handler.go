package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"net/http"
	"oauth-server-go/protocol"
	"oauth-server-go/security"
	"oauth-server-go/user"
	"oauth-server-go/user/service"
)

var authService *service.AuthService

func init() {
	authService = service.NewAuthService()
}

func Routing(route *gin.Engine) {
	auth := route.Group("/auth")

	auth.POST("/login", protocol.NewHTTPHandler(login, errHandler))
}

func login(c *gin.Context) error {
	var req service.LoginRequest
	if err := c.ShouldBindBodyWithJSON(&req); err != nil {
		return err
	}
	account, err := authService.Login(&req)
	if err != nil {
		return err
	}
	l := &security.Login{Username: account.Username}
	serial, _ := json.Marshal(l)
	s := sessions.Default(c)
	s.Set(security.ShareKeyLogin, serial)
	_ = s.Save()
	c.JSON(http.StatusOK, protocol.NewOK(protocol.MsgOK))
	return nil
}

func errHandler(err error, c *gin.Context) {
	if errors.Is(err, user.ErrRequireParamsMissing) {
		c.JSON(http.StatusBadRequest, protocol.NewErr(protocol.ErrMsgBadRequest, "require parameters are missing"))
	} else if errors.Is(err, user.ErrAccountNotFound) || errors.Is(err, user.ErrPasswordNotMatch) {
		c.JSON(http.StatusBadRequest, protocol.NewErr(protocol.ErrMsgBadState, "id/password is not match"))
	} else if errors.Is(err, user.ErrAccountLocked) {
		c.JSON(http.StatusBadRequest, protocol.NewErr(protocol.ErrMsgBadState, "account is locked"))
	} else {
		fmt.Printf("%v\n", err)
		c.JSON(http.StatusInternalServerError, protocol.NewErr(protocol.ErrMsgUnknown, "internal server error"))
	}
}
