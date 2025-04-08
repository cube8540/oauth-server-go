package handler

import (
	"errors"
	"fmt"
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

	auth.GET("/login", protocol.NewHTTPHandler(errHandler, loginPage))
	auth.POST("/login", protocol.NewHTTPHandler(errHandler, login))
}

func loginPage(c *gin.Context) error {
	c.HTML(http.StatusOK, "login.html", gin.H{})
	return nil
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
	sl := &security.SessionLogin{Username: account.Username}
	err = security.StoreLogin(c, sl)
	if err != nil {
		return err
	}
	c.JSON(http.StatusOK, protocol.NewOK(protocol.MsgOK))
	return nil
}

func errHandler(c *gin.Context, err error) {
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
