package handler

import (
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
	"oauth-server-go/conf"
	"oauth-server-go/crypto"
	"oauth-server-go/protocol"
	"oauth-server-go/security"
	"oauth-server-go/user"
	"oauth-server-go/user/entity"
	"oauth-server-go/user/model"
	"oauth-server-go/user/repository"
	"oauth-server-go/user/service"
)

type h struct {
	authentication func(r *model.Login) (*entity.Account, error)
}

func Routing(route *gin.Engine) {
	accountRepository := repository.NewAccountRepository(conf.GetDB())
	authService := service.NewAuthService(accountRepository, crypto.NewBcryptHasher())

	h := h{
		authentication: authService.Login,
	}

	auth := route.Group("/auth")
	auth.GET("/login", protocol.NewHTTPHandler(errHandle, h.loginPage))
	auth.POST("/login", protocol.NewHTTPHandler(errHandle, h.login))
}

func (h h) loginPage(c *gin.Context) error {
	c.HTML(http.StatusOK, "login.html", gin.H{})
	return nil
}

func (h h) login(c *gin.Context) error {
	var req model.Login
	if err := c.ShouldBindBodyWithJSON(&req); err != nil {
		return err
	}
	account, err := h.authentication(&req)
	if err != nil {
		return err
	}
	sl := &security.SessionLogin{Username: account.Username}
	if err = security.StoreLogin(c, sl); err != nil {
		return err
	}
	c.JSON(http.StatusOK, protocol.NewOK(protocol.MsgOK))
	return nil
}

func errHandle(c *gin.Context, err error) {
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
