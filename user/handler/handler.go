package handler

import (
	"errors"
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
	auth.GET("/login", protocol.NewHTTPHandler(h.loginPage))
	auth.POST("/login", protocol.NewHTTPHandler(h.login))
}

func (h h) loginPage(c *gin.Context) error {
	c.HTML(http.StatusOK, "login.html", gin.H{})
	return nil
}

func (h h) login(c *gin.Context) error {
	var req model.Login
	if err := c.ShouldBindBodyWithJSON(&req); err != nil {
		return wrap(err)
	}
	account, err := h.authentication(&req)
	if err != nil {
		return wrap(err)
	}
	sl := &security.SessionLogin{Username: account.Username}
	if err = security.StoreLogin(c, sl); err != nil {
		return wrap(err)
	}
	c.JSON(http.StatusOK, protocol.NewOK(protocol.MsgOK))
	return nil
}

func wrap(err error) error {
	if errors.Is(err, user.ErrRequireParamsMissing) {
		return protocol.Wrap(err, protocol.ErrCodeBadRequest, "require parameter is missing")
	} else if errors.Is(err, user.ErrAccountNotFound) || errors.Is(err, user.ErrPasswordNotMatch) {
		return protocol.Wrap(err, protocol.ErrCodeBadRequest, "id/password is not matched")
	} else if errors.Is(err, user.ErrAccountLocked) {
		return protocol.Wrap(err, protocol.ErrCodeBadRequest, "account is locked")
	} else {
		return protocol.Wrap(err, protocol.ErrCodeUnknown, "internal server error")
	}
}
