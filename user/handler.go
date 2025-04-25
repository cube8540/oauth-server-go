package user

import (
	"errors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"net/http"
	"oauth-server-go/crypto"
	"oauth-server-go/protocol"
	"oauth-server-go/security"
)

type h struct {
	authentication func(r *Login) (*Account, error)
}

func Routing(route *gin.Engine, db *gorm.DB) {
	repository := NewRepository(db)
	service := NewService(repository, crypto.NewBcryptHasher())

	h := h{
		authentication: service.Login,
	}

	auth := route.Group("/auth")
	auth.GET("/login", protocol.NewHTTPHandler(h.loginPage))
	auth.POST("/login", protocol.NewHTTPHandler(h.login))
}

func (h h) loginPage(c *gin.Context) error {
	c.HTML(http.StatusOK, "login.html", nil)
	return nil
}

func (h h) login(c *gin.Context) error {
	var req Login
	if err := c.ShouldBindBodyWithJSON(&req); err != nil {
		return wrap(err)
	}
	account, err := h.authentication(&req)
	if err != nil {
		return wrap(err)
	}
	login := &security.Login{Username: account.Username}
	if err = security.Retrieve(c).Set(login); err != nil {
		return wrap(err)
	}
	c.JSON(http.StatusOK, protocol.NewOK(protocol.MsgOK))
	return nil
}

func wrap(err error) error {
	if errors.Is(err, ErrRequireParamsMissing) {
		return protocol.Wrap(err, protocol.ErrCodeBadRequest, "require parameter is missing")
	} else if errors.Is(err, ErrAccountNotFound) || errors.Is(err, ErrPasswordNotMatch) {
		return protocol.Wrap(err, protocol.ErrCodeBadRequest, "id/password is not matched")
	} else if errors.Is(err, ErrAccountLocked) {
		return protocol.Wrap(err, protocol.ErrCodeBadRequest, "account is locked")
	} else {
		return protocol.Wrap(err, protocol.ErrCodeUnknown, "internal server error")
	}
}
