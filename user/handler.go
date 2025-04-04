package user

import (
	"errors"
	"fmt"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/goccy/go-json"
	"net/http"
	"oauth-server-go/conf"
	"oauth-server-go/protocol"
)

func Routing(route *gin.Engine) {
	repo := NewRepository(conf.GetDB())
	srv := NewAuthService(repo, NewBcryptHasher())

	h := NewHandler(srv)

	auth := route.Group("/auth")
	auth.POST("/login", protocol.NewHTTPHandler(h.Login, errHandler))
}

type Handler interface {
	Login(c *gin.Context) error
}

type handler struct {
	authSrv AuthService
}

func NewHandler(authSrv AuthService) Handler {
	return &handler{authSrv: authSrv}
}

func (h handler) Login(c *gin.Context) error {
	session := sessions.Default(c)
	var req LoginRequest
	if err := c.ShouldBindBodyWithJSON(&req); err != nil {
		return err
	}
	login, err := h.authSrv.Login(&req)
	if err != nil {
		return err
	}
	serial, _ := json.Marshal(login)
	session.Set("login", serial)
	_ = session.Save()
	c.JSON(http.StatusOK, protocol.NewOK(protocol.MsgOK))
	return nil
}

func errHandler(err error, c *gin.Context) {
	if errors.Is(err, ErrRequireParamsMissing) {
		c.JSON(http.StatusBadRequest, protocol.NewErr(protocol.ErrMsgBadRequest, "require parameters are missing"))
	} else if errors.Is(err, ErrAccountNotFound) || errors.Is(err, ErrPasswordNotMatch) {
		c.JSON(http.StatusBadRequest, protocol.NewErr(protocol.ErrMsgBadState, "id/password is not match"))
	} else if errors.Is(err, ErrAccountLocked) {
		c.JSON(http.StatusBadRequest, protocol.NewErr(protocol.ErrMsgBadState, "account is locked"))
	} else {
		fmt.Printf("%v\n", err)
		c.JSON(http.StatusInternalServerError, protocol.NewErr(protocol.ErrMsgUnknown, "internal server error"))
	}
}
