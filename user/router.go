package user

import (
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
	"oauth-server-go/cmm"
)

func Routing(route *gin.Engine) {
	auth := route.Group("/auth")
	auth.POST("/login", login)
}

func login(c *gin.Context) {
	var req LoginRequest

	if err := c.ShouldBindBodyWithJSON(&req); err != nil {
		handling(err, c)
		return
	}

	if result, err := Login(&req, NewBcryptHasher()); err != nil {
		handling(err, c)
	} else {
		c.JSON(http.StatusOK, result)
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
