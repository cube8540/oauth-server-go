package handler

import (
	"github.com/gin-gonic/gin"
	"oauth-server-go/oauth"
	"oauth-server-go/protocol"
)

func Routing(route *gin.Engine) {
	auth := route.Group("/oauth")

	auth.GET("/authorize", protocol.NewHTTPHandler(authorize, errHandler))
}

func authorize(c *gin.Context) error {
	var r oauth.AuthorizationRequest
	if err := c.ShouldBindQuery(&r); err != nil {
		return err
	}
	if r.ClientID == "" {
		return oauth.NewInvalidErr("client id is required")
	}
	if r.ResponseType == "" {
		return NewRedirectErr(oauth.NewInvalidErr("require parameter is missing"), "http://localhost:7070")
	}
	return nil
}
