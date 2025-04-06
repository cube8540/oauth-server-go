package handler

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"net/url"
	"oauth-server-go/oauth"
	"oauth-server-go/oauth/service"
	"oauth-server-go/protocol"
)

var clientService *service.ClientService
var authCodeService *service.AuthCodeService

func init() {
	clientService = service.NewClientService()
	authCodeService = service.NewAuthCodeService()
}

func Routing(route *gin.Engine) {
	auth := route.Group("/oauth")

	auth.Use(noCache)
	auth.GET("/authorize", protocol.NewHTTPHandler(authorize, errHandler))
}

func noCache(c *gin.Context) {
	c.Header("Cache-Control", "no-cache")
}

func authorize(c *gin.Context) error {
	var r oauth.AuthorizationRequest
	if err := c.ShouldBindQuery(&r); err != nil {
		return err
	}

	if r.ClientID == "" {
		return oauth.NewErr(oauth.ErrInvalidRequest, "client id is required")
	}
	client := clientService.GetClient(r.ClientID)
	if client == nil {
		return oauth.NewErr(oauth.ErrUnauthorizedClient, "client cannot find")
	}

	redirect, err := client.RedirectURL(r.Redirect)
	u, _ := url.Parse(redirect)
	if err != nil {
		return err
	}
	if r.ResponseType == "" {
		return NewRedirectErr(oauth.NewErr(oauth.ErrInvalidRequest, "require parameter is missing"), u)
	}

	if r.ResponseType == oauth.ResponseTypeCode {
		code, err := authCodeService.New(client, &r)
		if err != nil {
			return NewRedirectErr(oauth.NewErr(err, "error occurred code generate"), u)
		}
		err = chaining([]Enhancer{authorizationCodeFlow})(code, u)
		if err != nil {
			return NewRedirectErr(oauth.NewErr(err, "error occurred response enhancer"), u)
		}
		c.Redirect(http.StatusMovedPermanently, u.String())
	}
	return nil
}
