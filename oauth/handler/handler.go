package handler

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"net/url"
	"oauth-server-go/oauth"
	"oauth-server-go/oauth/service"
	"oauth-server-go/protocol"
	"oauth-server-go/security"
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

	_, exists := c.Get(security.ShareKeyLogin)
	if !exists {
		return oauth.NewErr(oauth.ErrInvalidRequest, "login is required")
	}

	redirect, err := client.RedirectURL(r.Redirect)
	if err != nil {
		return err
	}
	u, _ := url.Parse(redirect)
	if r.ResponseType == "" {
		return NewRedirectErr(oauth.NewErr(oauth.ErrInvalidRequest, "require parameter is missing"), u)
	}

	if r.ResponseType == oauth.ResponseTypeCode {
		s := r.SplitScope()
		if len(s) == 0 {
			s = client.Scopes
		}
		c.HTML(http.StatusOK, "approval.html", gin.H{
			"scopes": s,
			"client": client.Name,
		})
	}
	return nil
}
