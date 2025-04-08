package handler

import (
	"encoding/json"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"net/http"
	"net/url"
	"oauth-server-go/oauth"
	"oauth-server-go/oauth/service"
	"oauth-server-go/protocol"
	"oauth-server-go/security"
)

const sessionKeyOriginAuthRequest = "sessions/originAuthRequest"

var (
	clientService   *service.ClientService
	scopeService    *service.ScopeService
	authCodeService *service.AuthCodeService
)

func init() {
	clientService = service.NewClientService()
	scopeService = service.NewScopeService()
	authCodeService = service.NewAuthCodeService()
}

func Routing(route *gin.Engine) {
	oauthPath := route.Group("/oauth")
	oauthPath.Use(func(c *gin.Context) {
		c.Header("Cache-Control", "no-cache")
	})

	authPath := oauthPath.Group("/authorize")
	authPath.Use(security.Authenticated(func(c *gin.Context) {
		errHandler(c, oauth.ErrAccessDenied)
	}))

	authPath.GET("", protocol.NewHTTPHandler(errHandler, authorize))
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
	if err != nil {
		return err
	}
	u, _ := url.Parse(redirect)
	if r.ResponseType == "" {
		return NewRedirectErr(oauth.NewErr(oauth.ErrInvalidRequest, "require parameter is missing"), u)
	}

	scopes, err := client.GetScopes(r.SplitScope())
	if err != nil {
		return NewRedirectErr(oauth.NewErr(err, "scope cannot grant"), u)
	}
	c.HTML(http.StatusOK, "approval.html", gin.H{
		"scopes": scopes,
		"client": client.Name,
	})
	return storeOriginRequest(c, &r)
}

func storeOriginRequest(c *gin.Context, r *oauth.AuthorizationRequest) error {
	serial, err := json.Marshal(&r)
	if err != nil {
		return err
	}
	s := sessions.Default(c)
	s.Set(sessionKeyOriginAuthRequest, serial)
	return s.Save()
}
