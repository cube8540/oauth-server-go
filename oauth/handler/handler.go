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
	"strings"
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
	authPath.POST("", protocol.NewHTTPHandler(errHandler, approval))
}

func authorize(c *gin.Context) error {
	var r oauth.AuthorizationRequest
	if err := c.ShouldBindQuery(&r); err != nil {
		return err
	}

	if r.ClientID == "" {
		return oauth.NewErr(oauth.ErrInvalidRequest, "client id is required")
	}
	client, err := clientService.GetClient(r.ClientID)
	if err != nil {
		return oauth.NewErr(err, "unknown error")
	}
	if client == nil {
		return oauth.NewErr(oauth.ErrUnauthorizedClient, "client is not found")
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

func approval(c *gin.Context) error {
	origin, err := getOriginRequest(c)
	if err != nil {
		return err
	}
	if origin == nil {
		return oauth.NewErr(oauth.ErrInvalidRequest, "origin request is not found")
	}
	client, err := clientService.GetClient(origin.ClientID)
	if err != nil {
		return oauth.NewErr(err, "unknown error")
	}
	if client == nil {
		return oauth.NewErr(oauth.ErrUnauthorizedClient, "client is not found")
	}

	redirect, _ := client.RedirectURL(origin.Redirect)
	u, _ := url.Parse(redirect)

	rs := c.PostFormArray("scope")
	if len(rs) == 0 {
		return NewRedirectErr(oauth.NewErr(oauth.ErrInvalidScope, "scope not selected"), u)
	}
	loginValue, _ := c.Get(security.SessionKeyLogin)
	if login, ok := loginValue.(*security.SessionLogin); ok {
		origin.Username = login.Username
	}
	origin.Scopes = strings.Join(rs, " ")

	var enhancer Enhancer
	var src any
	if origin.ResponseType == oauth.ResponseTypeCode {
		src, err = authCodeService.New(client, origin)
		if err != nil {
			return NewRedirectErr(oauth.NewErr(err, "error occurred during code generate"), u)
		}
		enhancer = chaining(authorizationCodeFlow)
	}
	err = enhancer(src, u)
	if err != nil {
		return NewRedirectErr(oauth.NewErr(err, "error occurred during code generate"), u)
	}
	c.Redirect(http.StatusMovedPermanently, u.String())
	return clearOriginRequest(c)
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

func getOriginRequest(c *gin.Context) (*oauth.AuthorizationRequest, error) {
	s := sessions.Default(c)
	v := s.Get(sessionKeyOriginAuthRequest)
	if rb, ok := v.([]byte); ok {
		var r oauth.AuthorizationRequest
		err := json.Unmarshal(rb, &r)
		return &r, err
	}
	return nil, nil
}

func clearOriginRequest(c *gin.Context) error {
	s := sessions.Default(c)
	s.Delete(sessionKeyOriginAuthRequest)
	return s.Save()
}
