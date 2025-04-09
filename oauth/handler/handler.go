package handler

import (
	"encoding/json"
	"fmt"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"net/http"
	"net/url"
	"oauth-server-go/oauth"
	"oauth-server-go/oauth/entity"
	"oauth-server-go/oauth/service"
	"oauth-server-go/protocol"
	"oauth-server-go/security"
	"strings"
	"time"
)

const sessionKeyOriginAuthRequest = "sessions/originAuthRequest"

var (
	clientService     *service.ClientService
	authCodeService   *service.AuthCodeService
	tokenIssueService *service.TokenIssueService
)

func init() {
	clientService = service.NewClientService()
	authCodeService = service.NewAuthCodeService()
	tokenIssueService = service.NewTokenIssueService()
}

func Routing(route *gin.Engine) {
	oauthPath := route.Group("/oauth")
	oauthPath.Use(func(c *gin.Context) {
		c.Header("Cache-Control", "no-cache")
	})

	authPath := oauthPath.Group("/authorize")
	authPath.Use(security.Authenticated(func(c *gin.Context) {
		errHandle(c, oauth.NewErr(oauth.ErrAccessDenied, "resource owner login is required"))
	}))
	authPath.GET("", protocol.NewHTTPHandler(errHandle, authorize))
	authPath.POST("", protocol.NewHTTPHandler(errHandle, approval))

	tokenPath := oauthPath.Group("/token")
	tokenPath.Use(clientBasicAuthManage(clientService.Auth, errHandle))
	tokenPath.Use(clientFormAuthManage(clientService.Auth, errHandle))
	tokenPath.Use(func(c *gin.Context) {
		_, exists := c.Get(oauth2ShareKeyAuthClient)
		if !exists {
			errHandle(c, oauth.NewErr(oauth.ErrUnauthorizedClient, "client auth is required"))
			c.Abort()
		}
		c.Next()
	})
	tokenPath.POST("", protocol.NewHTTPHandler(errHandle, tokenIssue))
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
		return err
	}

	redirect, err := client.RedirectURL(r.Redirect)
	if err != nil {
		return err
	}
	to, _ := url.Parse(redirect)
	if r.ResponseType == "" {
		return routeWrap(oauth.NewErr(oauth.ErrInvalidRequest, "require parameter is missing"), &r, to)
	}
	if r.ResponseType != oauth.ResponseTypeCode && r.ResponseType != oauth.ResponseTypeToken {
		return routeWrap(oauth.NewErr(oauth.ErrUnsupportedGrantType, "unsupported grant type"), &r, to)
	}

	scopes, err := client.GetScopes(r.SplitScope())
	if err != nil {
		return routeWrap(err, &r, to)
	}
	c.HTML(http.StatusOK, "approval.html", gin.H{
		"scopes": scopes,
		"client": client.Name,
	})
	s := sessions.Default(c)
	return storeOriginRequest(s, &r)
}

func approval(c *gin.Context) error {
	s := sessions.Default(c)
	origin, err := getOriginRequest(s)
	if err != nil {
		return err
	}
	if origin == nil {
		return oauth.NewErr(oauth.ErrInvalidRequest, "origin request is not found")
	}
	client, err := clientService.GetClient(origin.ClientID)
	if err != nil {
		fmt.Printf("%v", err)
		return oauth.NewErr(oauth.ErrServerError, "unknown error")
	}

	redirect, _ := client.RedirectURL(origin.Redirect)
	to, _ := url.Parse(redirect)

	loginValue, _ := c.Get(security.SessionKeyLogin)
	if login, ok := loginValue.(*security.SessionLogin); ok {
		origin.Username = login.Username
	}

	rs := c.PostFormArray("scope")
	if len(rs) == 0 {
		return routeWrap(oauth.NewErr(oauth.ErrInvalidScope, "resource owner denied access"), origin, to)
	}
	origin.Scopes = strings.Join(rs, " ")

	var src any
	if origin.ResponseType == oauth.ResponseTypeCode {
		if src, err = authCodeService.New(client, origin); err != nil {
			return routeWrap(err, origin, to)
		}
	}

	enhancer := chaining(authorizationCodeFlow)
	if err = enhancer(origin, src, to); err != nil {
		return routeWrap(err, origin, to)
	}

	c.Redirect(http.StatusMovedPermanently, to.String())
	return clearOriginRequest(s)
}

func tokenIssue(c *gin.Context) error {
	var r oauth.TokenRequest
	err := c.Bind(&r)
	if err != nil {
		return err
	}

	clientValue, _ := c.Get(oauth2ShareKeyAuthClient)
	client, _ := clientValue.(*entity.Client)

	var token *entity.Token
	var refresh *entity.RefreshToken
	switch r.GrantType {
	case oauth.GrantTypeAuthorizationCode:
		token, refresh, err = tokenIssueService.AuthorizationCodeFlow(client, &r)
		if err != nil {
			return err
		}
	default:
		return oauth.NewErr(oauth.ErrUnsupportedGrantType, "unsupported")
	}
	if token == nil {
		return oauth.NewErr(oauth.ErrServerError, "token cannot issued")
	}
	var scopes []string
	for _, s := range token.Scopes {
		scopes = append(scopes, s.Code)
	}
	res := oauth.TokenResponse{
		Token:     token.Value,
		Type:      oauth.TokenTypeBearer,
		ExpiresIn: uint(token.ExpiredAt.Sub(time.Now()) / time.Second),
		Scope:     strings.Join(scopes, " "),
	}
	if refresh != nil {
		res.Refresh = refresh.Value
	}
	c.JSON(http.StatusOK, res)
	return nil
}

func storeOriginRequest(s sessions.Session, r *oauth.AuthorizationRequest) error {
	serial, err := json.Marshal(&r)
	if err != nil {
		return err
	}
	s.Set(sessionKeyOriginAuthRequest, serial)
	return s.Save()
}

func getOriginRequest(s sessions.Session) (*oauth.AuthorizationRequest, error) {
	v := s.Get(sessionKeyOriginAuthRequest)
	if rb, ok := v.([]byte); ok {
		var r oauth.AuthorizationRequest
		err := json.Unmarshal(rb, &r)
		return &r, err
	}
	return nil, nil
}

func clearOriginRequest(s sessions.Session) error {
	s.Delete(sessionKeyOriginAuthRequest)
	return s.Save()
}
