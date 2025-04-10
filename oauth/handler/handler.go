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
	"oauth-server-go/security"
	"strings"
	"time"
)

const sessionKeyOriginAuthRequest = "sessions/originAuthRequest"

type (
	ClientAuthenticationProvider interface {
		Auth(id, secret string) (*entity.Client, error)
	}
	ClientRetriever interface {
		GetClient(id string) (*entity.Client, error)
	}
	AuthorizationRequestConsumer interface {
		Consume(c *entity.Client, request *oauth.AuthorizationRequest) (any, error)
	}
	TokenIssuer interface {
		Generate(c *entity.Client, r *oauth.TokenRequest) (*entity.Token, *entity.RefreshToken, error)
	}
)

type Handler interface {
	authorize(c *gin.Context) error
	approval(c *gin.Context) error
	issueToken(c *gin.Context) error
}

type h struct {
	clientAuthenticationProvider ClientAuthenticationProvider
	clientRetriever              ClientRetriever
	requestConsumer              AuthorizationRequestConsumer
	tokenIssuer                  TokenIssuer
}

func (h h) authorize(c *gin.Context) error {
	var r oauth.AuthorizationRequest
	if err := c.ShouldBindQuery(&r); err != nil {
		return err
	}
	if r.ClientID == "" {
		return oauth.NewErr(oauth.ErrInvalidRequest, "client id is required")
	}

	client, err := h.clientRetriever.GetClient(r.ClientID)
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
		return routeWrap(oauth.NewErr(oauth.ErrUnsupportedResponseType, "unsupported"), &r, to)
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

func (h h) approval(c *gin.Context) error {
	s := sessions.Default(c)
	origin, err := getOriginRequest(s)
	if err != nil {
		return err
	}
	if origin == nil {
		return oauth.NewErr(oauth.ErrInvalidRequest, "origin request is not found")
	}
	client, err := h.clientRetriever.GetClient(origin.ClientID)
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

	src, err := h.requestConsumer.Consume(client, origin)
	if err != nil {
		return routeWrap(err, origin, to)
	}

	enhancer := chaining(authorizationCodeFlow)
	if err = enhancer(origin, src, to); err != nil {
		return routeWrap(err, origin, to)
	}

	c.Redirect(http.StatusMovedPermanently, to.String())
	return clearOriginRequest(s)
}

func (h h) issueToken(c *gin.Context) error {
	var r oauth.TokenRequest
	err := c.Bind(&r)
	if err != nil {
		return err
	}
	clientValue, _ := c.Get(oauth2ShareKeyAuthClient)
	token, refresh, err := h.tokenIssuer.Generate(clientValue.(*entity.Client), &r)
	if err != nil {
		return err
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
