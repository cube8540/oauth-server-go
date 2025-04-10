package handler

import (
	"github.com/gin-gonic/gin"
	"oauth-server-go/conf"
	"oauth-server-go/crypto"
	"oauth-server-go/oauth"
	"oauth-server-go/oauth/entity"
	"oauth-server-go/oauth/repository"
	"oauth-server-go/oauth/service"
	"oauth-server-go/protocol"
	"oauth-server-go/security"
)

type (
	authorizationRequestFlow struct {
		authCodeService *service.AuthCodeService
	}

	tokenIssueFlow struct {
		authorizationCodeFlow *service.AuthorizationCodeFlow
	}
)

func (f authorizationRequestFlow) consume(c *entity.Client, r *oauth.AuthorizationRequest) (any, error) {
	switch r.ResponseType {
	case oauth.ResponseTypeCode:
		return f.authCodeService.New(c, r)
	default:
		return nil, oauth.NewErr(oauth.ErrUnsupportedResponseType, "unsupported")
	}
}

func (f tokenIssueFlow) generate(c *entity.Client, r *oauth.TokenRequest) (*entity.Token, *entity.RefreshToken, error) {
	switch r.GrantType {
	case oauth.GrantTypeAuthorizationCode:
		return f.authorizationCodeFlow.Generate(c, r)
	default:
		return nil, nil, oauth.NewErr(oauth.ErrUnsupportedGrantType, "unsupported")
	}
}

func Routing(route *gin.Engine) {
	clientRepository := repository.NewClientRepository(conf.GetDB())
	clientService := service.NewClientService(clientRepository, crypto.NewBcryptHasher())

	authCodeRepository := repository.NewAuthCodeRepository(conf.GetDB())
	authCodeService := service.NewAuthCodeService(authCodeRepository)

	requestConsumer := &authorizationRequestFlow{
		authCodeService: authCodeService,
	}

	tokenRepository := repository.NewTokenRepository(conf.GetDB())
	issueFlow := &tokenIssueFlow{
		authorizationCodeFlow: service.NewAuthorizationCodeFlow(tokenRepository, authCodeService.Retrieve),
	}

	h := h{
		clientRetriever: clientService.GetClient,
		requestConsumer: requestConsumer.consume,
		tokenIssuer:     issueFlow.generate,
	}

	group := route.Group("/oauth")
	group.Use(noCacheMiddleware)

	authorize := group.Group("/authorize")
	authorize.Use(security.Authenticated(newAccessDeniedHandler(errHandle)))
	authorize.GET("", protocol.NewHTTPHandler(errHandle, h.authorize))
	authorize.POST("", protocol.NewHTTPHandler(errHandle, h.approval))

	token := group.Group("/token")
	token.Use(clientBasicAuthManage(clientService.Auth, errHandle))
	token.Use(clientFormAuthManage(clientService.Auth, errHandle))
	token.Use(newClientAuthRequiredMiddleware(errHandle))
	token.POST("", protocol.NewHTTPHandler(errHandle, h.issueToken))
}

func noCacheMiddleware(c *gin.Context) {
	c.Header("Cache-Control", "no-cache")
}

func newAccessDeniedHandler(eh protocol.ErrHandler) security.AccessDeniedHandler {
	return func(c *gin.Context) {
		eh(c, oauth.NewErr(oauth.ErrAccessDenied, "resource owner login is required"))
	}
}

func newClientAuthRequiredMiddleware(eh protocol.ErrHandler) gin.HandlerFunc {
	return func(c *gin.Context) {
		_, exists := c.Get(oauth2ShareKeyAuthClient)
		if !exists {
			eh(c, oauth.NewErr(oauth.ErrUnauthorizedClient, "client auth is required"))
			c.Abort()
		} else {
			c.Next()
		}
	}
}
