package handler

import (
	"errors"
	"github.com/gin-gonic/gin"
	"oauth-server-go/conf"
	"oauth-server-go/crypto"
	"oauth-server-go/oauth"
	"oauth-server-go/oauth/entity"
	"oauth-server-go/oauth/repository"
	"oauth-server-go/oauth/service"
	"oauth-server-go/protocol"
	"oauth-server-go/security"
	"oauth-server-go/user"
	"oauth-server-go/user/model"
	userrepo "oauth-server-go/user/repository"
	usersrv "oauth-server-go/user/service"
)

type (
	authorizationRequestFlow struct {
		authCodeService *service.AuthCodeService
		implicitFlow    *service.ImplicitFlow
	}

	tokenIssueFlow struct {
		authorizationCodeFlow *service.AuthorizationCodeFlow
		resourceOwnerFlow     *service.ResourceOwnerPasswordCredentialsFlow
		refreshFlow           *service.RefreshFlow
		clientCredentialsFlow *service.ClientCredentialsFlow
	}
)

func (f authorizationRequestFlow) consume(c *entity.Client, r *oauth.AuthorizationRequest) (any, error) {
	switch r.ResponseType {
	case oauth.ResponseTypeCode:
		return f.authCodeService.New(c, r)
	case oauth.ResponseTypeToken:
		return f.implicitFlow.Generate(c, r)
	default:
		return nil, oauth.NewErr(oauth.ErrUnsupportedResponseType, "unsupported")
	}
}

func (f tokenIssueFlow) generate(c *entity.Client, r *oauth.TokenRequest) (*entity.Token, *entity.RefreshToken, error) {
	switch r.GrantType {
	case oauth.GrantTypeAuthorizationCode:
		return f.authorizationCodeFlow.Generate(c, r)
	case oauth.GrantTypePassword:
		return f.resourceOwnerFlow.Generate(c, r)
	case oauth.GrantTypeRefreshToken:
		return f.refreshFlow.Generate(c, r)
	case oauth.GrantTypeClientCredentials:
		return f.clientCredentialsFlow.Generate(c, r)
	default:
		return nil, nil, oauth.NewErr(oauth.ErrUnsupportedGrantType, "unsupported")
	}
}

func adaptAuthentication() service.ResourceOwnerAuthentication {
	accountRepository := userrepo.NewAccountRepository(conf.GetDB())
	authService := usersrv.NewAuthService(accountRepository, crypto.NewBcryptHasher())

	return func(u, p string) (bool, error) {
		_, err := authService.Login(&model.Login{
			Username: u,
			Password: p,
		})
		if errors.Is(err, user.ErrAccountNotFound) ||
			errors.Is(err, user.ErrPasswordNotMatch) ||
			errors.Is(err, user.ErrAccountLocked) {
			return false, oauth.NewErr(oauth.ErrAccessDenied, "failed resource owner credentials")
		}
		if err != nil {
			return false, err
		}
		return true, nil
	}
}

func Routing(route *gin.Engine) {
	clientRepository := repository.NewClientRepository(conf.GetDB())
	tokenRepository := repository.NewTokenRepository(conf.GetDB())
	authCodeRepository := repository.NewAuthCodeRepository(conf.GetDB())

	clientService := service.NewClientService(clientRepository, crypto.NewBcryptHasher())
	tokenService := service.NewTokenService(tokenRepository)
	authCodeService := service.NewAuthCodeService(authCodeRepository)

	requestConsumer := &authorizationRequestFlow{
		authCodeService: authCodeService,
		implicitFlow:    service.NewImplicitFlow(tokenRepository),
	}
	issueFlow := &tokenIssueFlow{
		authorizationCodeFlow: service.NewAuthorizationCodeFlow(tokenRepository, authCodeService.Retrieve),
		resourceOwnerFlow:     service.NewResourceOwnerPasswordCredentialsFlow(adaptAuthentication(), tokenRepository),
		refreshFlow:           service.NewRefreshFlow(tokenRepository),
		clientCredentialsFlow: service.NewClientCredentialsFlow(tokenRepository),
	}

	h := h{
		clientRetriever: clientService.GetClient,
		requestConsumer: requestConsumer.consume,
		tokenIssuer:     issueFlow.generate,
		introspector:    tokenService.Introspection,
	}

	group := route.Group("/oauth")
	group.Use(noCacheMiddleware)
	group.Use(ErrorHandleMiddleware())

	authorize := group.Group("/authorize")
	authorize.Use(security.Authenticated(newAccessDeniedHandler()))
	authorize.GET("", protocol.NewHTTPHandler(h.authorize))
	authorize.POST("", protocol.NewHTTPHandler(h.approval))

	token := group.Group("/token")
	token.Use(clientBasicAuthManage(clientService.Auth))
	token.Use(clientFormAuthManage(clientService.Auth))
	token.Use(newClientAuthRequiredMiddleware())
	token.POST("", protocol.NewHTTPHandler(h.issueToken))
	token.POST("/introspect", protocol.NewHTTPHandler(h.introspection))
}

func noCacheMiddleware(c *gin.Context) {
	c.Header("Cache-Control", "no-cache")
}

func newAccessDeniedHandler() security.AccessDeniedHandler {
	return func(c *gin.Context) {
		_ = c.Error(oauth.NewErr(oauth.ErrAccessDenied, "resource owner login is required"))
		c.Abort()
	}
}

func newClientAuthRequiredMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		_, exists := c.Get(oauth2ShareKeyAuthClient)
		if !exists {
			_ = c.Error(oauth.NewErr(oauth.ErrUnauthorizedClient, "client auth is required"))
			c.Abort()
		} else {
			c.Next()
		}
	}
}
