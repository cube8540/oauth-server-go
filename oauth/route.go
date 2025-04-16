package oauth

import (
	"errors"
	"github.com/gin-gonic/gin"
	"oauth-server-go/conf"
	"oauth-server-go/crypto"
	"oauth-server-go/oauth/client"
	"oauth-server-go/oauth/code"
	"oauth-server-go/oauth/pkg"
	"oauth-server-go/oauth/token"
	"oauth-server-go/protocol"
	"oauth-server-go/security"
	"oauth-server-go/user"
	"oauth-server-go/user/model"
	userrepo "oauth-server-go/user/repository"
	usersrv "oauth-server-go/user/service"
)

type (
	authorizationRequestFlow struct {
		authCodeService *code.Service
		implicitFlow    *token.ImplicitFlow
	}

	tokenIssueFlow struct {
		authorizationCodeFlow *token.AuthorizationCodeFlow
		resourceOwnerFlow     *token.ResourceOwnerPasswordCredentialsFlow
		refreshFlow           *token.RefreshFlow
		clientCredentialsFlow *token.ClientCredentialsFlow
	}
)

func (f *authorizationRequestFlow) consume(c *client.Client, r *pkg.AuthorizationRequest) (any, error) {
	switch r.ResponseType {
	case pkg.ResponseTypeCode:
		return f.authCodeService.New(c, r)
	case pkg.ResponseTypeToken:
		return f.implicitFlow.Generate(c, r)
	default:
		return nil, NewErr(pkg.ErrUnsupportedResponseType, "unsupported")
	}
}

func (f *tokenIssueFlow) generate(c *client.Client, r *pkg.TokenRequest) (*token.Token, *token.RefreshToken, error) {
	switch r.GrantType {
	case pkg.GrantTypeAuthorizationCode:
		return f.authorizationCodeFlow.Generate(c, r)
	case pkg.GrantTypePassword:
		return f.resourceOwnerFlow.Generate(c, r)
	case pkg.GrantTypeRefreshToken:
		return f.refreshFlow.Generate(c, r)
	case pkg.GrantTypeClientCredentials:
		return f.clientCredentialsFlow.Generate(c, r)
	default:
		return nil, nil, NewErr(pkg.ErrUnsupportedGrantType, "unsupported")
	}
}

func adaptAuthentication() token.ResourceOwnerAuthentication {
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
			return false, NewErr(pkg.ErrAccessDenied, "failed resource owner credentials")
		}
		if err != nil {
			return false, err
		}
		return true, nil
	}
}

func Routing(route *gin.Engine) {
	clientRepository := client.NewRepository(conf.GetDB())
	tokenRepository := token.NewRepository(conf.GetDB())
	authCodeRepository := code.NewRepository(conf.GetDB())

	clientService := client.NewService(clientRepository, crypto.NewBcryptHasher())
	tokenService := token.NewIntrospectionService(tokenRepository)
	authCodeService := code.NewService(authCodeRepository)

	requestConsumer := &authorizationRequestFlow{
		authCodeService: authCodeService,
		implicitFlow:    token.NewImplicitFlow(tokenRepository),
	}
	issueFlow := &tokenIssueFlow{
		authorizationCodeFlow: token.NewAuthorizationCodeFlow(tokenRepository, authCodeService.Retrieve),
		resourceOwnerFlow:     token.NewResourceOwnerPasswordCredentialsFlow(adaptAuthentication(), tokenRepository),
		refreshFlow:           token.NewRefreshFlow(tokenRepository),
		clientCredentialsFlow: token.NewClientCredentialsFlow(tokenRepository),
	}

	h := h{
		clientRetriever: clientService.GetClient,
		requestConsumer: requestConsumer.consume,
		tokenIssuer:     issueFlow.generate,
		introspector:    tokenService.Introspection,
	}

	group := route.Group("/oauth/auth")
	group.Use(noCacheMiddleware)
	group.Use(ErrorHandleMiddleware())
	group.Use(ErrorWrappingMiddleware())

	authorize := group.Group("/authorize")
	authorize.Use(security.Protected(security.AccessDeniedRedirect("/auth/login")))
	authorize.GET("", protocol.NewHTTPHandler(h.authorize))
	authorize.POST("", protocol.NewHTTPHandler(h.approval))

	tokenRoute := group.Group("/token")
	tokenRoute.Use(clientBasicAuthManage(clientService.Auth))
	tokenRoute.Use(clientFormAuthManage(clientService.Auth))
	tokenRoute.Use(newClientAuthRequiredMiddleware())
	tokenRoute.POST("", protocol.NewHTTPHandler(h.issueToken))
	tokenRoute.POST("/introspect", protocol.NewHTTPHandler(h.introspection))

	m := m{
		service: token.NewManagementService(tokenRepository),
	}

	manageGroup := route.Group("/oauth/manage")
	manageGroup.Use(security.Protected(security.AccessDeniedRedirect("/auth/login")))
	manageGroup.GET("/tokens", protocol.NewHTTPHandler(m.tokenManagement))
	manageGroup.DELETE("/tokens/:tokenValue", protocol.NewHTTPHandler(m.deleteToken))
}

func noCacheMiddleware(c *gin.Context) {
	c.Header("Cache-Control", "no-cache")
}

func newClientAuthRequiredMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		_, exists := c.Get(oauth2ShareKeyAuthClient)
		if !exists {
			_ = c.Error(NewErr(pkg.ErrUnauthorizedClient, "client auth is required"))
			c.Abort()
		} else {
			c.Next()
		}
	}
}
