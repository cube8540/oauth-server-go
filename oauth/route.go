package oauth

import (
	"errors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"oauth-server-go/internal/pkg/web"
	"oauth-server-go/internal/user/codes"
	"oauth-server-go/internal/user/repository"
	"oauth-server-go/internal/user/service"
	"oauth-server-go/oauth/client"
	"oauth-server-go/oauth/code"
	"oauth-server-go/oauth/pkg"
	"oauth-server-go/oauth/token"
	"oauth-server-go/security"
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

func adaptAuthentication(db *gorm.DB) token.ResourceOwnerAuthentication {
	accountRepository := repository.NewGorm(db)
	authService := service.NewAuthenticationService(accountRepository)

	return func(u, p string) (bool, error) {
		_, err := authService.Auth(&service.AuthenticationRequest{
			Username: u,
			Password: p,
		})
		if errors.Is(err, codes.ErrAccountNotFound) ||
			errors.Is(err, codes.ErrPasswordNotMatched) ||
			errors.Is(err, codes.ErrAccountLocked) {
			return false, NewErr(pkg.ErrAccessDenied, "failed resource owner credentials")
		}
		if err != nil {
			return false, err
		}
		return true, nil
	}
}

func Routing(route *gin.Engine, db *gorm.DB) {
	clientRepository := client.NewRepository(db)
	tokenRepository := token.NewRepository(db)
	authCodeRepository := code.NewRepository(db)

	clientService := client.NewService(clientRepository)
	tokenService := token.NewIntrospectionService(tokenRepository)
	authCodeService := code.NewService(authCodeRepository)

	requestConsumer := &authorizationRequestFlow{
		authCodeService: authCodeService,
		implicitFlow:    token.NewImplicitFlow(tokenRepository),
	}
	issueFlow := &tokenIssueFlow{
		authorizationCodeFlow: token.NewAuthorizationCodeFlow(tokenRepository, authCodeService.Retrieve),
		resourceOwnerFlow:     token.NewResourceOwnerPasswordCredentialsFlow(adaptAuthentication(db), tokenRepository),
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
	authorize.Use(security.Protected(security.AccessDeniedRedirect("/users/auth")))
	authorize.GET("", web.NewHTTPHandler(h.authorize))
	authorize.POST("", web.NewHTTPHandler(h.approval))

	tokenRoute := group.Group("/token")
	tokenRoute.Use(clientBasicAuthManage(clientService.Auth))
	tokenRoute.Use(clientFormAuthManage(clientService.Auth))
	tokenRoute.Use(newClientAuthRequiredMiddleware())
	tokenRoute.POST("", web.NewHTTPHandler(h.issueToken))
	tokenRoute.POST("/introspect", web.NewHTTPHandler(h.introspection))

	m := m{
		service: token.NewManagementService(tokenRepository),
	}

	manageGroup := route.Group("/oauth/manage")
	manageGroup.Use(security.Protected(security.AccessDeniedRedirect("/users/auth")))
	manageGroup.GET("/tokens", web.NewHTTPHandler(m.tokenManagement))
	manageGroup.DELETE("/tokens/:tokenValue", web.NewHTTPHandler(m.deleteToken))
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
