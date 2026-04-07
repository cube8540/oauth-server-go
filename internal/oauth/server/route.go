package server

import (
	"context"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"oauth-server-go/internal/oauth/client"
	"oauth-server-go/internal/oauth/server/handler"
	"oauth-server-go/internal/oauth/server/pkg/gen"
	"oauth-server-go/internal/oauth/server/pkg/security"
	"oauth-server-go/internal/oauth/server/repository"
	"oauth-server-go/internal/oauth/server/service"
	"oauth-server-go/internal/oauth/token"
	"oauth-server-go/internal/pkg/auth"
	"oauth-server-go/internal/pkg/middleware"
	"oauth-server-go/internal/pkg/web"
	"oauth-server-go/pkg/hash"
)

var resourceOwnerAuthenticate auth.SimpleAuthenticate

func SetResourceOwnerAuthenticate(f auth.SimpleAuthenticate) {
	resourceOwnerAuthenticate = f
}

// Environment OAuth2 도메인 처리를 위한 환경을 제공하는 인터페이스
type Environment interface {
	GetDB() *gorm.DB
}

type ClientAuthProvider struct {
	clientRepository repository.ClientRepository
}

func (srv *ClientAuthProvider) Authenticate(ctx context.Context, id, secret string) (*client.Client, error) {
	retriever := func(id string) (*client.Client, bool) {
		return srv.clientRepository.FindByClientID(ctx, id)
	}

	authProvider := client.NewAuthenticationProvider(retriever, hash.Compare)
	return authProvider.Authenticate(id, secret)
}

func OAuth2RFCRouting(route *gin.Engine, env Environment) {
	repositoryCachingContext := func(c context.Context) context.Context {
		cacheContext := repository.WithClientCaching(c)
		cacheContext = repository.WithAccessTokenCaching(cacheContext)
		return cacheContext
	}

	clientRepository := repository.NewClientGormBridge(env.GetDB())
	scopeRepository := repository.NewScopeGormBridge(env.GetDB())
	authCodeRepository := repository.NewAuthCodeGormBride(env.GetDB())
	tokenRepository := repository.NewTokenGormBridge(env.GetDB())

	clientService := service.NewClientService(clientRepository)
	scopeService := service.NewScopeService(scopeRepository)
	authCodeService := service.NewAuthCodeService(authCodeRepository)
	tokenService := service.NewTokenService(tokenRepository)

	approveHandler := handler.NewAuthorizationApproveHandler(authCodeService, token.NewImplicitGrant(gen.GenerateRandomUUID))

	issuer := service.TokenIssuer{
		Repository:                tokenRepository,
		RetrieveAuthorizationCode: authCodeService.Consume,
		AuthenticateResourceOwner: resourceOwnerAuthenticate,
		GenerateAccessToken:       gen.GenerateRandomUUID,
		GenerateRefreshToken:      gen.GenerateRandomUUID,
	}
	rfcHandler := handler.NewHandler(&issuer, clientService, scopeService, approveHandler, tokenService)

	group := route.Group("/oauth/auth")
	group.Use(middleware.NoCache)
	group.Use(handler.OAuth2ErrorWrappingHandler)
	group.Use(handler.OAuth2ErrorHandler)
	group.Use(middleware.EnhanceGinContext(repositoryCachingContext))

	authorizationEndpoint := group.Group("/authorize")
	authorizationEndpoint.Use(web.RequestProtect(web.AccessDeniedRedirectHandler("/users/auth")))
	authorizationEndpoint.GET("", web.NewHTTPHandler(rfcHandler.Authorize))
	authorizationEndpoint.POST("", web.NewHTTPHandler(rfcHandler.Approve))

	clientAuthProvider := ClientAuthProvider{clientRepository: clientRepository}
	tokenIssueEndpoint := group.Group("/token")
	tokenIssueEndpoint.Use(security.ClientBasicAuthenticateHandler(&clientAuthProvider))
	tokenIssueEndpoint.Use(security.ClientFormAuthenticationHandler(&clientAuthProvider))
	tokenIssueEndpoint.Use(security.ClientRequiredAuthenticationHandler)
	tokenIssueEndpoint.POST("", web.NewHTTPHandler(rfcHandler.IssueToken))
	tokenIssueEndpoint.POST("/introspect", web.NewHTTPHandler(rfcHandler.InspectToken))
}
