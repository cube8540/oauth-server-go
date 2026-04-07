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

	rfcHandler := handler.Handler{
		TokenIssuer: &service.TokenIssuer{
			Repository:                tokenRepository,
			RetrieveAuthorizationCode: authCodeService.Consume,
			AuthenticateResourceOwner: resourceOwnerAuthenticate,
			GenerateAccessToken:       gen.GenerateRandomUUID,
			GenerateRefreshToken:      gen.GenerateRandomUUID,
		},
		TokenService:    tokenService,
		ClientService:   clientService,
		ScopeService:    scopeService,
		AuthCodeService: authCodeService,
		ImplicitGranter: token.NewImplicitGrant(gen.GenerateRandomUUID),
	}

	managementHandler := handler.ManagementHandler{
		TokenService: tokenService,
	}

	group := route.Group("/oauth/auth")
	group.Use(middleware.NoCache)
	group.Use(handler.OAuth2ErrorWrappingHandler)
	group.Use(handler.OAuth2ErrorHandler)
	group.Use(middleware.EnhanceGinContext(repositoryCachingContext))

	authorizationEndpoint := group.Group("/authorize")
	authorizationEndpoint.Use(web.RequestProtect(web.AccessDeniedRedirectHandler("/users/auth")))
	authorizationEndpoint.GET("", web.NewHTTPHandler(rfcHandler.Authorize))
	authorizationEndpoint.POST("", web.NewHTTPHandler(rfcHandler.Approve))

	clientAuthProvider := func(ctx context.Context, id, secret string) (*client.Client, error) {
		retriever := func(id string) (*client.Client, bool) {
			return clientRepository.FindByClientID(ctx, id)
		}
		authProvider := client.NewAuthenticationProvider(retriever, hash.Compare)
		return authProvider.Authenticate(id, secret)
	}

	tokenIssueEndpoint := group.Group("/token")
	tokenIssueEndpoint.Use(security.ClientBasicAuthenticateHandler(clientAuthProvider))
	tokenIssueEndpoint.Use(security.ClientFormAuthenticationHandler(clientAuthProvider))
	tokenIssueEndpoint.Use(security.ClientRequiredAuthenticationHandler)
	tokenIssueEndpoint.POST("", web.NewHTTPHandler(rfcHandler.IssueToken))
	tokenIssueEndpoint.POST("/introspect", web.NewHTTPHandler(rfcHandler.InspectToken))

	managementGroup := route.Group("/oauth/manage")
	managementGroup.Use(web.RequestProtect(web.AccessDeniedRedirectHandler("/users/auth")))
	managementGroup.GET("/tokens", web.NewHTTPHandler(managementHandler.TokenManagement))
	managementGroup.DELETE("/tokens/:tokenValue", web.NewHTTPHandler(managementHandler.DeleteToken))
}
