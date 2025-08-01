package server

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"oauth-server-go/internal/oauth/client"
	"oauth-server-go/internal/oauth/server/handler"
	"oauth-server-go/internal/oauth/server/pkg/gen"
	"oauth-server-go/internal/oauth/server/pkg/security"
	"oauth-server-go/internal/oauth/server/repository"
	"oauth-server-go/internal/oauth/server/service"
	"oauth-server-go/internal/oauth/token"
	"oauth-server-go/internal/pkg/web"
	"oauth-server-go/pkg/hash"
)

// Environment OAuth2 도메인 처리를 위한 환경을 제공하는 인터페이스
type Environment interface {
	GetDB() *gorm.DB
}

func OAuth2RFCRouting(route *gin.Engine, env Environment) {
	clientRepository := repository.NewClientGormBridge(env.GetDB())
	scopeRepository := repository.NewScopeGormBridge(env.GetDB())
	authCodeRepository := repository.NewAuthCodeGormBride(env.GetDB())
	tokenRepository := repository.NewTokenGormBridge(env.GetDB())

	clientService := service.NewClientService(clientRepository)
	scopeService := service.NewScopeService(scopeRepository)
	authCodeService := service.NewAuthCodeService(authCodeRepository)
	tokenService := service.NewTokenService(tokenRepository)

	approveHandler := handler.NewAuthorizationApproveHandler(authCodeService, token.NewImplicitGrant(gen.GenerateRandomUUID))
	rfcHandler := handler.NewHandler(clientService, scopeService, approveHandler, tokenService)

	group := route.Group("/oauth/auth")
	group.Use(noCache)
	group.Use(handler.OAuth2ErrorWrappingHandler)
	group.Use(handler.OAuth2ErrorHandler)

	authorizationEndpoint := group.Group("/authorize")
	authorizationEndpoint.Use(web.RequestProtect(web.AccessDeniedRedirectHandler("/users/auth")))
	authorizationEndpoint.GET("", web.NewHTTPHandler(rfcHandler.Authorize))
	authorizationEndpoint.POST("", web.NewHTTPHandler(rfcHandler.Approve))

	clientAuthProvider := client.NewAuthenticationProvider(clientRepository, hash.Compare)
	tokenIssueEndpoint := group.Group("/token")
	tokenIssueEndpoint.Use(security.ClientBasicAuthenticateHandler(clientAuthProvider))
	tokenIssueEndpoint.Use(security.ClientFormAuthenticationHandler(clientAuthProvider))
	tokenIssueEndpoint.Use(security.ClientRequiredAuthenticationHandler)
	tokenIssueEndpoint.POST("", web.NewHTTPHandler(rfcHandler.IssueToken))
	tokenIssueEndpoint.POST("/introspect", web.NewHTTPHandler(rfcHandler.InspectToken))
}

func noCache(c *gin.Context) {
	c.Header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	c.Header("Pragma", "no-cache")
	c.Header("Expires", "0")
}
