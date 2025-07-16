package user

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"oauth-server-go/internal/user/handler"
	"oauth-server-go/internal/user/repository"
	"oauth-server-go/internal/user/service"
	"oauth-server-go/protocol"
)

// Environment 회원 도메인 처리를 위한 환경을 제공하는 인터페이스
type Environment interface {
	GetDB() *gorm.DB
}

func APIRouting(route *gin.Engine, env Environment) {
	repo := repository.NewGorm(env.GetDB())
	authSrv := service.NewAuthenticationService(repo)

	h := handler.NewAPI(authSrv)

	endpoint := route.Group("/api/users/v1")
	endpoint.POST("/login", protocol.NewHTTPHandler(h.Auth))
}

func StaticRouting(route *gin.Engine) {
	h := handler.NewStatic()

	endpoint := route.Group("/users")
	endpoint.GET("/auth", protocol.NewHTTPHandler(h.LoginPage))
}
