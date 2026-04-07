package user

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"oauth-server-go/internal/pkg/auth"
	"oauth-server-go/internal/pkg/web"
	"oauth-server-go/internal/user/handler"
	"oauth-server-go/internal/user/repository"
	"oauth-server-go/internal/user/service"
)

// Environment 회원 도메인 처리를 위한 환경을 제공하는 인터페이스
type Environment interface {
	GetDB() *gorm.DB
}

type Extract struct {
	Authenticate auth.SimpleAuthenticate
}

func APIRouting(route *gin.Engine, env Environment) Extract {
	repo := repository.NewGorm(env.GetDB())
	authSrv := service.NewAuthenticationService(repo)

	h := handler.NewAPI(authSrv)

	endpoint := route.Group("/api/users/v1")
	endpoint.POST("/login", web.NewHTTPHandler(h.Auth))

	simpleAuth := func(id, pw string) (bool, error) {
		req := service.AuthenticationRequest{
			Username: id,
			Password: pw,
		}
		_, err := authSrv.Auth(&req)
		return err == nil, err
	}

	return Extract{
		Authenticate: simpleAuth,
	}

}

func StaticRouting(route *gin.Engine) {
	h := handler.NewStatic()

	endpoint := route.Group("/users")
	endpoint.GET("/auth", web.NewHTTPHandler(h.LoginPage))
}
