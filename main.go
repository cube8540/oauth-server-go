package main

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"oauth-server-go/conf"
	"oauth-server-go/conf/db"
	"oauth-server-go/conf/log"
	appsession "oauth-server-go/conf/session"
	"oauth-server-go/internal/pkg/web"
	"oauth-server-go/internal/user"
	"oauth-server-go/oauth"
)

const applicationSessionID = "g_session_id"

// SystemEnvironment 시스템 환경
type SystemEnvironment struct {
	db *gorm.DB
}

func (s *SystemEnvironment) GetDB() *gorm.DB {
	return s.db
}

func main() {
	config := conf.Read()
	log.NewLogger(&config.Logger)
	defer func() {
		_ = log.Logger().Sync()
	}()

	gormDB := db.Connect(&config.DB)
	defer func() {
		gormSQL, _ := gormDB.DB()
		_ = gormSQL.Close()
	}()
	log.Logger().Debug("Gorm connection completed.")

	sessionStore := appsession.NewRedisStore(&config.Redis, &config.Session)

	route := gin.Default()
	route.LoadHTMLGlob("web/template/*")
	route.Static("/css", "./web/css")
	route.Static("/js", "./web/js")

	route.Use(web.ErrorHandler)
	route.Use(sessions.Sessions(applicationSessionID, sessionStore))
	route.Use(web.SessionAuthenticationHandler)

	env := SystemEnvironment{
		db: gormDB,
	}

	user.APIRouting(route, &env)
	user.StaticRouting(route)

	oauth.Routing(route, gormDB)

	_ = route.Run(config.Port)
}
