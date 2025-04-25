package main

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"oauth-server-go/conf"
	"oauth-server-go/conf/db"
	appsession "oauth-server-go/conf/session"
	"oauth-server-go/oauth"
	"oauth-server-go/protocol"
	"oauth-server-go/security"
	secsession "oauth-server-go/security/session"
	"oauth-server-go/user"
)

const applicationSessionID = "g_session_id"

func main() {
	config := conf.Read()

	gormDB := db.Connect(&config.DB)
	defer func() {
		gormSQL, _ := gormDB.DB()
		_ = gormSQL.Close()
	}()

	sessionRediStore := appsession.NewRedisStore(&config.Redis, &config.Session)
	session := sessions.Sessions(applicationSessionID, sessionRediStore)
	securityBySession := secsession.SecurityStore()

	route := gin.Default()
	route.LoadHTMLGlob("web/template/*")
	route.Static("/css", "./web/css")
	route.Static("/js", "./web/js")

	route.Use(protocol.ErrorHandlerMiddleware)
	route.Use(session)
	route.Use(securityBySession)
	route.Use(security.Authentication)

	user.Routing(route, gormDB)
	oauth.Routing(route, gormDB)

	_ = route.Run(config.Port)
}
