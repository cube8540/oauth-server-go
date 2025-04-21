package main

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"oauth-server-go/conf"
	"oauth-server-go/oauth"
	"oauth-server-go/protocol"
	"oauth-server-go/security"
	"oauth-server-go/security/session"
	userhandler "oauth-server-go/user"
)

const applicationSessionID = "g_session_id"

func main() {
	conf.InitAll()
	defer conf.Close()

	route := gin.Default()
	route.LoadHTMLGlob("web/template/*")
	route.Static("/css", "./web/css")
	route.Static("/js", "./web/js")

	route.Use(protocol.ErrorHandlerMiddleware)
	route.Use(sessions.Sessions(applicationSessionID, conf.GetSessionStore()))
	route.Use(session.SecurityStore())
	route.Use(security.Authentication)

	userhandler.Routing(route)
	oauth.Routing(route)

	_ = route.Run(conf.GetServerPort())
}
