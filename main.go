package main

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"oauth-server-go/conf"
	oauthhandler "oauth-server-go/oauth/handler"
	"oauth-server-go/protocol"
	"oauth-server-go/security"
	"oauth-server-go/security/session"
	userhandler "oauth-server-go/user/handler"
)

const applicationSessionID = "g_session_id"

func main() {
	route := gin.Default()
	store := conf.GetStore()

	route.LoadHTMLGlob("web/template/*")
	route.Static("/css", "./web/css")
	route.Static("/js", "./web/js")

	route.Use(protocol.ErrorHandlerMiddleware)
	route.Use(sessions.Sessions(applicationSessionID, store))
	route.Use(session.SecurityStore())
	route.Use(security.Authentication)

	userhandler.Routing(route)
	oauthhandler.Routing(route)

	_ = route.Run(conf.GetServerPort())
}
