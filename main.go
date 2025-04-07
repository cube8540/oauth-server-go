package main

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"oauth-server-go/conf"
	oauthhandler "oauth-server-go/oauth/handler"
	"oauth-server-go/security"
	userhandler "oauth-server-go/user/handler"
)

func main() {
	route := gin.Default()
	store := conf.GetRedisSessionStore()

	route.LoadHTMLGlob("templates/*")

	route.Use(sessions.Sessions("g_session_id", store))
	route.Use(security.LoginContext())

	userhandler.Routing(route)
	oauthhandler.Routing(route)

	_ = route.Run(":" + conf.GetServerPort())
}
