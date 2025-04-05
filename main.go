package main

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"oauth-server-go/conf"
	oauthhandler "oauth-server-go/oauth/handler"
	userhandler "oauth-server-go/user/handler"
)

func main() {
	route := gin.Default()
	route.Use(sessions.Sessions("g_session_id", conf.GetRedisSessionStore()))

	userhandler.Routing(route)
	oauthhandler.Routing(route)

	_ = route.Run(":" + conf.GetServerPort())
}
