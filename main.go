package main

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"oauth-server-go/conf"
	"oauth-server-go/user"
)

func main() {
	route := gin.Default()
	route.Use(sessions.Sessions("g_session_id", conf.GetRedisSessionStore()))

	user.Routing(route)

	_ = route.Run(":" + conf.GetServerPort())
}
