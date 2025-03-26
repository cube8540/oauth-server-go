package main

import (
	"github.com/gin-gonic/gin"
	"oauth-server-go/conf"
	"oauth-server-go/user"
)

func main() {
	conf.Init()

	route := gin.Default()
	user.Routing(route)

	_ = route.Run(":" + conf.GetServerPort())
}
