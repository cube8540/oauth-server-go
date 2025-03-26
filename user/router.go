package user

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
)

func Routing(route *gin.Engine) {
	auth := route.Group("/auth")
	auth.POST("/login", login)
}

func login(c *gin.Context) {
	var req LoginRequest
	err := c.ShouldBindBodyWithJSON(&req)

	if err != nil {
		fmt.Printf("%v\n", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "error"})
	}

	result, err := Login(&req, NewBcryptHasher())
	if err != nil {
		fmt.Printf("%v\n", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "error"})
	}

	c.JSON(http.StatusOK, result)
}
