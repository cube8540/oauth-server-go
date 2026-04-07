package middleware

import (
	"context"
	"github.com/gin-gonic/gin"
)

// ContextEnhancer HTTP 요청에서 사용될 새 컨텍스트를 생성한다.
type ContextEnhancer func(ctx context.Context) context.Context

func NoCache(c *gin.Context) {
	c.Header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	c.Header("Pragma", "no-cache")
	c.Header("Expires", "0")
}

func EnhanceGinContext(enhancer ContextEnhancer) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		c := enhancer(ctx.Request.Context())
		ctx.Request = ctx.Request.WithContext(c)
		ctx.Next()
	}
}
