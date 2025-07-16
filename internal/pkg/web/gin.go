package web

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

// RequestHandler 어플리케이션에서 사용할 HTTP 헨들러 함수
//
// gin 프레임워크 미들웨어로 등록되어 HTTP 요청을 처리한다.
type RequestHandler func(c *gin.Context) error

// NewHTTPHandler 어플리케이션에서 사용할 HTTP 핸들러를 `gin.HandlerFunc`로 변환한다.
//
// 여러개의 `web.RequestHandler`를 받아 하나의 `gin.HandlerFunc`로 묶어 반환한다.
// `web.RequestHandler`에서 발생한 에러는 gin 컨텍스트에 등록 되며 에러가 발생한 즉시 다른 처리 없이 동작을 종료한다.
func NewHTTPHandler(h ...RequestHandler) gin.HandlerFunc {
	return func(c *gin.Context) {
		for _, handler := range h {
			if err := handler(c); err != nil {
				_ = c.Error(err)
				return
			}
		}
	}
}

// ErrorHandler gin 미들웨어에 등록되어 에러를 처리하는 에러 핸들러
//
// 등록된 HTTP 헨들러 동작 후 에러가 발생하여 gin 컨텍스트에 에러가 등록되어 있을 경우
// HTTP 실패 메시지를 요청 바디에 쓴다.
//
// 단, 아래 조건에서는 에러를 요청 바디에 쓰지 않는다.
//   - 이미 응답 바디에 데이터가 쓰인(Written) 경우
//   - HTTP 상태 코드가 200이 아닌 경우
//
// Note: 에러가 여러개 등록 되어도 마지막 에러를 기준으로 처리한다.
func ErrorHandler(c *gin.Context) {
	c.Next()
	if len(c.Errors) > 0 && !c.Writer.Written() && c.Writer.Status() == http.StatusOK {
		m := ParseErr(c.Errors.Last())
		c.JSON(CodeToStatus(m.Code), m)
	}
}
