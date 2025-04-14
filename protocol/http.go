package protocol

import (
	"errors"
	"github.com/gin-gonic/gin"
	"net/http"
)

const MsgOK = "ok"

type ErrCode string

const (
	ErrCodeBadRequest   ErrCode = "bad_request"
	ErrCodeBadState     ErrCode = "bad_state"
	ErrCodeUnauthorized ErrCode = "unauthorized"
	ErrCodeUnknown      ErrCode = "unknown"
)

type Error struct {
	Err     error
	Code    ErrCode
	Message string
}

func (e Error) Unwrap() error {
	return e.Err
}

func (e Error) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return e.Message
}

func Wrap(e error, c ErrCode, m string) error {
	return &Error{
		Err:     e,
		Code:    c,
		Message: m,
	}
}

type (
	OK struct {
		Data any `json:"data"`
	}

	ErrorResponse struct {
		ErrCode ErrCode `json:"code"`
		Message string  `json:"message"`
	}
)

func NewOK(data any) OK {
	return OK{Data: data}
}

type RequestHandler func(c *gin.Context) error

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

func ErrorHandlerMiddleware(c *gin.Context) {
	c.Next()
	if len(c.Errors) > 0 && !c.Writer.Written() && c.Writer.Status() == http.StatusOK {
		m := parse(c.Errors.Last())
		c.JSON(httpStatus(m.ErrCode), m)
	}
}

func httpStatus(c ErrCode) int {
	switch c {
	case ErrCodeBadRequest, ErrCodeBadState:
		return http.StatusBadRequest
	case ErrCodeUnauthorized:
		return http.StatusUnauthorized
	default:
		return http.StatusInternalServerError
	}
}

func parse(e error) ErrorResponse {
	m := ErrorResponse{
		ErrCode: ErrCodeUnknown,
		Message: "Unknown error occurred",
	}
	var appError *Error
	if errors.As(e, &appError) {
		m.ErrCode = appError.Code
		m.Message = appError.Message
	}
	return m
}
