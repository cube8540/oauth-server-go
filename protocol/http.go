package protocol

import "github.com/gin-gonic/gin"

const MsgOK = "ok"

const (
	ErrMsgBadRequest = "bad_request"
	ErrMsgBadState   = "bad_state"
	ErrMsgUnknown    = "unknown"
)

type ErrCode string

type OK struct {
	Data any `json:"data"`
}

type ErrorResponse struct {
	ErrCode ErrCode `json:"err_code"`
	Message string  `json:"message"`
}

func NewErr(code ErrCode, message string) ErrorResponse {
	return ErrorResponse{
		ErrCode: code,
		Message: message,
	}
}

func NewOK(data any) OK {
	return OK{Data: data}
}

type RequestHandler func(c *gin.Context) error

type ErrHandler func(c *gin.Context, err error)

func NewHTTPHandler(e ErrHandler, h ...RequestHandler) gin.HandlerFunc {
	return func(c *gin.Context) {
		for _, handler := range h {
			err := handler(c)
			if err != nil {
				e(c, err)
				return
			}
		}
	}
}
