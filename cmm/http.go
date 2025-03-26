package cmm

const (
	ErrMsgBadRequest = "bad_request"
	ErrMsgBadState   = "bad_state"
	ErrMsgUnknown    = "unknown"
)

type ErrCode string

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
