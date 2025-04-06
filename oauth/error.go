package oauth

import "errors"

var (
	ErrInvalidRequest          = errors.New("invalid_request")
	ErrUnauthorizedClient      = errors.New("unauthorized_client")
	ErrAccessDenied            = errors.New("access_denied")
	ErrUnsupportedResponseType = errors.New("unsupported_response_type")
	ErrInvalidScope            = errors.New("invalid_scope")
	ErrServerError             = errors.New("server_error")
	ErrTemporaryUnavailable    = errors.New("temporarily_unavailable")
	ErrInvalidClient           = errors.New("invalid_client")
	ErrInvalidGrant            = errors.New("invalid_grant")
	ErrUnsupportedGrantType    = errors.New("unsupported_grant_type")
)

type Err struct {
	Err     error
	Message string
}

func (e *Err) Unwrap() error {
	return e.Err
}

func (e *Err) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return e.Message
}

func NewErr(err error, m string) *Err {
	return &Err{
		Err:     err,
		Message: m,
	}
}
