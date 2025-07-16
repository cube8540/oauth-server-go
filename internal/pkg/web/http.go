package web

import (
	"errors"
	"net/http"
)

// HTTP 요청 처리 중 발생하는 에러 코드 모음
// `web.CodeToStatus` 함수를 통해 특정 HTTP 상태 코드로 변환 할 수 있다.
const (
	// ErrCodeBadRequest 클라이언트에서 잘못된 요청을 했음을 의미
	ErrCodeBadRequest = "bad_request"

	// ErrCodeBadState 클라이언트가 잘못된 상태를 가지고 있음을 의미
	ErrCodeBadState = "bad_state"

	// ErrCodeUnauthorized 인증되지 않은 클라이언트를 의미
	ErrCodeUnauthorized = "unauthorized"

	// ErrCodeUnknown 알 수 없는 에러가 발생 했음을 의미
	ErrCodeUnknown = "unknown"
)

const (
	// MsgOK HTTP 성공 응답에 사용될 기본 메시지
	// 성공 응답 메시지란에 따로 표시할 값이 없을 경우 이 값이 표시 된다.
	MsgOK = "ok"

	// MsgUnknownErr HTTP 실패 응답에 사용될 기본 메시지
	// 실패 응답 메시지란에 따로 표시할 값이 없을 경우 이 값이 표시 된다.
	MsgUnknownErr = "Unknown error occurred"
)

// Error HTTP 요청을 처리하던 도중 발생한 에러의 정보를 담고 있는 구조체
type Error struct {
	// err 실제 어플리케이션 수행 도중 발생한 에러
	err error

	// code 에러 코드
	code string

	// message 사용자에게 노출할 메시지
	message string
}

func (e Error) Unwrap() error {
	return e.err
}

func (e Error) Error() string {
	return e.message
}

// Wrap 인자로 받은 에러를 랩핑하여 새 에러 인스턴스를 생성한다.
func Wrap(err error, code, message string) Error {
	return Error{
		err:     err,
		code:    code,
		message: message,
	}
}

// HTTP 성공/실패 응답 바디 정의
type (

	// Success HTTP 요청 처리에 성공시 사용자에게 보여줄 응답 구조체
	Success struct {
		// Data 처리된 데이터
		// 이 값은 사용자가 요청한 데이터 혹은 요청이 성공적으로 완료 되었다는 의미의 값을 가질 수 있다.
		Data any `json:"data"`
	}

	// Fail HTTP 요청 처리에 실패시 사용자에게 보여줄 응답 구조체
	Fail struct {
		// Code 에러 코드
		// 실패 원인에 대한 큰 범주의 코드를 제공한다.
		Code string `json:"code"`

		// Message 실패 원인에 대한 간략한 설명 메시지
		Message string `json:"message"`
	}
)

// NewSuccess 새 HTTP 성공 메시지 인스턴스를 생성한다.
func NewSuccess(data any) *Success {
	return &Success{Data: data}
}

// NewFail 새 HTTP 실패 메시지 인스턴스를 생성한다.
func NewFail(code, message string) *Fail {
	return &Fail{Code: code, Message: message}
}

// ParseErr 에러 받아 새 `web.Fail` 인스턴스를 생성한다.
//
// 인자로 받은 에러가 `web.Error`인 경우 인자에 저장된 코드와 메시지를 사용한다.
// 그 외의 경우 코드와 메시지로 `web.ErrCodeUnknown`, `web.MsgUnknownErr`를 사용한다.
func ParseErr(e error) *Fail {
	m := NewFail(ErrCodeUnknown, MsgUnknownErr)

	var appError *Error
	if errors.As(e, &appError) {
		m.Code = appError.code
		m.Message = appError.message
	}
	return m
}

// CodeToStatus 에러코드를 인자로 받아 코드에 맞는 HTTP 상태 코드를 반환한다.
func CodeToStatus(code string) int {
	switch code {
	case ErrCodeBadRequest, ErrCodeBadState:
		return http.StatusBadRequest
	case ErrCodeUnauthorized:
		return http.StatusUnauthorized
	default:
		return http.StatusInternalServerError
	}
}
