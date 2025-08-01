package scope

import (
	"strings"
)

// Scope OAuth2 스코프
//
// 관리 포인트를 위한 구조체로 실제 클라이언트나 엑세스 토큰등에서는
// 이 구조체를 참조하지 않고 코드값 하나만 참조 한다.
type Scope struct {
	// Code 스코프 코드
	// 실제로 사용될 스코프의 코드값
	Code string

	// Name, Desc 각각 스코프명과 설명으로 스코프 관리를 위해 존재하는 필드
	Name, Desc string
}

// Split 입력 받은 문자열을 공백(" ")으로 나누어 반환한다. [RFC 6749]
//
// [RFC 6749]: https://datatracker.ietf.org/doc/html/rfc6749#section-3.3
func Split(src string) []string {
	var s []string
	if src == "" {
		return s
	}
	s = strings.Split(src, " ")
	return s
}

// Join 입력 받은 문자열 슬라이스 요소를 단일 문자열로 만든다.
// [RFC 6749] 에 따라 각 요소는 공백(" ")으로 구분 된다.
//
// [RFC 6749]: https://datatracker.ietf.org/doc/html/rfc6749#section-3.3
func Join(src []string) string {
	return strings.Join(src, " ")
}
