package scope

import "strings"

// Split 현제 저장되어 있는 string 타입의 문자열을 공백(" ")으로 나누어 반환한다. [RFC 6749]
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
