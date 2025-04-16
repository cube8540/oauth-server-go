package oauth

import (
	"net/url"
	"oauth-server-go/oauth/code"
	"oauth-server-go/oauth/pkg"
	"oauth-server-go/oauth/token"
	"strconv"
)

// Enhancer 인가 요청 결과를 리다이렉트 URL에 추가하는 함수 타입이다.
// OAuth 2.0의 다양한 인가 코드(Authorization Code), 암묵적(Implicit) 인가 타입에 따라
// 인가 코드나 액세스 토큰을 리다이렉트 URL에 적절히 추가하는 역할을 한다.
//
// 매개변수:
//   - r: 원래의 인가 요청 정보
//   - src: 인가 코드나 액세스 토큰 등 응답으로 전달할 객체
//   - redirect: 리다이렉트될 URL
type Enhancer func(r *pkg.AuthorizationRequest, src any, redirect *url.URL) error

// chaining 여러 Enhancer 함수들을 순차적으로 실행하는 새로운 Enhancer 를 반환한다.
// 이를 통해 여러 OAuth 흐름(Authorization Code, Implicit 등)을 조합하여 처리할 수 있다.
func chaining(e ...Enhancer) Enhancer {
	return func(r *pkg.AuthorizationRequest, src any, redirect *url.URL) error {
		u := redirect
		for _, h := range e {
			err := h(r, src, u)
			if err != nil {
				return err
			}
		}
		return nil
	}
}

// authorizationCodeFlow Authorization Code Grant 흐름([RFC 6749 섹션 4.1.2])을 처리한다.
// response_type이 "code"인 경우 인가 코드를 리다이렉트 URL의 쿼리 파라미터로 추가한다.
//
// 동작 방식:
//  1. response_type이 "code"인지 확인하고 아니면 아무 처리도 하지 않음
//  2. src가 AuthorizationCode 타입인지 확인
//  3. 인가 코드를 리다이렉트 URL의 쿼리 파라미터로 추가
//  4. state 값이 있으면 함께 추가
//
// [RFC 6749 섹션 4.1.2]: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2
func authorizationCodeFlow(r *pkg.AuthorizationRequest, src any, redirect *url.URL) error {
	if r.ResponseType != pkg.ResponseTypeCode {
		return nil
	}
	if c, ok := src.(*code.AuthorizationCode); ok {
		q := redirect.Query()
		q.Set("code", c.Value)
		if c.State != "" {
			q.Set("state", c.State)
		}
		redirect.RawQuery = q.Encode()
	}
	return nil
}

// implicitFlow Implicit Grant 흐름([RFC 6749 섹션 4.2])을 처리한다.
// response_type이 "token"인 경우 액세스 토큰을 리다이렉트 URL의 프래그먼트로 추가한다.
//
// 동작 방식:
//  1. response_type이 "token"인지 확인하고 아니면 아무 처리도 하지 않음
//  2. src가 Token 타입인지 확인
//  3. 액세스 토큰 및 관련 정보(token_type, expires_in, scope, state)를
//     리다이렉트 URL의 프래그먼트(#)로 추가
//
// [RFC 6749 섹션 4.2.2]: https://datatracker.ietf.org/doc/html/rfc6749#section-4.2.2
func implicitFlow(r *pkg.AuthorizationRequest, src any, redirect *url.URL) error {
	if r.ResponseType != pkg.ResponseTypeToken {
		return nil
	}
	if t, ok := src.(*token.Token); ok {
		q := redirect.Query()
		q.Set("access_token", t.GetValue())
		q.Set("token_type", string(pkg.TokenTypeBearer))
		q.Set("expires_in", strconv.FormatUint(uint64(t.GetExpiredAt()), 10))
		q.Set("scope", t.GetScopes())
		q.Set("state", r.State)
		redirect.Fragment = q.Encode()
	}
	return nil
}
