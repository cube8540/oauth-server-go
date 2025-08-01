package handler

import (
	"net/url"
	"oauth-server-go/internal/oauth/authorization"
	"oauth-server-go/internal/oauth/scope"
	"oauth-server-go/internal/oauth/token"
	"strconv"
)

// Enhancer OAuth2 인가 요청 결과를 리다이렉트 URI에 추가하는 함수
//
// OAuth2 2.0의 다양한 인가 방식에 따라 인가 코드나 엑세스 토큰을 리다이렉트 URI에 적절히 추가하는 역할을 한다.
//
// Parameter:
//   - request: 인가 요청 정보 원본
//   - src: 인가 코드, 엑세스 토큰 등 응답으로 전달될 객체
//   - redirect: 라다이렉트 될 URI
type Enhancer func(request *authorization.Request, src any, redirect *url.URL) error

// ChainEnhancer 여러 Enhancer 함수들을 순차적으로 실행하는 새로운 Enhancer 함수를 생성한다.
// 이를 통해 여러 OAuth2 흐름을 조합하여 처리할 수 있다.
func ChainEnhancer(e ...Enhancer) Enhancer {
	return func(request *authorization.Request, src any, redirect *url.URL) error {
		u := redirect
		for _, h := range e {
			err := h(request, src, u)
			if err != nil {
				return err
			}
		}
		return nil
	}
}

// EnhanceAuthorizationCode Authorization Code Grant 흐름([RFC 6749 섹션 4.1.2])을 처리한다.
// response_type이 "code"인 경우 인가 코드를 리다이렉트 URL의 쿼리 파라미터로 추가한다.
//
// 동작 방식:
//  1. response_type이 "code"인지 확인하고 아니면 아무 처리도 하지 않음
//  2. src가 AuthorizationCode 타입인지 확인
//  3. 인가 코드를 리다이렉트 URL의 쿼리 파라미터로 추가
//  4. state 값이 있으면 함께 추가
//
// [RFC 6749 섹션 4.1.2]: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2
func EnhanceAuthorizationCode(request *authorization.Request, src any, redirect *url.URL) error {
	if request.ResponseType != authorization.ResponseTypeCode {
		return nil
	}

	if c, ok := src.(*authorization.Code); ok {
		q := redirect.Query()
		q.Set("code", c.Value())
		if c.State() != "" {
			q.Set("state", c.State())
		}
		redirect.RawQuery = q.Encode()
	}

	return nil
}

// EnhanceImplicit Implicit Grant 흐름([RFC 6749 섹션 4.2])을 처리한다.
// response_type이 "token"인 경우 액세스 토큰을 리다이렉트 URL의 프래그먼트로 추가한다.
//
// 동작 방식:
//  1. response_type이 "token"인지 확인하고 아니면 아무 처리도 하지 않음
//  2. src가 Token 타입인지 확인
//  3. 액세스 토큰 및 관련 정보(token_type, expires_in, scope, state)를
//     리다이렉트 URL의 프래그먼트(#)로 추가
//
// [RFC 6749 섹션 4.2.2]: https://datatracker.ietf.org/doc/html/rfc6749#section-4.2.2
func EnhanceImplicit(request *authorization.Request, src any, redirect *url.URL) error {
	if request.ResponseType != authorization.ResponseTypeToken {
		return nil
	}

	if t, ok := src.(token.AccessToken); ok {
		q := redirect.Query()
		q.Set("access_token", t.Value())
		q.Set("token_type", string(token.TypeBearer))
		q.Set("expires_in", strconv.FormatUint(uint64(t.ExpiresIn()), 10))
		q.Set("scope", scope.Join(t.Scopes()))
		q.Set("state", request.State)
		redirect.Fragment = q.Encode()
	}

	return nil
}
