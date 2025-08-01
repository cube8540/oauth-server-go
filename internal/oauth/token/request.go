package token

import (
	"oauth-server-go/internal/oauth/authorization"
	"oauth-server-go/internal/oauth/scope"
)

// GrantType [RFC 6749] 에 정의된 OAuth2의 인가 방식
//
// [RFC 6749]: https://datatracker.ietf.org/doc/html/rfc6749
type GrantType string

const (
	// GrantTypeAuthorizationCode 인가 코드 싱안 방식
	// 일반적인 웹 어플리케이션에서 가장 많이 사용되며, 사용자의 계정을 클라이언트에 노출하지 않고 인증 할 수 있다.
	GrantTypeAuthorizationCode GrantType = "authorization_code"

	// GrantTypePassword 리소스 소유자 암호 자격 증명 승인 방식
	// 사용자의 아이디와 비밀번호를 직접 사용하여 토큰을 발행 받는다.
	// 클라이언트를 매우 신뢰할 수 있는 경우에만 사용
	GrantTypePassword GrantType = "password"

	// GrantTypeClientCredentials 클라이언트 자격 증명 승인 방식
	// 클라이언트 자신의 자격 증명을 사용하여 직접 토큰을 발행 받는다.
	// 사용자가 필요 없는 클라이언트 <-> 서버 간의 인증에 사용한다.
	GrantTypeClientCredentials GrantType = "client_credentials"

	// GrantTypeRefreshToken 리플레시 토큰을 이용하여 토큰을 갱신하는 방식
	// 엑세스 토큰이 만료된 경우 리플레시 토큰을 사용하여 새로운 엑세스 토큰을 발급 받는다.
	GrantTypeRefreshToken GrantType = "refresh_token"
)

// Request OAuth2 토큰 발행 요청을 나타내는 구조체
type Request struct {
	// Type 토큰 발행에 사용할 권한 부여 방식을 지정한다.
	Type GrantType `form:"grant_type"`

	// Code 인가 코드 승인 방식에서 사용 되는 인가 코드
	// 이전 단계에서 발급 받은 인가 코드를 포함해야 한다.
	Code string `form:"code"`

	// CodeVerifier PKCE 구현을 위한 검증 문자열
	// 인가 요청 시 생성한 code_challenge에 대응하는 원본 값으로 토큰 요청 시 이 값을 검증하여 인가 코드 탈취 공격을 방지한다.
	CodeVerifier authorization.Verifier `form:"code_verifier"`

	// Redirect 인가 코드 승인 방식에서 사용되는 리다이렉트 URI
	// 인가 요청시 사용한 redirect_uri와 정확히 일치해야 하며 클라이언트에 등록된 리다이렉트 URI 중 하나여야 한다.
	Redirect string `form:"redirect_uri"`

	// Username 자원 소유자 암호 자격 증명 방식에서 사용되는 사용자 식별자(아이디)
	Username string `form:"username"`

	// Password 자원 소유자 암호 자격 증명 방식에서 사용되는 사용자 비밀번호(패스워드)
	Password string `form:"password"`

	// RefreshToken 토큰 갱신(재발행)을 위해 사용되는 리플레시 토큰
	RefreshToken string `form:"refresh_token"`

	// Scope 요청하는 접근 권한의 범위
	// 공백으로 구분된 문자열로 클라이언트가 접근하고자 하는 자원의 범위를 나타낸다.
	// 생략시 클라이언트에 설정된 기본 범위가 사용된다.
	Scope string `form:"scope"`
}

// Response OAuth2 토큰 발행 응답
type Response struct {
	Token     string `json:"access_token,omitempty"`
	T         Type   `json:"token_type,omitempty"`
	ExpiresIn uint   `json:"expires_in,omitempty"`
	Refresh   string `json:"refresh_token,omitempty"`
	Scope     string `json:"scope,omitempty"`
}

// InspectionRequest 토큰 질의 API에서 사용할 요청 폼
// [RFC 7662] 를 참고
//
// [RFC 7662]: https://datatracker.ietf.org/doc/html/rfc7662#section-2.1
type InspectionRequest struct {
	Token         string   `form:"token"`
	TokenTypeHint TypeHint `form:"token_type_hint"`
}

// Inspection 토큰 질의 API의 응답 폼 [RFC 7662] 를 참고
//
// [RFC 7662]: https://datatracker.ietf.org/doc/html/rfc7662#section-2.2
type Inspection struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Username  string `json:"username,omitempty"`
	TokenType Type   `json:"token_type,omitempty"`

	ExpiresIn uint   `json:"exp,omitempty"`
	IssuedAt  uint   `json:"iat,omitempty"`
	NotBefore uint   `json:"nbf,omitempty"`
	Subject   string `json:"sub,omitempty"`
	Audience  string `json:"aud,omitempty"`
	Issuer    string `json:"iss,omitempty"`
	JTI       string `json:"jti,omitempty"`
}

func (i *Inspection) CopyFromAccessToken(token *AccessToken) {
	i.Scope = scope.Join(token.Scopes())
	i.ClientID = token.Client().Id()
	i.Username = token.Username()
	i.TokenType = TypeBearer // 현재는 Bearer만 지원
}

func InspectAccessToken(token *AccessToken) *Inspection {
	v := &Inspection{
		Active: token.Available(),
	}
	if v.Active {
		v.CopyFromAccessToken(token)
		v.ExpiresIn = token.ExpiresIn()
		v.IssuedAt = token.StartedAt()
	}
	return v
}

func InspectRefreshToken(token *RefreshToken) *Inspection {
	v := &Inspection{
		Active: token.Available(),
	}
	if v.Active {
		v.CopyFromAccessToken(token.Token())

		v.ExpiresIn = token.ExpiresIn()
		v.IssuedAt = token.StartedAt()
	}
	return v
}
