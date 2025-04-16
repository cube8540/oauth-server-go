package pkg

import (
	"net/url"
	"strings"
)

// ClientType OAuth 클라이언트 타입 [RFC 6749]
//
// [RFC 6749]: https://datatracker.ietf.org/doc/html/rfc6749#section-2.1
type ClientType string

const (
	ClientTypePublic       ClientType = "public"
	ClientTypeConfidential ClientType = "confidential"
)

// Challenge OAuth2 인증 코드 사용(교환) 때 인증에 사용될 코드 [RFC 7636]
//
// [RFC 7636]: https://datatracker.ietf.org/doc/html/rfc7636
type Challenge string

// ChallengeMethod [CodeChallenge] 인코딩 방법 [RFC 7636]
//
// [RFC 7636]: https://datatracker.ietf.org/doc/html/rfc7636
type ChallengeMethod string

// [ChallengeMethod] 열거형 정의 "plain"과 "S256"이 있다.
//
// ChallengeMethod가 plain인 경우 code_verifier를 검사 할 때 입력 받은 값을 그대로 사용하여 검사하며,
// S256인 경우 SHA256 인코딩을 하여 검사하게 된다. 자세한 정보는 [RFC 7636] 을 참고
//
// [RFC 7636]: https://datatracker.ietf.org/doc/html/rfc7636#section-4.2
const (
	ChallengePlan ChallengeMethod = "plain"
	ChallengeS256 ChallengeMethod = "S256"
)

// Verifier 인가코드(authorization_code) 발급에 사용된 [CodeChallenge]
type Verifier string

// GrantType [RFC 6749] 에 정의된 OAuth2의 인가 방식
//
// [RFC 6749]: https://datatracker.ietf.org/doc/html/rfc6749
type GrantType string

const (
	GrantTypeAuthorizationCode GrantType = "authorization_code"
	GrantTypePassword          GrantType = "password"
	GrantTypeClientCredentials GrantType = "client_credentials"
	GrantTypeRefreshToken      GrantType = "refresh_token"
)

// ResponseType /authorize에서 응답 방식을 결정할 코드
type ResponseType string

const (
	ResponseTypeCode  ResponseType = "code"
	ResponseTypeToken ResponseType = "token"
)

// ErrResponse OAuth2 에러에 대한 응답 형식 [RFC 6749]
//
// [RFC 6749]: https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
type ErrResponse struct {
	Code    string `json:"error"`
	Message string `json:"error_description"`
	State   string `json:"state,omitempty"`
	Uri     string `json:"error_uri,omitempty"`
}

// QueryParam 인자로 받은 URL에 현제 저장된 에러 정보들을 URL Query Param으로 붙여 반환한다.
func (e ErrResponse) QueryParam(u *url.URL) *url.URL {
	newUrl, _ := url.Parse(u.String())
	q := newUrl.Query()
	q.Set("error", e.Code)
	q.Set("error_description", e.Message)
	if e.State != "" {
		q.Set("state", e.State)
	}
	newUrl.RawQuery = q.Encode()
	return newUrl
}

func NewErrResponse(code, message string) ErrResponse {
	return ErrResponse{
		Code:    code,
		Message: message,
	}
}

// AuthorizationRequest [RFC 6749] 에 정의된 [Authorization Code Grant] 와 [Implicit Grant] 에서 사용할 요청 형태
//
// [RFC 6749]: https://datatracker.ietf.org/doc/html/rfc6749
// [Authorization Code Grant]: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1
// [Implicit Grant]: https://datatracker.ietf.org/doc/html/rfc6749#section-4.2
type AuthorizationRequest struct {
	ClientID            string          `form:"client_id"`
	Username            string          `form:"username"`
	State               string          `form:"state"`
	Redirect            string          `form:"redirect_uri"`
	Scopes              string          `form:"scope"`
	ResponseType        ResponseType    `form:"response_type"`
	CodeChallenge       Challenge       `form:"code_challenge"`
	CodeChallengeMethod ChallengeMethod `form:"code_challenge_method"`
}

// TokenType 엑세스 토큰 타입 자세한 사항은 [RFC 6749] 를 참고
//
// [RFC 6749]: https://datatracker.ietf.org/doc/html/rfc6749#section-7.1
type TokenType string

const (
	TokenTypeBearer TokenType = "bearer"
	TokenTypeMac    TokenType = "mac"
)

// 토큰 발행을 요청하고 발급 된 토큰을 응답 받을 때 사용할 폼으로 [AuthorizationCodeGrant], [ResourceOwnerPasswordCredentialsGrant]
// [ClientCredentialsGrant], [Refresh] 인가 방식에서 사용 중
//
// [AuthorizationCodeGrant]: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
// [ResourceOwnerPasswordCredentialsGrant]: https://datatracker.ietf.org/doc/html/rfc6749#section-4.3.2
// [ClientCredentialsGrant]: https://datatracker.ietf.org/doc/html/rfc6749#section-4.4.2
// [Refresh]: https://datatracker.ietf.org/doc/html/rfc6749#section-6
type (
	TokenRequest struct {
		GrantType    GrantType `form:"grant_type"`
		Code         string    `form:"code"`
		Redirect     string    `form:"redirect_uri"`
		CodeVerifier Verifier  `form:"code_verifier"`
		Username     string    `form:"username"`
		Password     string    `form:"password"`
		RefreshToken string    `form:"refresh_token"`
		Scope        string    `form:"scope"`
		ClientID     string    `form:"client_id"`
		Secret       string    `form:"secret"`
	}

	TokenResponse struct {
		Token     string    `json:"access_token,omitempty"`
		Type      TokenType `json:"token_type,omitempty"`
		ExpiresIn uint      `json:"expires_in,omitempty"`
		Refresh   string    `json:"refresh_token,omitempty"`
		Scope     string    `json:"scope,omitempty"`
	}
)

// TokenTypeHint 토큰 정보 질의시 질의할 토큰의 타입 코드
// 자세한 사항은 [RFC 7662] 를 참고
//
// [RFC 7662]: https://datatracker.ietf.org/doc/html/rfc7662#section-2.1
type TokenTypeHint string

const (
	TokenHintAccessToken  TokenTypeHint = "access_token"
	TokenHintRefreshToken TokenTypeHint = "refresh_token"
)

type (
	// IntrospectionRequest 토큰 질의 API에서 사용할 요청 폼 [RFC 7662] 를 참고
	//
	// [RFC 7662]: https://datatracker.ietf.org/doc/html/rfc7662#section-2.1
	IntrospectionRequest struct {
		Token         string        `form:"token"`
		TokenTypeHint TokenTypeHint `form:"token_type_hint"`
	}

	// Introspection 토큰 질의 API의 응답 폼 [RFC 7662] 를 참고
	//
	// [RFC 7662]: https://datatracker.ietf.org/doc/html/rfc7662#section-2.2
	Introspection struct {
		Active    bool      `json:"active"`
		Scope     string    `json:"scope,omitempty"`
		ClientID  string    `json:"client_id,omitempty"`
		Username  string    `json:"username,omitempty"`
		TokenType TokenType `json:"token_type,omitempty"`

		ExpiresIn uint   `json:"exp,omitempty"`
		IssuedAt  uint   `json:"iat,omitempty"`
		NotBefore uint   `json:"nbf,omitempty"`
		Subject   string `json:"sub,omitempty"`
		Audience  string `json:"aud,omitempty"`
		Issuer    string `json:"iss,omitempty"`
		JTI       string `json:"jti,omitempty"`
	}
)

// SplitScope 현제 저장되어 있는 string 타입의 문자열을 공백(" ")으로 나누어 반환한다. [RFC 6749]
//
// [RFC 6749]: https://datatracker.ietf.org/doc/html/rfc6749#section-3.3
func SplitScope(src string) []string {
	var s []string
	if src == "" {
		return s
	}
	s = strings.Split(src, " ")
	return s
}
