// []
package oauth

import (
	"net/url"
	"strings"
)

// CodeChallenge OAuth2 인증 코드 사용(교환) 때 인증에 사용될 코드 [RFC 7636]
//
// [RFC 7636]: https://datatracker.ietf.org/doc/html/rfc7636
type CodeChallenge string

// CodeChallengeMethod [CodeChallenge] 인코딩 방법 [RFC 7636]
//
// [RFC 7636]: https://datatracker.ietf.org/doc/html/rfc7636
type CodeChallengeMethod string

// [CodeChallengeMethod] 열거형 정의 "plain"과 "S256"이 있다.
//
// CodeChallengeMethod가 plain인 경우 code_verifier를 검사 할 때 입력 받은 값을 그대로 사용하여 검사하며,
// S256인 경우 SHA256 인코딩을 하여 검사하게 된다. 자세한 정보는 [RFC 7636] 을 참고
//
// [RFC 7636]: https://datatracker.ietf.org/doc/html/rfc7636#section-4.2
const (
	CodeChallengePlan CodeChallengeMethod = "plain"
	CodeChallengeS256 CodeChallengeMethod = "S256"
)

// GrantType [RFC 6749] 에 정의된 OAuth2의 인가 방식
//
// [RFC 6749]: https://datatracker.ietf.org/doc/html/rfc6749
type GrantType string

const (
	GrantTypeAuthorizationCode GrantType = "authorization_code"
	GrantTypeImplicit          GrantType = "implicit"
	GrantTypePassword          GrantType = "password"
	GrantTypeClientCredentials GrantType = "client_credentials"
	GrantTypeRefreshToken      GrantType = "refresh_token"
)

// CodeVerifier 인가코드(authorization_code) 발급에 사용된 [CodeChallenge]
type CodeVerifier string

// ResponseType /authorize에서 응답 방식을 결정할 코드
type ResponseType string

const (
	ResponseTypeCode  ResponseType = "code"
	ResponseTypeToken ResponseType = "token"
)

// ClientType OAuth 클라이언트 타입 [RFC 6749]
//
// [RFC 6749]: https://datatracker.ietf.org/doc/html/rfc6749#section-2.1
type ClientType string

const (
	ClientTypePublic       ClientType = "public"
	ClientTypeConfidential ClientType = "confidential"
)

// ErrResponse OAuth2 에러에 대한 응답 형식 [RFC 6749]
//
// [RFC 6749]: https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
type ErrResponse struct {
	Code    string `json:"error"`
	Message string `json:"error_description"`
	State   string `json:"state"`
	Uri     string `json:"error_uri"`
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
	ClientID            string              `form:"client_id"`
	Username            string              `form:"username"`
	State               string              `form:"state"`
	Redirect            string              `form:"redirect_uri"`
	Scopes              string              `form:"scope"`
	ResponseType        ResponseType        `form:"response_type"`
	CodeChallenge       CodeChallenge       `form:"code_challenge"`
	CodeChallengeMethod CodeChallengeMethod `form:"code_challenge_method"`
}

// SplitScope 현제 저장되어 있는 string 타입의 문자열을 공백(" ")으로 나누어 반환한다.
func (r AuthorizationRequest) SplitScope() []string {
	var s []string
	if r.Scopes == "" {
		return s
	}
	s = strings.Split(r.Scopes, " ")
	return s
}

type TokenType string

const (
	TokenTypeBearer TokenType = "bearer"
	TokenTypeMac    TokenType = "mac"
)

type TokenRequest struct {
	GrantType    GrantType    `form:"grant_type"`
	Code         string       `form:"code"`
	Redirect     string       `form:"redirect_uri"`
	ClientID     string       `form:"client_id"`
	Secret       string       `form:"secret"`
	CodeVerifier CodeVerifier `form:"code_verifier"`
}

type TokenResponse struct {
	Token     string    `json:"access_token"`
	Type      TokenType `json:"token_type"`
	ExpiresIn uint      `json:"expires_in"`
	Refresh   string    `json:"refresh_token"`
	Scope     string    `json:"scope"`
}
