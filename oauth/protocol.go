package oauth

import "strings"

// CodeChallenge OAuth2 인증 코드 사용(교환) 때 인증에 사용될 코드(RFC 7636)
type CodeChallenge string

// CodeChallengeMethod [CodeChallenge] 인코딩 방법
type CodeChallengeMethod string

const (
	CodeChallengePlan CodeChallengeMethod = "plain"
	CodeChallengeS256 CodeChallengeMethod = "S256"
)

// GrantType OAuth2 인증 방식
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
// 인가 방식이 Authorization Code Flow인 경우 code, Implicit Flow인 경우 token이 된다.
type ResponseType string

const (
	// ResponseTypeCode 응답 타입이 code인 경우 /authroize API는 인가코드(authroization_code)를 생성하여 응답한다.
	ResponseTypeCode ResponseType = "code"

	// ResponseTypeToken 응답 타입이 token인 경우 /authroize API는 엑세스 토큰을 생성하여 응답한다.
	ResponseTypeToken ResponseType = "token"
)

type ErrResponse struct {
	Code    string `json:"error"`
	Message string `json:"error_description"`
}

func NewErrResponse(code, message string) ErrResponse {
	return ErrResponse{
		Code:    code,
		Message: message,
	}
}

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

func (r AuthorizationRequest) SplitScope() []string {
	var s []string
	if r.Scopes == "" {
		return s
	}
	s = strings.Split(r.Scopes, " ")
	return s
}
