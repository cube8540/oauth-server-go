package authorization

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"oauth-server-go/internal/oauth/client"
	oautherr "oauth-server-go/internal/oauth/errors"
	"oauth-server-go/internal/oauth/scope"
	"oauth-server-go/pkg/array"
	"oauth-server-go/pkg/period"
	"time"
)

// codeExpiresMinute 인가 코드의 만료 시간 (5분)
const codeExpiresMinute = time.Minute * 5

// GenerateCode 인가 코드 텍스트 생성 함수
//
// 이 함수로 생성된 문자열이 실제 인가 코드 값으로 사용된다.
// 호출시 요청자나 클라이언트의 정보를 유추 할 수 없도록 랜덤한 문자열을 생성해야한다.
type GenerateCode func() string

// Code OAuth2 인가 코드
//
// OAuth2의 Authorization Code Grant Type에 사용되는 인가 코드를 표현한 구조체
// [RFC 6479 섹션 4.1] 에 정의된 사양을 구현한다.
//
// [RFC 6479 섹션 4.1]: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1
type Code struct {
	// value 실제 코드값.
	// 이 값은 요청자나 클라이언트의 정보를 알 수 없도록 랜덤한 방식으로 생성된 문자열로 생성 되어야 한다.
	value string

	// client 인가를 요청한 클라이언트
	client *client.Client

	// username 자원 소유자의 식별자
	username string

	// state CSRF 공격을 방지하기 위한 검증 문자열
	// 클라이언트는 전송한 원본 state 값을 저장하고 인가 코드 발급 시 이 값을 함께 반환하여 요청의 신뢰성을 보장한다.
	state string

	// redirect 인가 완료시 인가 코드를 넘길 콜백 URI
	// 클라이언트 등록 시 지정된 redirect_uri와 일치 해야 한다.
	redirect string

	// scopes 인가 완료시 토큰에 부여할 스코프
	scopes []string

	// codeChallenge codeChallengeMethod [PKCE(RFC 7636)] 구현을 위한 필드
	//
	// [PKCE(RFC 7636)]: https://datatracker.ietf.org/doc/html/rfc7636
	codeChallenge       Challenge
	codeChallengeMethod ChallengeMethod

	period.Range
}

func (c *Code) Value() string {
	return c.value
}

func (c *Code) Client() *client.Client {
	return c.client
}

func (c *Code) Username() string {
	return c.username
}

func (c *Code) State() string {
	return c.state
}

func (c *Code) Redirect() string {
	return c.redirect
}

func (c *Code) Scopes() []string {
	return c.scopes
}

func (c *Code) CodeChallenge() Challenge {
	return c.codeChallenge
}

func (c *Code) CodeChallengeMethod() ChallengeMethod {
	return c.codeChallengeMethod
}

func NewCode(c *client.Client, g GenerateCode) *Code {
	code := &Code{
		value:  g(),
		client: c,
		Range:  period.New(codeExpiresMinute),
	}
	return code
}

func NewCodeWithRange(c *client.Client, g GenerateCode, r period.Range) *Code {
	code := &Code{
		value:  g(),
		client: c,
		Range:  r,
	}
	return code
}

// CopyFrom 인가 요청을 인가 코드에 복사한다.
func (c *Code) CopyFrom(request *Request) error {
	if request.Username == "" {
		return fmt.Errorf("%w: username", oautherr.ErrMissingParameter)
	}
	c.username = request.Username

	scopes := scope.Split(request.Scopes)
	if !array.ContainsAll(c.client.Scopes(), scopes) {
		return oautherr.ErrInvalidScope
	}
	c.scopes = scopes
	c.state = request.State
	c.redirect = request.Redirect
	c.codeChallenge = request.CodeChallenge
	c.codeChallengeMethod = request.CodeChallengeMethod
	if c.codeChallenge != "" && c.codeChallengeMethod == "" {
		c.codeChallengeMethod = ChallengePlan
	} else if c.codeChallenge == "" && c.codeChallengeMethod != "" {
		return fmt.Errorf("%w: code challenge", oautherr.ErrMissingParameter)
	}
	return nil
}

// Verify 인자로 받은 verifier가 code_challenge와 일치하는지 확인하여 PKCE 검증을 진행한다.
// PKCE 검증에 대한 자세한 사항은 [Challenge], [ChallengeMethod] 확인
func (c *Code) Verify(verifier Verifier) (bool, error) {
	if c.codeChallenge == "" {
		return true, nil
	}
	if verifier == "" {
		return false, fmt.Errorf("%w: verifier", oautherr.ErrMissingParameter)
	}

	switch c.codeChallengeMethod {
	case ChallengeS256:
		hash := sha256.New()
		_, err := hash.Write([]byte(verifier))
		if err != nil {
			return false, fmt.Errorf("%w: codes occurred during hasing %s, %v", oautherr.ErrUnknown, verifier, err)
		}
		encoded := base64.URLEncoding.EncodeToString(hash.Sum(nil))
		return string(c.codeChallenge) == encoded, nil
	case ChallengePlan:
		return string(c.codeChallenge) == string(verifier), nil
	default:
		return false, fmt.Errorf("%w: undefined code challenge method", oautherr.ErrInvalidRequest)
	}
}
