package token

import (
	"oauth-server-go/internal/oauth/authorization"
	"oauth-server-go/internal/oauth/client"
	"oauth-server-go/pkg/period"
	"time"
)

// tokenExpiresMinute OAuth2 토큰 만료 시간
// 10분으로 설정
const tokenExpiresMinute = time.Minute * 10

// GenerateToken 토큰 텍스트 생성 함수
//
// 이 함수로 생성된 문자열이 실제 토큰값으로 사용된다.
// 호출시 토큰 소유자의 정보를 유추 할 수 없도록 랜덤한 문자열을 반환해야 한다.
type GenerateToken func() string

// Type 엑세스 토큰 타입 자세한 사항은 [RFC 6749] 를 참고
//
// [RFC 6749]: https://datatracker.ietf.org/doc/html/rfc6749#section-7.1
type Type string

const (
	TypeBearer Type = "bearer"
	TypeMAC    Type = "mac"
)

// TypeHint 토큰 정보 질의시 질의할 토큰의 타입
// 자세한 사항은 [RFC 7662] 를 참고
//
// [RFC 7662]: https://datatracker.ietf.org/doc/html/rfc7662#section-2.1
type TypeHint string

const (
	TypeHintAccessToken  TypeHint = "access_token"
	TypeHintRefreshToken TypeHint = "refresh_token"
)

// AccessToken OAuth2 액세스 토큰
type AccessToken struct {
	// value 토큰의 실제 값. 토큰 소유자의 정보등을 유추할 수 없도록 아무런 의미가 없는 랜덤한 값이어야 한다.
	// 이 값은 API 요청 시 인증 수단으로 사용된다.
	value string

	// client 토큰을 발급한 클라이언트
	client *client.Client

	// username 토큰을 발급한 유저
	username string

	// scopes 할당된 스코프
	scopes []string

	period.Range
}

func New(client *client.Client, g GenerateToken) *AccessToken {
	return &AccessToken{
		value:  g(),
		client: client,
		Range:  period.New(tokenExpiresMinute),
	}
}

func NewWithRange(client *client.Client, g GenerateToken, r period.Range) *AccessToken {
	return &AccessToken{
		value:  g(),
		client: client,
		Range:  r,
	}
}

func (t *AccessToken) Value() string {
	return t.value
}

func (t *AccessToken) Client() *client.Client {
	return t.client
}

func (t *AccessToken) Username() string {
	return t.username
}

func (t *AccessToken) Scopes() []string {
	return t.scopes
}

func (t *AccessToken) ApplyAuthorizationCode(code *authorization.Code) {
	t.username = code.Username()
	t.scopes = code.Scopes()
}

func (t *AccessToken) ApplyResourceOwnerInfo(username string, scopes []string) {
	t.username = username
	t.scopes = scopes
}

// refreshExpiresMinute OAuth2 리프레시 토큰 만료
// 7일로 설정
const refreshExpiresMinute = time.Hour * 24 * 7

// RefreshToken OAuth2 액세스 토큰 만료시 이를 갱신하기 위한 용도로 사용하는 토큰
type RefreshToken struct {
	// value 실제 리플레시 토큰 값. 토큰 소유자의 정보를 유추 할 수 없도록 랜덤한 문자열로 만들어져야 한다.
	value string

	// token 리플래시 토큰 사용시 재생성할 액세스 토큰
	token AccessToken

	period.Range
}

func NewRefreshToken(token *AccessToken, g GenerateToken) *RefreshToken {
	return &RefreshToken{
		value: g(),
		token: *token,
		Range: period.New(refreshExpiresMinute),
	}
}

func NewRefreshTokenWithRange(token *AccessToken, g GenerateToken, r period.Range) *RefreshToken {
	return &RefreshToken{
		value: g(),
		token: *token,
		Range: r,
	}
}

func (t *RefreshToken) Value() string {
	return t.value
}

func (t *RefreshToken) Token() *AccessToken {
	return &t.token
}
