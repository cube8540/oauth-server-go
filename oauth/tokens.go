package oauth

import (
	"github.com/google/uuid"
	"time"
)

// tokenExpiresMinute OAuth2 토큰 만료 시간
// 10분으로 설정
const tokenExpiresMinute = time.Minute * 10

// refreshExpiresMinute OAuth2 리프레시 토큰 만료
// 7일로 설정
const refreshExpiresMinute = time.Hour * 24 * 7

// TokenIdGenerator 토큰 생성 인터페이스
type TokenIdGenerator interface {
	// Generate 문자열로 이루어진 새 토큰을 생성한다.
	Generate() string
}

// UuidTokenIdGenerator UUID 토큰 생성기
type UuidTokenIdGenerator struct {
}

func NewTokenGenerator() UuidTokenIdGenerator {
	return UuidTokenIdGenerator{}
}

func (u UuidTokenIdGenerator) Generate() string {
	return uuid.New().String()
}

// Token 토큰
type Token struct {
	ID        string
	ClientID  string
	Username  string
	Scopes    []string
	Refresh   *RefreshToken
	IssuedAt  time.Time
	ExpiredAt time.Time
}

func NewToken(gen TokenIdGenerator, clientId, username string) *Token {
	now := time.Now()
	return &Token{
		ID:        gen.Generate(),
		ClientID:  clientId,
		Username:  username,
		Scopes:    nil,
		Refresh:   nil,
		IssuedAt:  now,
		ExpiredAt: now.Add(tokenExpiresMinute),
	}
}

// RefreshToken OAuth2 리프레시 토큰
type RefreshToken struct {
	ID        string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

func NewRefreshToken(gen TokenIdGenerator) *RefreshToken {
	now := time.Now()
	return &RefreshToken{
		ID:        gen.Generate(),
		IssuedAt:  now,
		ExpiresAt: now.Add(refreshExpiresMinute),
	}
}
