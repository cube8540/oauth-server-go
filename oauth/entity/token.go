package entity

import (
	"github.com/google/uuid"
	"oauth-server-go/sql"
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
	ID                  uint
	Value               string `gorm:"column:token"`
	ClientID            uint
	Client              Client
	Username            string
	Scopes              sql.Strings
	IssuedAt, ExpiredAt time.Time
}

func (t Token) TableName() string {
	return "users.oauth2_access_token"
}

// RefreshToken OAuth2 리프레시 토큰
type RefreshToken struct {
	ID                  uint
	Value               string `gorm:"column:token"`
	TokenID             uint   `gorm:"column:access_token_id"`
	Token               Token
	IssuedAt, ExpiredAt time.Time
}

func (t RefreshToken) TableName() string {
	return "users.oauth2_refresh_token"
}
