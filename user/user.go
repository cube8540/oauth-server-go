package user

import (
	"database/sql"
)

// VerificationToken 인증토큰
// 토큰과 만료일을 가지고 있으며, 계정을 활성화하는 등 계정 인증에서 사용한다.
type VerificationToken struct {
	Token     string
	ExpiresAt sql.NullTime `gorm:"column:token_expires"`
}

// Account 유저의 로그인에 필요한 정보를 담은 구조체
type Account struct {
	ID            uint
	Username      string
	Password      string
	Active        bool
	ActiveToken   *VerificationToken `gorm:"embedded;embeddedPrefix:active"`
	PasswordToken *VerificationToken `gorm:"embedded;embeddedPrefix:password"`
}

func (a Account) TableName() string {
	return "users.account"
}
