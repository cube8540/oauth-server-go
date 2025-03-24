package user

import (
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"time"
)

var (
	errTokenInvalid = errors.New("token is invalid") // 유저의 인증 토큰이 유효하지 않음
)

// Account 유저의 로그인에 필요한 정보를 담은 구조체
type Account struct {
	ID            uint
	Username      string
	password      string
	active        bool
	activeToken   *verificationToken
	passwordToken *verificationToken
}

// IsActive 계정이 활성화 되었는지 여부를 반환한다.
func (a Account) IsActive() bool {
	return a.active
}

// Hashing 저장된 패스워드를 [Hasher] 를 통해 해싱하여 저장한다.
func (a *Account) Hashing(hasher Hasher) error {
	hashed, err := hasher.Hashing(a.password)
	if err != nil {
		return err
	}
	a.password = hashed
	return nil
}

// activate 토큰을 받아 [Account] 를 활성화 시킨다.
func (a *Account) activate(token string) error {
	if err := tokenMatches(token, a.activeToken); err != nil {
		return err
	}
	a.active = true
	a.activeToken = nil
	return nil
}

// changePassword 변경할 패스워드와 토큰을 받아 [Account] 의 패스워드를 변경 한다.
func (a *Account) changePassword(password, token string) error {
	if err := tokenMatches(token, a.passwordToken); err != nil {
		return err
	}
	a.password = password
	a.passwordToken = nil
	return nil
}

// Hasher 문자열을 받아 해싱하여 반환하는 함수를 정의한 인터페이스
type Hasher interface {
	Hashing(v string) (string, error)
}

// BcryptHasher Bcrypt 해싱
type BcryptHasher struct{}

func NewBcryptHasher() BcryptHasher {
	return BcryptHasher{}
}

func (_ BcryptHasher) Hashing(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func (_ BcryptHasher) Compare(hashed, password string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(password))
	if err != nil {
		return false, err
	} else {
		return true, nil
	}
}

// expiresMinute [verificationToken]생성시 설정될 기본 만료시간으로 설정된 시간은 5분이다.
const expiresMinute = time.Minute * 5

// matches 인증토큰의 매칭 결과
type matches int8

const (
	expired    matches = iota // 토큰이 만료됨
	matched                   // 토큰이 일치함
	notMatched                // 토큰이 일치하지 않음
)

// verificationToken 인증토큰
// 토큰과 만료일을 가지고 있으며, 계정을 활성화하는 등 계정 인증에서 사용한다.
type verificationToken struct {
	token     string
	expiresAt time.Time
}

func newToken(token string) verificationToken {
	expiresAt := time.Now().Add(expiresMinute)
	return verificationToken{
		token:     token,
		expiresAt: expiresAt,
	}
}

func (t verificationToken) matches(token string) matches {
	if t.expired() {
		return expired
	} else if token == t.token {
		return matched
	} else {
		return notMatched
	}
}

func (t verificationToken) expired() bool {
	return time.Now().After(t.expiresAt)
}

func tokenMatches(token string, vt *verificationToken) error {
	if vt == nil {
		return fmt.Errorf("token is not issued %w", errTokenInvalid)
	}
	if m := vt.matches(token); m == expired {
		return fmt.Errorf("token is expired %w", errTokenInvalid)
	} else if m == notMatched {
		return fmt.Errorf("token is not matched %w", errTokenInvalid)
	} else {
		return nil
	}
}
