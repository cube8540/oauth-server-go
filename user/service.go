package user

import (
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"oauth-server-go/conf"
)

var (
	ErrRequireParamsMissing = errors.New("required parameters are missing")
	ErrAccountNotFound      = errors.New("account cannot found")
	ErrPasswordNotMatch     = errors.New("password does not match")
	ErrAccountLocked        = errors.New("account is locked")
)

// Hasher 문자열을 받아 해싱하여 반환하는 함수를 정의한 인터페이스
type Hasher interface {
	Hashing(v string) (string, error)
	Compare(hashed, cmp string) (bool, error)
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

type (
	LoginModel struct {
		Username string `json:"username"`
	}

	LoginRequest struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
)

func Login(req *LoginRequest, hasher Hasher) (*LoginModel, error) {
	if req.Username == "" || req.Password == "" {
		return nil, ErrRequireParamsMissing
	}

	var account Account
	err := conf.GetDB().Where(&Account{Username: req.Username}).First(&account).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrAccountNotFound
	} else if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	if cmp, err := hasher.Compare(account.Password, req.Password); err != nil {
		return nil, err
	} else if !cmp {
		return nil, ErrPasswordNotMatch
	} else if !account.Active {
		return nil, ErrAccountLocked
	}

	login := LoginModel{Username: account.Username}
	return &login, nil
}
