package crypto

import (
	"errors"
	"golang.org/x/crypto/bcrypt"
)

// Hasher 문자열을 받아 해싱하여 반환하는 함수를 정의한 인터페이스
type Hasher interface {
	Hashing(v string) (string, error)
	Compare(hashed, cmp string) (bool, error)
}

// BcryptHasher Bcrypt 해싱
type BcryptHasher struct {
	cost int
}

func NewBcryptHasher() BcryptHasher {
	return BcryptHasher{
		cost: bcrypt.DefaultCost,
	}
}

func (h BcryptHasher) Hashing(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), h.cost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func (_ BcryptHasher) Compare(hashed, password string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(password))
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}
