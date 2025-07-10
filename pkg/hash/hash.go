package hash

import (
	"errors"
	"golang.org/x/crypto/bcrypt"
)

// Hashing Bcrypt 해싱 알고리즘을 이용하여 입력 받은 텍스트를 해싱 한다.
func Hashing(password string) (string, error) {
	return HashingCost(password, bcrypt.DefaultCost)
}

func HashingCost(password string, cost int) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// Compare Bcrypt 해싱 알고리즘을 이용하여 해싱된 패스워드와 일반 텍스트를 입력 받아
// 두 텍스트의 일치 여부를 확인한다.
func Compare(hashed, password string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(password))
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}
