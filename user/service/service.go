package service

import (
	"errors"
	"gorm.io/gorm"
	"oauth-server-go/crypto"
	"oauth-server-go/user"
	"oauth-server-go/user/entity"
	"oauth-server-go/user/model"
)

type AccountRepository interface {
	FindByUsername(u string) (*entity.Account, error)
}

type AuthService struct {
	repository AccountRepository
	hasher     crypto.Hasher
}

func NewAuthService(r AccountRepository, h crypto.Hasher) *AuthService {
	return &AuthService{
		repository: r,
		hasher:     h,
	}
}

func (s AuthService) Login(r *model.Login) (*entity.Account, error) {
	if r.Username == "" || r.Password == "" {
		return nil, user.ErrRequireParamsMissing
	}

	account, err := s.repository.FindByUsername(r.Username)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, user.ErrAccountNotFound
	} else if err != nil {
		return nil, err
	}

	if cmp, err := s.hasher.Compare(account.Password, r.Password); err != nil {
		return nil, err
	} else if !cmp {
		return nil, user.ErrPasswordNotMatch
	} else if !account.Active {
		return nil, user.ErrAccountLocked
	}

	return account, nil
}
