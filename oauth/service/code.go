package service

import (
	"oauth-server-go/oauth"
	"oauth-server-go/oauth/entity"
)

var codeGenerator entity.AuthCodeGenerator

func init() {
	codeGenerator = entity.UUIDAuthCodeGenerator
}

type AuthCodeService struct {
	New func(c *entity.Client, r *oauth.AuthorizationRequest) (*entity.AuthorizationCode, error)
}

func NewAuthCodeService() *AuthCodeService {
	return &AuthCodeService{
		New: newAuthCode,
	}
}

func newAuthCode(c *entity.Client, r *oauth.AuthorizationRequest) (*entity.AuthorizationCode, error) {
	code, err := entity.NewAuthCode(c, codeGenerator, r)
	if err != nil {
		return nil, err
	}
	if err = authCodeRepository.Save(code); err != nil {
		return nil, err
	}
	return code, nil
}
