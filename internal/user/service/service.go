package service

import (
	"fmt"
	usererr "oauth-server-go/internal/user/errors"
	"oauth-server-go/internal/user/model"
	"oauth-server-go/pkg/hash"
)

// Repository 계정 저장소 인터페이스
type Repository interface {

	// FindByUsername 아이디를 인자로 받아 저장소에서 회원을 검색한다.
	FindByUsername(u string) (*model.Account, error)
}

// AuthenticationService 회원의 인증을 제공하는 서비스 객체
type AuthenticationService struct {
	repo Repository
}

// NewAuthenticationService 새 인증 서비스 인스턴스를 생성한다.
func NewAuthenticationService(repo Repository) *AuthenticationService {
	return &AuthenticationService{repo: repo}
}

// Auth 인증 요청을 받아 인증 프로세스를 실행하고 인증된 사용자 인스턴스를 생성한다.
func (s *AuthenticationService) Auth(request *AuthenticationRequest) (*Principal, error) {
	if request.Username == "" || request.Password == "" {
		return nil, fmt.Errorf("%w: username or password is missing", usererr.ErrRequireParamsMissing)
	}

	account, err := s.repo.FindByUsername(request.Username)
	if err != nil {
		return nil, err
	}

	if cmp, err := hash.Compare(account.Password, request.Password); err != nil {
		return nil, fmt.Errorf("%w: %v", usererr.ErrPasswordNotMatched, err)
	} else if !cmp {
		return nil, usererr.ErrPasswordNotMatched
	}

	if !account.Active {
		return nil, usererr.ErrAccountLocked
	}

	return NewPrincipal(account.Username), nil
}
